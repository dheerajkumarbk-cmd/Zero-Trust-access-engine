package dev.dwarpal.console;

import dev.dwarpal.crypto.Digests;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The server-side session store (standards section 3): 256-bit random identifiers, a new identifier at login and at
 * step-up (no fixation), an idle and an absolute timeout, a limit on concurrent sessions per person, and a binding of
 * each session to the client address and a hash of its User-Agent. (The JDK's HTTPS server does not expose TLS channel
 * binding, so the address and agent stand in for it; a stolen cookie replayed from another address or browser is
 * refused and the session is ended.)
 */
final class ConsoleSessions {

    /** A session. Only {@code lastSeen} and {@code stepUpAt} change, and only through this class. */
    static final class Session {
        final String id;
        final long order;
        final ConsoleAuth.Person person;
        final String csrf;
        final Instant createdAt;
        final String source;
        final String agent;
        volatile Instant lastSeen;
        volatile Instant stepUpAt;
        /** The shared window: one passkey entry opens cases, entities and hunt together until this real time. */
        volatile Instant unlockedUntil;
        /** The audit explorer's own, shorter unlock. */
        volatile Instant auditUntil;
        /** One passkey entry, good for exactly one risky action; null when there is none. */
        volatile Instant onceUntil;

        Session(String id, long order, ConsoleAuth.Person person, String csrf, Instant createdAt, String source,
                String agent, Instant stepUpAt) {
            this.id = id;
            this.order = order;
            this.person = person;
            this.csrf = csrf;
            this.createdAt = createdAt;
            this.source = source;
            this.agent = agent;
            this.lastSeen = createdAt;
            this.stepUpAt = stepUpAt;
        }

        String tag() {
            return ConsoleAudit.sessionTag(id);
        }
    }

    enum Lookup { OK, NONE, EXPIRED, BOUND_ELSEWHERE }

    record Found(Lookup lookup, Session session) {
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Clock clock;
    private final ConsoleSettings settings;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final java.util.concurrent.atomic.AtomicLong counter = new java.util.concurrent.atomic.AtomicLong();

    ConsoleSessions(Clock clock, ConsoleSettings settings) {
        this.clock = clock;
        this.settings = settings;
    }

    /**
     * A new session for a person who just proved both factors. If the person already has the limit, the oldest of
     * theirs is ended; if the store is full of live sessions of others, no session is made (empty).
     */
    synchronized Optional<Session> start(ConsoleAuth.Person person, String source, String agent) {
        sweep();
        List<Session> mine = of(person.id());
        while (mine.size() >= settings.maxSessionsPerPerson()) {
            end(mine.removeFirst().id);
        }
        if (sessions.size() >= settings.maxSessions()) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        Session s = new Session(token(), counter.incrementAndGet(), person, token(), now, source, agentHash(agent), now);
        sessions.put(s.id, s);
        return Optional.of(s);
    }

    /** The session for a cookie value, with idle and absolute timeouts and the binding checked. */
    Found find(String id, String source, String agent) {
        if (id == null) {
            return new Found(Lookup.NONE, null);
        }
        Session s = sessions.get(id);
        if (s == null) {
            return new Found(Lookup.NONE, null);
        }
        Instant now = clock.instant();
        if (!now.isBefore(s.lastSeen.plus(settings.idle())) || !now.isBefore(s.createdAt.plus(settings.absolute()))) {
            end(id);
            return new Found(Lookup.EXPIRED, s);
        }
        if (!s.source.equals(source) || !MessageDigest.isEqual(s.agent.getBytes(StandardCharsets.UTF_8),
                agentHash(agent).getBytes(StandardCharsets.UTF_8))) {
            end(id);
            return new Found(Lookup.BOUND_ELSEWHERE, s);
        }
        return new Found(Lookup.OK, s);
    }

    /** Counts as activity (a background refresh does not). */
    void touch(Session s) {
        s.lastSeen = clock.instant();
    }

    /** A fresh second factor: new identifier and new anti-forgery token, same creation time (absolute lifetime kept). */
    synchronized Optional<Session> stepUp(Session old) {
        if (sessions.get(old.id) != old) {
            return Optional.empty();
        }
        sessions.remove(old.id);
        Instant now = clock.instant();
        Session s = new Session(token(), old.order, old.person, token(), old.createdAt, old.source, old.agent, now);
        s.lastSeen = now;
        s.unlockedUntil = old.unlockedUntil;
        s.auditUntil = old.auditUntil;
        sessions.put(s.id, s);
        return Optional.of(s);
    }

    /**
     * Opens the shared window: confidential views stay open until {@code window} (real time) after the passkey was given.
     * Using them does not extend it, so a countdown shown to the person is true; only a new passkey entry renews it.
     */
    void unlock(Session s, java.time.Duration window) {
        s.unlockedUntil = clock.instant().plus(window);
    }

    /** The passkey given for the audit explorer: open for {@code audit}, and the shared window is renewed too. */
    void unlockAudit(Session s, java.time.Duration audit, java.time.Duration window) {
        Instant now = clock.instant();
        s.auditUntil = now.plus(audit);
        s.unlockedUntil = now.plus(window);
    }

    /** The passkey given for one risky action: good for that one action, for at most {@code ttl}; no window is touched. */
    void grantOnce(Session s, java.time.Duration ttl) {
        s.onceUntil = clock.instant().plus(ttl);
    }

    /** Uses up the single-use passkey: true once per entry. The next risky action needs the passkey again. */
    boolean consumeOnce(Session s) {
        synchronized (s) {
            Instant t = s.onceUntil;
            s.onceUntil = null;
            return t != null && clock.instant().isBefore(t);
        }
    }

    /** Closes everything the passkey opened: the window, the audit unlock and any unused single-use entry. */
    void lock(Session s) {
        s.unlockedUntil = null;
        s.auditUntil = null;
        s.onceUntil = null;
    }

    boolean unlocked(Session s) {
        return before(s.unlockedUntil);
    }

    boolean auditOpen(Session s) {
        return before(s.auditUntil);
    }

    /** Real seconds left in the shared window, 0 when it is closed. */
    long unlockedSeconds(Session s) {
        return secondsLeft(s.unlockedUntil);
    }

    /** Real seconds left in the audit unlock, 0 when it is closed. */
    long auditSeconds(Session s) {
        return secondsLeft(s.auditUntil);
    }

    private boolean before(Instant t) {
        return t != null && clock.instant().isBefore(t);
    }

    private long secondsLeft(Instant t) {
        return t == null ? 0 : Math.max(0, java.time.Duration.between(clock.instant(), t).toSeconds());
    }

    boolean stepUpFresh(Session s) {
        Instant t = s.stepUpAt;
        return t != null && clock.instant().isBefore(t.plus(settings.stepUpFreshness()));
    }

    Instant stepUpUntil(Session s) {
        return s.stepUpAt.plus(settings.stepUpFreshness());
    }

    Instant idleUntil(Session s) {
        return s.lastSeen.plus(settings.idle());
    }

    Instant absoluteUntil(Session s) {
        return s.createdAt.plus(settings.absolute());
    }

    boolean valid(String id) {
        Session s = sessions.get(id);
        if (s == null) {
            return false;
        }
        Instant now = clock.instant();
        return now.isBefore(s.lastSeen.plus(settings.idle())) && now.isBefore(s.createdAt.plus(settings.absolute()));
    }

    void end(String id) {
        sessions.remove(id);
    }

    /** The person's live sessions, oldest first. */
    List<Session> of(String personId) {
        List<Session> out = new ArrayList<>();
        for (Session s : sessions.values()) {
            if (s.person.id().equals(personId)) {
                out.add(s);
            }
        }
        out.sort(Comparator.comparingLong((Session s) -> s.order));
        return out;
    }

    int size() {
        return sessions.size();
    }

    private void sweep() {
        Instant now = clock.instant();
        sessions.values().removeIf(s -> !now.isBefore(s.lastSeen.plus(settings.idle()))
                || !now.isBefore(s.createdAt.plus(settings.absolute())));
    }

    private static String token() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static String agentHash(String agent) {
        return Digests.sha256Hex(agent == null ? "" : agent);
    }
}

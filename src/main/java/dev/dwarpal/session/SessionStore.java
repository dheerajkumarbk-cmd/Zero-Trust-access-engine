package dev.dwarpal.session;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;

/**
 * In-memory session store, keyed by token hash, with a per-subject index in opening order.
 * Every method is synchronized: session operations are short, and correctness under concurrency
 * (two uses racing a revocation) matters more here than raw throughput.
 */
final class SessionStore {

    private final Map<String, Session> byToken = new HashMap<>();
    private final Map<String, Set<String>> bySubject = new HashMap<>();

    synchronized Optional<Session> get(String tokenHash) {
        return Optional.ofNullable(byToken.get(tokenHash));
    }

    synchronized void add(Session s) {
        if (byToken.putIfAbsent(s.tokenHash(), s) != null) {
            throw new IllegalStateException("token hash collision");
        }
        bySubject.computeIfAbsent(s.subjectId(), k -> new LinkedHashSet<>()).add(s.tokenHash());
    }

    /**
     * Applies {@code change} to the session as it is stored now. Empty if the session is gone (revoked
     * meanwhile), so an update can never bring a revoked session back.
     */
    synchronized Optional<Session> update(String tokenHash, UnaryOperator<Session> change) {
        Session current = byToken.get(tokenHash);
        if (current == null) {
            return Optional.empty();
        }
        Session updated = change.apply(current);
        byToken.put(tokenHash, updated);
        return Optional.of(updated);
    }

    synchronized Optional<Session> remove(String tokenHash) {
        Session s = byToken.remove(tokenHash);
        if (s == null) {
            return Optional.empty();
        }
        Set<String> tokens = bySubject.get(s.subjectId());
        if (tokens != null) {
            tokens.remove(tokenHash);
            if (tokens.isEmpty()) {
                bySubject.remove(s.subjectId());
            }
        }
        return Optional.of(s);
    }

    synchronized List<Session> removeIf(Predicate<Session> which) {
        List<Session> removed = new ArrayList<>();
        for (Session s : List.copyOf(byToken.values())) {
            if (which.test(s)) {
                remove(s.tokenHash()).ifPresent(removed::add);
            }
        }
        return removed;
    }

    /** The subject's live sessions, oldest first. */
    synchronized List<Session> ofSubject(String subjectId) {
        List<Session> out = new ArrayList<>();
        for (String token : bySubject.getOrDefault(subjectId, Set.of())) {
            out.add(byToken.get(token));
        }
        return out;
    }

    synchronized List<Session> purgeExpired(Instant now, Duration idleTimeout) {
        return removeIf(s -> ended(s, now, idleTimeout).isPresent());
    }

    synchronized int size() {
        return byToken.size();
    }

    /** Why the session is over by time alone, if it is. */
    static Optional<String> ended(Session s, Instant now, Duration idleTimeout) {
        if (!now.isBefore(s.expiresAt())) {
            return Optional.of("session reached its absolute lifetime");
        }
        if (!now.isBefore(s.lastUsedAt().plus(idleTimeout))) {
            return Optional.of("session idle for " + idleTimeout.toMinutes() + " min or more");
        }
        return Optional.empty();
    }
}

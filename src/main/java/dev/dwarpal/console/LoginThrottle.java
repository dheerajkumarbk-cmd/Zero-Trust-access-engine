package dev.dwarpal.console;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Login throttling with exponential delay and a lockout the person can see (standards section 3). Failures are
 * counted per (account, client address) so that a stranger typing wrong passwords for "ana" locks out that stranger
 * and not ana, and per client address alone so that one address cannot try many accounts. Unknown accounts are
 * throttled exactly like known ones, so the delay tells nothing about who exists.
 *
 * <p>The first {@value #FREE_FAILURES} failures cost nothing; each further one doubles the wait (5 s, 10 s, 20 s, ...,
 * at most 15 minutes). A success clears the pair. When the table is full of live entries a new key is refused: under
 * a flood of fresh keys, saying "wait" is the safe answer.
 */
final class LoginThrottle {

    static final int FREE_FAILURES = 3;
    static final Duration MAX_WAIT = Duration.ofMinutes(15);
    static final int SOURCE_FAILURES = 30;
    static final Duration SOURCE_WINDOW = Duration.ofMinutes(10);
    private static final int MAX_KEYS = 10_000;

    private static final class Entry {
        int failures;
        Instant lockedUntil = Instant.MIN;
        Instant last;
    }

    private final Clock clock;
    private final Map<String, Entry> pairs = new LinkedHashMap<>();
    private final Map<String, Entry> sources = new LinkedHashMap<>();
    private long lockouts;

    LoginThrottle(Clock clock) {
        this.clock = clock;
    }

    /** Seconds the caller must still wait (0 when it may try now). */
    synchronized long retryAfterSeconds(String account, String source) {
        Instant now = clock.instant();
        prune(pairs, now, Duration.ofMinutes(30));
        prune(sources, now, SOURCE_WINDOW);
        long wait = 0;
        Entry p = pairs.get(key(account, source));
        if (p != null) {
            wait = Math.max(wait, remaining(p, now));
        } else if (pairs.size() >= MAX_KEYS) {
            wait = 60;
        }
        Entry s = sources.get(source);
        if (s != null) {
            wait = Math.max(wait, remaining(s, now));
        }
        return wait;
    }

    synchronized void failure(String account, String source) {
        Instant now = clock.instant();
        prune(pairs, now, Duration.ofMinutes(30));
        prune(sources, now, SOURCE_WINDOW);
        Entry p = pairs.get(key(account, source));
        if (p == null && pairs.size() < MAX_KEYS) {
            p = new Entry();
            pairs.put(key(account, source), p);
        }
        if (p != null) {
            p.failures++;
            p.last = now;
            if (p.failures > FREE_FAILURES) {
                long seconds = Math.min(MAX_WAIT.toSeconds(), 5L << Math.min(20, p.failures - FREE_FAILURES - 1));
                p.lockedUntil = now.plusSeconds(seconds);
                lockouts++;
            }
        }
        Entry s = sources.get(source);
        if (s == null && sources.size() < MAX_KEYS) {
            s = new Entry();
            s.last = now;
            sources.put(source, s);
        }
        if (s != null) {
            s.failures++;
            if (s.failures >= SOURCE_FAILURES && s.lockedUntil.isBefore(now)) {
                s.lockedUntil = s.last.plus(SOURCE_WINDOW);
                lockouts++;
            }
        }
    }

    synchronized void success(String account, String source) {
        pairs.remove(key(account, source));
    }

    synchronized long lockouts() {
        return lockouts;
    }

    private static long remaining(Entry e, Instant now) {
        return e.lockedUntil.isAfter(now) ? Math.max(1, Duration.between(now, e.lockedUntil).toSeconds() + 1) : 0;
    }

    /** Entries forget themselves: a pair 30 minutes after its last failure, an address 10 minutes after its first. */
    private static void prune(Map<String, Entry> map, Instant now, Duration ttl) {
        Iterator<Map.Entry<String, Entry>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            Entry e = it.next().getValue();
            boolean old = e.last != null && now.isAfter(e.last.plus(ttl));
            if (old && !e.lockedUntil.isAfter(now)) {
                it.remove();
            }
        }
    }

    private static String key(String account, String source) {
        String a = account.length() > 128 ? account.substring(0, 128) : account;
        return source + "|" + a;
    }
}

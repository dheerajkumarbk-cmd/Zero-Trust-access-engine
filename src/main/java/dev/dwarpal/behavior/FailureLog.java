package dev.dwarpal.behavior;

import dev.dwarpal.domain.Validate;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Recent authentication failures, per subject (brute force: many guesses at one account) and per
 * source IP (password spraying: one guess at many accounts, MITRE ATT&amp;CK T1110.003). Fed by the
 * authentication layer whenever a password or MFA check fails.
 *
 * <p>Bounded, because an attacker controls both keys. But a plain LRU cache can be <em>flushed</em>:
 * an attacker floods junk failures until the evidence of the real attack is evicted (found by
 * red-teaming). So evidence younger than {@link #RETENTION} is never evicted; when the store is full
 * of recent evidence, new keys are dropped instead and counted. Separately, a keyless per-minute
 * counter records <em>every</em> failure, so a flood can never hide from the org-wide total.
 *
 * <p>Every failure keeps its own timestamp. An earlier version kept only the latest time per
 * (IP, account), so a query about an earlier moment lost the evidence whenever events arrived out of
 * order or a past moment was re-evaluated (found by the accuracy simulation).
 */
public final class FailureLog implements FailureView {

    public static final int MAX_KEYS = 100_000;
    public static final int MAX_PER_KEY = 1_000;
    public static final Duration RETENTION = Duration.ofHours(1);
    private static final int MINUTE_BUCKETS = 120;

    private final int maxKeys;
    private final Map<String, ArrayDeque<Instant>> bySubject = new LinkedHashMap<>(16, 0.75f, true);
    private final Map<String, ArrayDeque<Failure>> byIp = new LinkedHashMap<>(16, 0.75f, true);
    private final long[] bucketMinute = new long[MINUTE_BUCKETS];
    private final long[] bucketCount = new long[MINUTE_BUCKETS];
    private long droppedKeys;

    private record Failure(String subjectId, Instant at) {
    }

    public FailureLog() {
        this(MAX_KEYS);
    }

    /** Smaller capacity for tests of the eviction rules. */
    FailureLog(int maxKeys) {
        this.maxKeys = maxKeys;
    }

    public synchronized void recordFailure(String subjectId, String ip, Instant at) {
        Validate.id(subjectId, "subjectId");
        Validate.id(ip, "ip");
        Objects.requireNonNull(at, "at");
        countMinute(at);

        ArrayDeque<Instant> q = bySubject.get(subjectId);
        if (q == null && admit(bySubject, at, e -> e.getValue().stream().max(Instant::compareTo).orElse(null))) {
            q = new ArrayDeque<>();
            bySubject.put(subjectId, q);
        }
        if (q != null) {
            q.addLast(at);
            if (q.size() > MAX_PER_KEY) {
                q.removeFirst();
            }
        }

        ArrayDeque<Failure> fromIp = byIp.get(ip);
        if (fromIp == null && admit(byIp, at, e -> e.getValue().stream().map(Failure::at).max(Instant::compareTo).orElse(null))) {
            fromIp = new ArrayDeque<>();
            byIp.put(ip, fromIp);
        }
        if (fromIp != null) {
            fromIp.addLast(new Failure(subjectId, at));
            if (fromIp.size() > MAX_PER_KEY) {
                fromIp.removeFirst();
            }
        }
    }

    /** Room for a new key? Evicts the least-recently-used key only if its evidence is stale. */
    private <V> boolean admit(Map<String, V> map, Instant now, java.util.function.Function<Map.Entry<String, V>, Instant> newest) {
        if (map.size() < maxKeys) {
            return true;
        }
        Map.Entry<String, V> eldest = map.entrySet().iterator().next();
        Instant last = newest.apply(eldest);
        if (last == null || last.isBefore(now.minus(RETENTION))) {
            map.remove(eldest.getKey());
            return true;
        }
        droppedKeys++;
        return false;
    }

    private void countMinute(Instant at) {
        long minute = Math.floorDiv(at.getEpochSecond(), 60);
        int slot = Math.floorMod(minute, MINUTE_BUCKETS);
        if (bucketMinute[slot] != minute) {
            bucketMinute[slot] = minute;
            bucketCount[slot] = 0;
        }
        bucketCount[slot]++;
    }

    /** Failures for the subject within [from, to]. */
    @Override
    public synchronized long subjectFailures(String subjectId, Instant from, Instant to) {
        ArrayDeque<Instant> q = bySubject.get(subjectId);
        return q == null ? 0 : q.stream().filter(t -> !t.isBefore(from) && !t.isAfter(to)).count();
    }

    /** Distinct subjects that failed from this IP within [from, to]. */
    @Override
    public synchronized long distinctSubjectsFromIp(String ip, Instant from, Instant to) {
        ArrayDeque<Failure> q = byIp.get(ip);
        return q == null ? 0 : q.stream().filter(f -> !f.at().isBefore(from) && !f.at().isAfter(to))
                .map(Failure::subjectId).distinct().count();
    }

    /** Org-wide failures in the whole minutes covering [from, to] (at most the last two hours). */
    @Override
    public synchronized long totalFailures(Instant from, Instant to) {
        long first = Math.floorDiv(from.getEpochSecond(), 60);
        long last = Math.floorDiv(to.getEpochSecond(), 60);
        long sum = 0;
        for (int i = 0; i < MINUTE_BUCKETS; i++) {
            if (bucketMinute[i] >= first && bucketMinute[i] <= last) {
                sum += bucketCount[i];
            }
        }
        return sum;
    }

    /** New keys refused because the store was full of recent evidence: itself a sign of a flood. */
    public synchronized long droppedKeys() {
        return droppedKeys;
    }
}

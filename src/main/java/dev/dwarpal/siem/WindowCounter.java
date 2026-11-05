package dev.dwarpal.siem;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Counts occurrences per key in a sliding window of audit time and says when a key reaches its
 * threshold. Bounded: at most {@code threshold} entries per key and {@code maxKeys} keys. When full it
 * first drops keys whose newest entry has left the window; if every key is still live, the new key is
 * <em>refused and counted</em> ({@link #overflow()}) rather than an old one forgotten, so flooding the
 * table cannot silently reset a counter that is about to fire.
 *
 * <p>In distinct mode the threshold counts different tags (for example different subjects denied from
 * one address); a repeated tag only refreshes its time.
 */
final class WindowCounter {

    /** One occurrence: when, which audit record, and a tag (an address, a subject). */
    record Entry(long epochMillis, long sequence, String tag) {
    }

    private final long windowMillis;
    private final int threshold;
    private final int maxKeys;
    private final boolean distinct;
    private final LinkedHashMap<String, ArrayDeque<Entry>> keys = new LinkedHashMap<>(16, 0.75f, true);
    private long overflow;

    WindowCounter(Duration window, int threshold, int maxKeys, boolean distinct) {
        this.windowMillis = Objects.requireNonNull(window, "window").toMillis();
        if (windowMillis < 1 || threshold < 1 || threshold > 100 || maxKeys < 1) {
            throw new IllegalArgumentException("window, threshold (1 to 100) and maxKeys must be positive");
        }
        this.threshold = threshold;
        this.maxKeys = maxKeys;
        this.distinct = distinct;
    }

    /**
     * Records one occurrence.
     *
     * @return the entries in the window when this one reaches the threshold (the key then starts again
     *         from zero), otherwise an empty list
     */
    List<Entry> add(String key, Instant at, long sequence, String tag) {
        long now = at.toEpochMilli();
        ArrayDeque<Entry> q = keys.get(key);
        if (q == null) {
            if (keys.size() >= maxKeys && !evictIdle(now)) {
                overflow++;
                return List.of();
            }
            q = new ArrayDeque<>();
            keys.put(key, q);
        }
        while (!q.isEmpty() && q.peekFirst().epochMillis() <= now - windowMillis) {
            q.pollFirst();
        }
        if (distinct) {
            q.removeIf(e -> e.tag().equals(tag));
        }
        q.addLast(new Entry(now, sequence, tag));
        if (q.size() >= threshold) {
            List<Entry> hit = new ArrayList<>(q);
            keys.remove(key);
            return hit;
        }
        return List.of();
    }

    /** Forgets a key (for example a run of step-ups ended by a decision). */
    void reset(String key) {
        keys.remove(key);
    }

    private boolean evictIdle(long now) {
        boolean freed = false;
        Iterator<Map.Entry<String, ArrayDeque<Entry>>> it = keys.entrySet().iterator();
        // Access order: the eldest key was updated longest ago, so stop at the first live one (amortised
        // constant time even when an attacker keeps the table full).
        while (it.hasNext()) {
            ArrayDeque<Entry> q = it.next().getValue();
            if (!q.isEmpty() && q.peekLast().epochMillis() > now - windowMillis) {
                break;
            }
            it.remove();
            freed = true;
        }
        return freed;
    }

    int size() {
        return keys.size();
    }

    long overflow() {
        return overflow;
    }
}

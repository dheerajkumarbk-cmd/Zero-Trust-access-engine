package dev.dwarpal.guard;

import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Remembers single-use values (request ids, report ids) long enough that a captured message cannot
 * be replayed while its signature is still accepted.
 *
 * <p>Every entry is kept for the same {@code retention}, counted from the clock when it was first
 * seen, so insertion order is expiry order and cleaning up is cheap: drop expired entries from the
 * front. Retention must be at least the signature's maximum age plus the allowed clock skew; then a
 * value is remembered for as long as any message carrying it could still verify.
 *
 * <p><b>Fail-closed when full.</b> Evicting a live entry would re-open the replay window, so when
 * the cache is full of live entries, new values are refused (the request fails) and counted. That
 * trades availability for integrity under a flood; the flood itself needs valid signatures.
 */
public final class NonceCache {

    private final Duration retention;
    private final int capacity;
    private final LinkedHashMap<String, Instant> expiries = new LinkedHashMap<>();
    private long refusedWhenFull;

    public NonceCache(Duration retention, int capacity) {
        this.retention = Objects.requireNonNull(retention, "retention");
        if (retention.isNegative() || retention.isZero() || capacity < 1) {
            throw new IllegalArgumentException("retention and capacity must be positive");
        }
        this.capacity = capacity;
    }

    /**
     * True exactly once per value within the retention window: the first time it is seen.
     * False for a replay, and false when the cache is full of live entries.
     */
    public synchronized boolean firstUse(String value, Instant now) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(now, "now");
        purgeExpired(now);
        Instant expiry = expiries.get(value);
        if (expiry != null) {
            return false;
        }
        if (expiries.size() >= capacity) {
            refusedWhenFull++;
            return false;
        }
        expiries.put(value, now.plus(retention));
        return true;
    }

    public synchronized int size() {
        return expiries.size();
    }

    public synchronized long refusedWhenFull() {
        return refusedWhenFull;
    }

    private void purgeExpired(Instant now) {
        Iterator<Map.Entry<String, Instant>> it = expiries.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue().isAfter(now)) {
                return;
            }
            it.remove();
        }
    }
}

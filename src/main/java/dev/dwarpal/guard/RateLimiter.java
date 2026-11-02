package dev.dwarpal.guard;

import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * At most {@code limit} events per key per {@code window} (fixed windows), with a bounded number of
 * keys. Used to stop admin endpoints being flooded and to keep floods of refused attempts from
 * flooding the audit trail.
 *
 * <p>Windows are kept in the order they started, so expired ones are dropped from the front. When the
 * table is full of live windows a new key is refused: under a flood of fresh keys, saying "no" is the
 * safe answer.
 */
public final class RateLimiter {

    private record Window(Instant start, int count) {
    }

    private final int limit;
    private final Duration window;
    private final int maxKeys;
    private final LinkedHashMap<String, Window> windows = new LinkedHashMap<>();
    private long refused;

    public RateLimiter(int limit, Duration window, int maxKeys) {
        this.window = Objects.requireNonNull(window, "window");
        if (limit < 1 || maxKeys < 1 || window.isNegative() || window.isZero()) {
            throw new IllegalArgumentException("limit, window and maxKeys must be positive");
        }
        this.limit = limit;
        this.maxKeys = maxKeys;
    }

    /** True if this event is within the limit (and counts it); false if the key is over its limit. */
    public synchronized boolean tryAcquire(String key, Instant now) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(now, "now");
        dropExpired(now);
        Window w = windows.get(key);
        if (w == null || !now.isBefore(w.start().plus(window))) {
            if (w == null && windows.size() >= maxKeys) {
                refused++;
                return false;
            }
            windows.remove(key);
            windows.put(key, new Window(now, 1));
            return true;
        }
        if (w.count() >= limit) {
            refused++;
            return false;
        }
        windows.put(key, new Window(w.start(), w.count() + 1));
        return true;
    }

    public synchronized long refused() {
        return refused;
    }

    private void dropExpired(Instant now) {
        Iterator<Map.Entry<String, Window>> it = windows.entrySet().iterator();
        while (it.hasNext()) {
            if (now.isBefore(it.next().getValue().start().plus(window))) {
                return;
            }
            it.remove();
        }
    }
}

package dev.dwarpal.console;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Keeps the audit trail compact: the same person reading the same thing again and again inside a short window is one
 * record that says how many repeats it stands for, not one record per click. The first read of a window is always
 * recorded; the repeats are counted, and the count is carried by the next record of that read.
 *
 * <p>The memory is bounded: when too many different reads are being followed, the oldest are forgotten, which can only
 * make the trail longer, never lose a first read.
 */
final class ReadWindow {

    /** Whether to record this read now, and how many repeats the record stands for. */
    record Decision(boolean record, int repeats) {
    }

    private static final class Seen {
        final Instant at;
        int repeats;

        Seen(Instant at) {
            this.at = at;
        }
    }

    private final Duration window;
    private final int capacity;
    private final Map<String, Seen> seen = new LinkedHashMap<>();

    ReadWindow(Duration window, int capacity) {
        if (window.isNegative() || window.isZero() || capacity < 1) {
            throw new IllegalArgumentException("a window and a capacity are needed");
        }
        this.window = window;
        this.capacity = capacity;
    }

    synchronized Decision see(String key, Instant now) {
        Seen s = seen.get(key);
        if (s != null && now.isBefore(s.at.plus(window)) && !now.isBefore(s.at)) {
            s.repeats++;
            return new Decision(false, 0);
        }
        int repeats = s == null ? 0 : s.repeats;
        seen.remove(key);
        if (seen.size() >= capacity) {
            Iterator<String> oldest = seen.keySet().iterator();
            oldest.next();
            oldest.remove();
        }
        seen.put(key, new Seen(now));
        return new Decision(true, repeats);
    }

    /** The record could not be written: the next read of this key must try again. */
    synchronized void undo(String key) {
        seen.remove(key);
    }

    synchronized int size() {
        return seen.size();
    }

    /** For tests: a copy of what is followed. */
    synchronized Map<String, Integer> repeats() {
        Map<String, Integer> out = new HashMap<>();
        seen.forEach((k, v) -> out.put(k, v.repeats));
        return out;
    }
}

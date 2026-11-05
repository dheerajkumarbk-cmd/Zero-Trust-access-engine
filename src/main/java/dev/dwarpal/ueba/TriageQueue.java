package dev.dwarpal.ueba;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertRanker;
import dev.dwarpal.soc.AlertSink;
import dev.dwarpal.soc.RankedAlert;

/**
 * A bounded queue of ranked alerts, in the order an analyst should look at them: priority, then actionable before
 * not, then score, then the oldest first. Alerts of the same rule about the same first entity are folded into one
 * entry that counts up, so a flood of copies takes one place. Part F may use it as its queue or as the reference
 * for its own.
 */
public final class TriageQueue implements AlertSink {

    public static final int MAX_CAPACITY = 1_000_000;

    /** One place in the queue: the latest ranking and how many alerts it stands for. */
    public record Entry(RankedAlert ranked, long alerts, Instant first) {
    }

    private final Object lock = new Object();
    private final AlertRanker ranker;
    private final int capacity;
    private final Map<String, Entry> entries = new LinkedHashMap<>();
    private long refused;
    private long evicted;

    public TriageQueue(AlertRanker ranker, int capacity) {
        this.ranker = Objects.requireNonNull(ranker, "ranker");
        if (capacity < 1 || capacity > MAX_CAPACITY) {
            throw new IllegalArgumentException("capacity 1 to " + MAX_CAPACITY);
        }
        this.capacity = capacity;
    }

    static final Comparator<Entry> ORDER = Comparator
            .comparing((Entry e) -> e.ranked().priority())
            .thenComparing(e -> !e.ranked().actionable())
            .thenComparing(Comparator.comparingDouble((Entry e) -> e.ranked().score()).reversed())
            .thenComparing(Entry::first)
            .thenComparing(e -> e.ranked().alert().id());

    private static String key(Alert a) {
        return a.rule() + "|" + a.entities().get(0);
    }

    /** Ranks the alert at its own time and queues it. */
    @Override
    public boolean raise(Alert alert) {
        return offer(alert, alert.raisedAt());
    }

    /** Ranks the alert at {@code now} and queues it; false if it was refused. */
    public boolean offer(Alert alert, Instant now) {
        RankedAlert r = ranker.rank(alert, now);
        synchronized (lock) {
            String k = key(alert);
            Entry old = entries.get(k);
            if (old != null) {
                RankedAlert keep = ORDER.compare(new Entry(r, 1, old.first()), old) < 0 ? r : old.ranked();
                entries.put(k, new Entry(keep, old.alerts() + 1, old.first()));
                return true;
            }
            if (entries.size() >= capacity) {
                String oldest = entries.keySet().iterator().next();
                entries.remove(oldest);
                evicted++;
            }
            entries.put(k, new Entry(r, 1, alert.raisedAt()));
            return true;
        }
    }

    /** The first {@code n} entries in triage order. */
    public List<Entry> head(int n) {
        if (n < 1 || n > MAX_CAPACITY) {
            throw new IllegalArgumentException("n 1 to " + MAX_CAPACITY);
        }
        synchronized (lock) {
            List<Entry> l = new ArrayList<>(entries.values());
            l.sort(ORDER);
            return List.copyOf(l.subList(0, Math.min(n, l.size())));
        }
    }

    public int size() {
        synchronized (lock) {
            return entries.size();
        }
    }

    public long refused() {
        synchronized (lock) {
            return refused;
        }
    }

    public long evicted() {
        synchronized (lock) {
            return evicted;
        }
    }
}

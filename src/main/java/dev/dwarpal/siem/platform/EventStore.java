package dev.dwarpal.siem.platform;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.soc.ChainedEvent;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EventSearch;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.SecurityEvents;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeSet;

/**
 * The searchable event store: every event of the trail (collected and Dwarpal's own), read only through a keyed
 * {@link AuditCursor}, so nothing in it can have been edited or forged without the audit key. Implements
 * {@link EventSearch} with the {@link Query} language.
 *
 * <p>Bounded: at most {@code capacity} events in memory, the oldest records evicted first (and a search that
 * reaches back past them says so). Indexes by event time, entity, category and dataset; a search starts from the
 * smallest index its required comparisons allow, walks newest first, and stops after examining
 * {@link #MAX_EXAMINED} events, reporting that it stopped. {@code count by} keeps at most {@link #MAX_GROUPS}
 * groups. If the chain breaks, the store keeps what it read before the break and every answer says so.
 */
public final class EventStore implements EventSearch {

    public static final int MAX_CAPACITY = 1_000_000;
    public static final int MAX_EXAMINED = 200_000;
    public static final int MAX_GROUPS = 1_000;

    /** Sort key: event time, then audit sequence. */
    private record Key(long atMillis, int atNanos, long sequence) implements Comparable<Key> {
        private static final Comparator<Key> ORDER = Comparator.comparingLong(Key::atMillis)
                .thenComparingInt(Key::atNanos).thenComparingLong(Key::sequence);

        static Key of(ChainedEvent c) {
            Instant at = c.event().at();
            return new Key(at.toEpochMilli(), at.getNano() % 1_000_000, c.sequence());
        }

        static Key bound(Instant at, boolean low) {
            return new Key(at.toEpochMilli(), at.getNano() % 1_000_000, low ? Long.MIN_VALUE : Long.MAX_VALUE);
        }

        @Override
        public int compareTo(Key o) {
            return ORDER.compare(this, o);
        }
    }

    /** One group of a {@code count by}. */
    public record Group(List<String> values, long count) {
        public Group {
            values = List.copyOf(values);
        }
    }

    /** The answer to a {@code count by} query: groups by count, largest first. */
    public record Counts(List<Group> groups, long matched, boolean truncated, Optional<String> problem) {
        public Counts {
            groups = List.copyOf(groups);
            Objects.requireNonNull(problem, "problem");
        }
    }

    /** What one refresh read. */
    public record Refresh(int read, int malformed, Optional<String> broken) {
    }

    private final AuditCursor cursor;
    private final int capacity;
    private final int maxExamined;
    private final java.util.TreeMap<Key, ChainedEvent> byTime = new java.util.TreeMap<>();
    private final ArrayDeque<Key> bySequence = new ArrayDeque<>();
    private final Map<Entity, TreeSet<Key>> byEntity = new HashMap<>();
    private final Map<SecurityEvent.Category, TreeSet<Key>> byCategory = new EnumMap<>(SecurityEvent.Category.class);
    private final Map<String, TreeSet<Key>> byDataset = new HashMap<>();
    private long evicted;
    private Instant evictedBefore = Instant.MIN;
    private long malformed;

    /**
     * @param cursor   a keyed cursor (built with the audit key), owned by this store from now on
     * @param capacity events kept in memory, 1 to {@link #MAX_CAPACITY}
     */
    public EventStore(AuditCursor cursor, int capacity) {
        this(cursor, capacity, MAX_EXAMINED);
    }

    /** With a lower cost limit (tests, or a deployment on smaller hardware). */
    EventStore(AuditCursor cursor, int capacity, int maxExamined) {
        this.cursor = Objects.requireNonNull(cursor, "cursor");
        if (capacity < 1 || capacity > MAX_CAPACITY) {
            throw new IllegalArgumentException("capacity: 1 to " + MAX_CAPACITY);
        }
        if (maxExamined < 1 || maxExamined > MAX_EXAMINED) {
            throw new IllegalArgumentException("maxExamined: 1 to " + MAX_EXAMINED);
        }
        this.capacity = capacity;
        this.maxExamined = maxExamined;
    }

    /** Reads up to {@code max} new records from the trail. */
    public synchronized Refresh refresh(int max) {
        AuditCursor.Batch b = cursor.next(max);
        int bad = 0;
        for (AuditEvent a : b.events()) {
            ChainedEvent c;
            try {
                c = SecurityEvents.fromAudit(a);
            } catch (IllegalArgumentException e) {
                bad++;
                continue;
            }
            add(c);
        }
        malformed += bad;
        return new Refresh(b.events().size(), bad, b.problem());
    }

    /** Events in memory. */
    public synchronized int size() {
        return byTime.size();
    }

    /** Events evicted to stay within capacity. */
    public synchronized long evicted() {
        return evicted;
    }

    /** Records that were in the chain but did not make a valid event (counted, never guessed). */
    public synchronized long malformed() {
        return malformed;
    }

    private void add(ChainedEvent c) {
        Key k = Key.of(c);
        byTime.put(k, c);
        bySequence.add(k);
        for (Entity e : c.event().entities()) {
            byEntity.computeIfAbsent(e, x -> new TreeSet<>()).add(k);
        }
        byCategory.computeIfAbsent(c.event().category(), x -> new TreeSet<>()).add(k);
        byDataset.computeIfAbsent(c.event().dataset(), x -> new TreeSet<>()).add(k);
        while (byTime.size() > capacity) {
            evict(bySequence.poll());
        }
    }

    private void evict(Key k) {
        ChainedEvent c = byTime.remove(k);
        evicted++;
        if (c.event().at().isAfter(evictedBefore)) {
            evictedBefore = c.event().at();
        }
        for (Entity e : c.event().entities()) {
            TreeSet<Key> s = byEntity.get(e);
            s.remove(k);
            if (s.isEmpty()) {
                byEntity.remove(e);
            }
        }
        byCategory.get(c.event().category()).remove(k);
        TreeSet<Key> d = byDataset.get(c.event().dataset());
        d.remove(k);
        if (d.isEmpty()) {
            byDataset.remove(c.event().dataset());
        }
    }

    @Override
    public synchronized Result search(String query, Instant from, Instant to, int limit) {
        Query q;
        try {
            EventSearch.check(query, from, to, limit);
            q = Query.parse(query);
            Key.bound(from, true);
            Key.bound(to, true);
        } catch (IllegalArgumentException e) {
            return Result.refused(e.getMessage());
        } catch (ArithmeticException e) {
            return Result.refused("time range out of bounds");
        }
        if (!q.countBy().isEmpty()) {
            return Result.refused("'count by' returns groups, not events: use counts");
        }
        List<ChainedEvent> out = new ArrayList<>(Math.min(limit, 64));
        long matched = 0;
        long examined = 0;
        boolean stopped = false;
        for (Key k : candidates(q, from, to).descendingSet()) {
            if (++examined > maxExamined) {
                stopped = true;
                break;
            }
            ChainedEvent c = byTime.get(k);
            if (q.matches(c.event())) {
                matched++;
                if (out.size() < limit) {
                    out.add(c);
                }
            }
        }
        Optional<String> problem = problem(stopped, from);
        return new Result(out, matched, stopped || matched > out.size() || problem.isPresent(), problem);
    }

    /**
     * Counts matching events by the fields after {@code count by} (an entity kind counts each entity of that
     * kind; a missing field counts as {@code -}).
     */
    public synchronized Counts counts(String query, Instant from, Instant to) {
        return countsOf(query, from, to, c -> true);
    }

    @Override
    public synchronized EventSearch.Counts counts(String query, Instant from, Instant to,
                                                  java.util.function.Predicate<ChainedEvent> visible) {
        Counts c = countsOf(query, from, to, Objects.requireNonNull(visible, "visible"));
        return new EventSearch.Counts(c.groups().stream().map(g -> new EventSearch.Group(g.values(), g.count())).toList(),
                c.matched(), c.truncated(), c.problem());
    }

    private Counts countsOf(String query, Instant from, Instant to, java.util.function.Predicate<ChainedEvent> visible) {
        Query q;
        try {
            EventSearch.check(query, from, to, 1);
            q = Query.parse(query);
            Key.bound(from, true);
            Key.bound(to, true);
        } catch (IllegalArgumentException e) {
            return new Counts(List.of(), 0, false, Optional.of(e.getMessage()));
        } catch (ArithmeticException e) {
            return new Counts(List.of(), 0, false, Optional.of("time range out of bounds"));
        }
        if (q.countBy().isEmpty()) {
            return new Counts(List.of(), 0, false, Optional.of("add '| count by <field>'"));
        }
        Map<List<String>, Long> groups = new LinkedHashMap<>();
        long matched = 0;
        long examined = 0;
        boolean stopped = false;
        boolean full = false;
        for (Key k : candidates(q, from, to).descendingSet()) {
            if (++examined > maxExamined) {
                stopped = true;
                break;
            }
            ChainedEvent chained = byTime.get(k);
            SecurityEvent e = chained.event();
            if (!q.matches(e) || !visible.test(chained)) {
                continue;
            }
            matched++;
            List<String> key = new ArrayList<>(q.countBy().size());
            for (String f : q.countBy()) {
                List<String> vs = Query.values(e, f);
                key.add(vs.isEmpty() ? "-" : vs.getFirst());
            }
            if (groups.containsKey(key) || groups.size() < MAX_GROUPS) {
                groups.merge(key, 1L, Long::sum);
            } else {
                full = true;
            }
        }
        List<Group> out = groups.entrySet().stream()
                .sorted(Map.Entry.<List<String>, Long>comparingByValue().reversed())
                .map(x -> new Group(x.getKey(), x.getValue())).toList();
        Optional<String> problem = problem(stopped, from);
        if (problem.isEmpty() && full) {
            problem = Optional.of("more than " + MAX_GROUPS + " groups: the rest are not shown");
        }
        return new Counts(out, matched, stopped || full || problem.isPresent(), problem);
    }

    private Optional<String> problem(boolean stopped, Instant from) {
        List<String> p = new ArrayList<>(3);
        if (stopped) {
            p.add("stopped after examining " + maxExamined + " events: narrow the time range or add a field");
        }
        if (evicted > 0 && !from.isAfter(evictedBefore)) {
            p.add("events up to " + evictedBefore + " are no longer in memory");
        }
        cursor.broken().ifPresent(b -> p.add("the audit trail is broken (" + b + "): later records are not shown"));
        return p.isEmpty() ? Optional.empty() : Optional.of(String.join("; ", p));
    }

    /** The smallest index the query's required comparisons allow, cut to the time range. */
    private NavigableSet<Key> candidates(Query q, Instant from, Instant to) {
        Key lo = Key.bound(from, true);
        Key hi = Key.bound(to, true);
        NavigableSet<Key> best = byTime.navigableKeySet().subSet(lo, true, hi, false);
        int bestSize = maxExamined + 1;
        for (Query.Cmp c : q.required()) {
            if (c.op() != Query.Op.EQ) {
                continue;
            }
            String v = c.values().getFirst();
            TreeSet<Key> index = null;
            Optional<Entity.Kind> kind = Query.entityKind(c.field());
            if (kind.isPresent()) {
                index = entityIndex(kind.get(), v);
            } else if (c.field().equals("category")) {
                index = byCategory.getOrDefault(SecurityEvent.Category.valueOf(v), new TreeSet<>());
            } else if (c.field().equals("dataset")) {
                index = byDataset.getOrDefault(v, new TreeSet<>());
            }
            if (index != null) {
                NavigableSet<Key> s = index.subSet(lo, true, hi, false);
                int n = sizeUpTo(s, bestSize);
                if (n < bestSize) {
                    best = s;
                    bestSize = n;
                }
            }
        }
        return best;
    }

    /** The size of a view, counted only up to {@code cap} (a view's own size() walks all of it). */
    private static int sizeUpTo(NavigableSet<Key> s, int cap) {
        int n = 0;
        for (Key ignored : s) {
            if (++n >= cap) {
                break;
            }
        }
        return n;
    }

    private TreeSet<Key> entityIndex(Entity.Kind kind, String id) {
        try {
            return byEntity.getOrDefault(new Entity(kind, id), new TreeSet<>());
        } catch (IllegalArgumentException notAnId) {
            return new TreeSet<>();
        }
    }
}

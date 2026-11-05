package dev.dwarpal.siem.platform;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertSink;
import dev.dwarpal.soc.ChainedEvent;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.SecurityEvents;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Technique;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Runs a {@link RuleBook} over the event stream of the audit chain and raises {@link Alert}s into the shared
 * {@link AlertSink}. It reads only through a keyed {@link AuditCursor}; at a break in the chain it stops for good
 * (part A's detection raises the {@code audit-chain-break} alert).
 *
 * <p><b>Time.</b> Windows use event time, not arrival order: endpoint batches arrive up to an hour after their
 * events, so each key keeps its events sorted and a threshold checks every window that contains the new event.
 * The engine's clock is the newest event time seen. An event dated more than {@link Settings#maxAhead} after the
 * record that carries it is ignored and counted (it would move the clock forward and close everyone's windows);
 * an event older than the clock minus {@link Settings#lateness} minus the rule's window is too late for that
 * rule and counted.
 *
 * <p><b>Bounds.</b> At most {@link Settings#maxKeys} keys per rule and {@link Settings#maxEntriesPerKey} events per
 * key; when a rule's state is full new keys are refused, counted and reported by one HIGH
 * {@code correlation-state-full} alert per rule per hour (live keys are never forgotten to make room, so flooding
 * with invented entities cannot push the real attacker out). Idle keys are dropped once their window has passed.
 * A rule that fired for a key is quiet for that key for one window (counted as suppressed). At most
 * {@link Settings#maxAlertsPerHour} alerts per rule per hour, then one HIGH {@code correlation-flood} alert.
 * Alerts the sink refuses are kept (at most 1,000) and offered again before anything new.
 *
 * <p><b>Provenance.</b> An alert whose evidence is only {@code COLLECTED} says so at the start of its summary, and
 * {@link #recent()} reports it as not actionable: anyone on the network can send such events.
 */
public final class CorrelationEngine {

    public static final String FLOOD_RULE = "correlation-flood";
    public static final String STATE_FULL_RULE = "correlation-state-full";
    public static final String COLLECTED_ONLY = "COLLECTED evidence only, not for destructive action: ";
    public static final int MAX_PENDING_ALERTS = 1_000;
    public static final int MAX_RECENT = 1_000;

    /** Limits; {@link #defaults()} suit a small organisation. */
    public record Settings(Duration lateness, Duration maxAhead, int maxKeys, int maxEntriesPerKey,
                           int maxAlertsPerHour) {
        public Settings {
            Objects.requireNonNull(lateness, "lateness");
            Objects.requireNonNull(maxAhead, "maxAhead");
            if (lateness.isNegative() || lateness.compareTo(Duration.ofDays(1)) > 0) {
                throw new IllegalArgumentException("lateness: 0 to 1 day");
            }
            if (maxAhead.isNegative() || maxAhead.compareTo(Duration.ofHours(1)) > 0) {
                throw new IllegalArgumentException("maxAhead: 0 to 1 hour");
            }
            if (maxKeys < 1 || maxKeys > 100_000 || maxEntriesPerKey < 2 || maxEntriesPerKey > 20_000
                    || maxAlertsPerHour < 1 || maxAlertsPerHour > 10_000) {
                throw new IllegalArgumentException("limits out of range");
            }
        }

        public static Settings defaults() {
            return new Settings(Duration.ofHours(2), Duration.ofMinutes(5), 10_000, 2_000, 50);
        }
    }

    /** An alert as raised, with what the rule says about it. */
    public record Raised(Alert alert, List<Technique> techniques, boolean actionable) {
        public Raised {
            techniques = List.copyOf(techniques);
        }
    }

    /** What one run read and did. */
    public record Report(int read, int alerts, Optional<String> problem) {
    }

    /**
     * One event as rules keep it, or several merged ones: {@code weight} events whose numeric values add up to
     * {@code amount}, dated at the newest of them.
     */
    private record Entry(long atMillis, long sequence, Instant recordedAt, String value, boolean collected,
                         List<Entity> entities, long weight, double amount) {
        static final Comparator<Entry> ORDER = Comparator.comparingLong(Entry::atMillis)
                .thenComparingLong(Entry::sequence);
    }

    private final RuleBook book;
    private final AlertSink sink;
    private final Settings settings;
    private final List<RuleState> states = new ArrayList<>();
    private final ArrayDeque<Alert> pending = new ArrayDeque<>();
    private final ArrayDeque<Raised> recent = new ArrayDeque<>();
    private long clock = Long.MIN_VALUE;
    private long processed;
    private long ignoredAhead;
    private long late;
    private long malformed;
    private long lost;
    private long raised;
    private String broken;

    public CorrelationEngine(RuleBook book, AlertSink sink, Settings settings) {
        this.book = Objects.requireNonNull(book, "book");
        this.sink = Objects.requireNonNull(sink, "sink");
        this.settings = Objects.requireNonNull(settings, "settings");
        for (RuleBook.Rule r : book.rules()) {
            reachable(r, settings);
            states.add(new RuleState(r));
        }
    }

    /**
     * Refuses a rule that these limits would never let fire (red-team finding rD4): a distinct count or a sequence
     * step needing more events than a key may hold. Counts and sums are safe: full state merges, never drops.
     */
    private static void reachable(RuleBook.Rule r, Settings s) {
        if (r.kind() == RuleBook.Kind.THRESHOLD && r.measure() == RuleBook.Measure.DISTINCT
                && r.amount() > s.maxEntriesPerKey()) {
            throw new IllegalArgumentException("rule " + r.id() + " can never fire: it needs " + (long) r.amount()
                    + " distinct values but a key holds at most " + s.maxEntriesPerKey() + " events");
        }
        for (RuleBook.Step st : r.steps()) {
            if (st.min() > s.maxEntriesPerKey()) {
                throw new IllegalArgumentException("rule " + r.id() + " can never fire: a step needs " + st.min()
                        + " events but a key holds at most " + s.maxEntriesPerKey());
            }
        }
    }

    // ---- reading --------------------------------------------------------------------------------------------

    /** Reads up to {@code max} records through the cursor and runs every rule on them. */
    public synchronized Report run(AuditCursor cursor, int max) {
        if (broken != null) {
            return new Report(0, 0, Optional.of(broken));
        }
        long before = raised;
        retry();
        AuditCursor.Batch b = cursor.next(max);
        for (AuditEvent a : b.events()) {
            ChainedEvent c;
            try {
                c = SecurityEvents.fromAudit(a);
            } catch (IllegalArgumentException e) {
                malformed++;
                continue;
            }
            process(c);
        }
        if (b.problem().isPresent()) {
            broken = "stopped at a break in the audit chain: " + b.problem().get();
        }
        return new Report(b.events().size(), (int) (raised - before), Optional.ofNullable(broken));
    }

    /** Runs every rule on one event (events must come from the verified chain). */
    public synchronized void process(ChainedEvent c) {
        Objects.requireNonNull(c, "event");
        SecurityEvent e = c.event();
        if (e.at().isAfter(c.recordedAt().plus(settings.maxAhead()))) {
            ignoredAhead++;
            return;
        }
        processed++;
        long at = e.at().toEpochMilli();
        clock = Math.max(clock, at);
        boolean tooLate = false;
        for (RuleState s : states) {
            tooLate |= s.offer(c, at);
        }
        if (tooLate) {
            late++;
        }
        for (RuleState s : states) {
            s.sweep(c);
        }
        retry();
    }

    // ---- counters -------------------------------------------------------------------------------------------

    public synchronized long processed() {
        return processed;
    }

    /** Events dated too far after their record, ignored. */
    public synchronized long ignoredAhead() {
        return ignoredAhead;
    }

    /** Events too late for at least one rule's window. */
    public synchronized long late() {
        return late;
    }

    public synchronized long malformed() {
        return malformed;
    }

    /** Alerts the sink refused and that could not be kept either. */
    public synchronized long lost() {
        return lost;
    }

    public synchronized long raised() {
        return raised;
    }

    /** Why the engine stopped, if it did. */
    public synchronized Optional<String> broken() {
        return Optional.ofNullable(broken);
    }

    /** The newest alerts with their techniques and whether anyone may act on them, newest last. */
    public synchronized List<Raised> recent() {
        return List.copyOf(recent);
    }

    /** Matches and alerts per rule, for "which rules never fire" health checks. */
    public synchronized Map<String, long[]> statistics() {
        Map<String, long[]> out = new LinkedHashMap<>();
        for (RuleState s : states) {
            out.put(s.rule.id(), new long[]{s.matches, s.fired, s.suppressed, s.refusedKeys});
        }
        return out;
    }

    /** Rules that have matched no event at all so far (dead rules, or sources that went quiet). */
    public synchronized List<String> silentRules() {
        return states.stream().filter(s -> s.matches == 0).map(s -> s.rule.id()).toList();
    }

    /** Keys held over all rules. */
    public synchronized int keys() {
        return states.stream().mapToInt(s -> s.keys.size()).sum();
    }

    // ---- alerts ---------------------------------------------------------------------------------------------

    private void retry() {
        while (!pending.isEmpty()) {
            Alert a = pending.peek();
            boolean ok;
            try {
                ok = sink.raise(a);
            } catch (RuntimeException e) {
                ok = false;
            }
            if (!ok) {
                return;
            }
            pending.poll();
        }
    }

    private void emit(Alert a, List<Technique> techniques, boolean actionable) {
        raised++;
        recent.add(new Raised(a, techniques, actionable));
        if (recent.size() > MAX_RECENT) {
            recent.poll();
        }
        if (pending.isEmpty()) {
            boolean ok;
            try {
                ok = sink.raise(a);
            } catch (RuntimeException e) {
                ok = false;
            }
            if (ok) {
                return;
            }
        }
        if (pending.size() < MAX_PENDING_ALERTS) {
            pending.add(a);
        } else {
            lost++;
        }
    }

    // ---- per rule -------------------------------------------------------------------------------------------

    private static final class Key {
        final List<String> values;
        final List<Entry> entries = new ArrayList<>();
        final List<List<Entry>> steps;
        long cooldownUntil = Long.MIN_VALUE;
        long newest = Long.MIN_VALUE;
        boolean absent;

        Key(List<String> values, int steps) {
            this.values = values;
            this.steps = new ArrayList<>(steps);
            for (int i = 0; i < steps; i++) {
                this.steps.add(new ArrayList<>());
            }
        }
    }

    private final class RuleState {
        final RuleBook.Rule rule;
        final long window;
        final Map<List<String>, Key> keys = new HashMap<>();
        final Map<Long, Integer> perHour = new HashMap<>();
        final Set<Long> floodHours = new HashSet<>();
        final Set<Long> fullHours = new HashSet<>();
        long matches;
        long fired;
        long suppressed;
        long refusedKeys;
        long lastSweep = Long.MIN_VALUE;

        RuleState(RuleBook.Rule rule) {
            this.rule = rule;
            this.window = rule.within().toMillis();
        }

        /** @return true if the event matched but was too late for this rule */
        boolean offer(ChainedEvent c, long at) {
            SecurityEvent e = c.event();
            if (rule.kind() == RuleBook.Kind.MATCH) {
                if (rule.where().matches(e)) {
                    matches++;
                    Entry x = entry(c, "");
                    fire(c.event().at(), List.of(), List.of(x), 1, "");
                }
                return false;
            }
            List<Integer> stepHits = new ArrayList<>(1);
            if (rule.kind() == RuleBook.Kind.SEQUENCE) {
                for (int i = 0; i < rule.steps().size(); i++) {
                    if (rule.steps().get(i).where().matches(e)) {
                        stepHits.add(i);
                    }
                }
                if (stepHits.isEmpty()) {
                    return false;
                }
            } else if (!rule.where().matches(e)) {
                return false;
            }
            matches++;
            if (at < clock - settings.lateness().toMillis() - window) {
                return true;
            }
            List<String> kv = keyOf(e);
            if (kv == null) {
                return false;
            }
            Key k = keys.get(kv);
            if (k == null) {
                if (keys.size() >= settings.maxKeys()) {
                    refusedKeys++;
                    stateFull(c);
                    return false;
                }
                k = new Key(kv, rule.steps().size());
                keys.put(kv, k);
            }
            long previous = k.newest;
            k.newest = Math.max(k.newest, at);
            switch (rule.kind()) {
                case THRESHOLD -> threshold(k, c, at);
                case SEQUENCE -> sequence(k, c, stepHits);
                default -> {
                    if (!k.absent && previous != Long.MIN_VALUE && at - previous > window) {
                        // the key went quiet and came back before anything else moved the clock (rD3)
                        fire(c.event().at(), k.values, List.of(k.entries.getLast(), entry(c, "")), 1,
                                "nothing for " + Duration.ofMillis(at - previous).toMinutes()
                                        + " min, then it came back");
                    }
                    if (k.entries.isEmpty() || at >= k.entries.getLast().atMillis()) {
                        k.entries.clear();
                        k.entries.add(entry(c, ""));
                    }
                    k.absent = false;
                }
            }
            return false;
        }

        private List<String> keyOf(SecurityEvent e) {
            List<String> kv = new ArrayList<>(rule.by().size());
            for (String f : rule.by()) {
                List<String> vs = Query.values(e, f);
                if (vs.isEmpty()) {
                    return null;
                }
                kv.add(vs.getFirst());
            }
            return List.copyOf(kv);
        }

        private Entry entry(ChainedEvent c, String value) {
            double amount = rule.measure() == RuleBook.Measure.SUM ? Query.number(value).orElse(0.0) : 0.0;
            return new Entry(c.event().at().toEpochMilli(), c.sequence(), c.recordedAt(), value,
                    !c.event().provenance().actionable(), c.event().entities(), 1, amount);
        }

        /** Inserts in time order; a full list drops its oldest entry (sequences: bounded per step). */
        private void insert(List<Entry> list, Entry x, int cap) {
            int i = Collections.binarySearch(list, x, Entry.ORDER);
            if (i < 0) {
                list.add(-i - 1, x);
            }
            if (list.size() > cap) {
                list.removeFirst();
            }
        }

        /**
         * Inserts into a threshold's window. When the key is full nothing is forgotten that the measure needs
         * (red-team finding rD5): counts and sums merge the two oldest entries (the merged one carries both
         * weights and amounts at the later time, so a window can only over-count, never under-count); a distinct
         * count drops the oldest entry whose value appears again later, keeping every distinct value.
         */
        private void insertThreshold(List<Entry> list, Entry x) {
            int i = Collections.binarySearch(list, x, Entry.ORDER);
            if (i >= 0) {
                return;
            }
            list.add(-i - 1, x);
            if (list.size() <= settings.maxEntriesPerKey()) {
                return;
            }
            if (rule.measure() == RuleBook.Measure.DISTINCT) {
                Map<String, Integer> seen = new HashMap<>();
                for (Entry e : list) {
                    seen.merge(e.value(), 1, Integer::sum);
                }
                for (int j = 0; j < list.size(); j++) {
                    if (seen.get(list.get(j).value()) > 1) {
                        list.remove(j);
                        return;
                    }
                }
                list.removeFirst();
                return;
            }
            Entry a = list.removeFirst();
            Entry b = list.removeFirst();
            list.addFirst(new Entry(b.atMillis(), b.sequence(), b.recordedAt(), b.value(),
                    a.collected() && b.collected(), b.entities(), a.weight() + b.weight(), a.amount() + b.amount()));
        }

        private void threshold(Key k, ChainedEvent c, long at) {
            String value = rule.measure() == RuleBook.Measure.COUNT ? ""
                    : Query.values(c.event(), rule.field()).stream().findFirst().orElse(null);
            if (value == null) {
                return;
            }
            if (rule.measure() == RuleBook.Measure.SUM && Query.number(value).isEmpty()) {
                return;
            }
            insertThreshold(k.entries, entry(c, value));
            // every window [s, s + within] whose start s is an entry in [at - within, at], in one pass (rD6)
            List<Entry> es = k.entries;
            int i = 0;
            while (i < es.size() && es.get(i).atMillis() < at - window) {
                i++;
            }
            int j = i;
            long weight = 0;
            double amount = 0;
            Map<String, Integer> distinct = new HashMap<>();
            for (; i < es.size() && es.get(i).atMillis() <= at; i++) {
                long end = es.get(i).atMillis() + window;
                while (j < es.size() && es.get(j).atMillis() <= end) {
                    Entry x = es.get(j++);
                    weight += x.weight();
                    amount += x.amount();
                    distinct.merge(x.value(), 1, Integer::sum);
                }
                double measured = switch (rule.measure()) {
                    case COUNT -> weight;
                    case DISTINCT -> distinct.size();
                    case SUM -> amount;
                };
                if (measured >= rule.amount()) {
                    if (at < k.cooldownUntil) {
                        suppressed++;
                        return;
                    }
                    List<Entry> inWindow = es.subList(i, j);
                    String what = switch (rule.measure()) {
                        case COUNT -> weight + " events";
                        case DISTINCT -> distinct.size() + " distinct " + rule.field();
                        case SUM -> String.format(java.util.Locale.ROOT, "%.0f %s", amount, rule.field());
                    };
                    fire(c.event().at(), k.values, List.copyOf(inWindow), weight, what + " within " + rule.within());
                    k.cooldownUntil = inWindow.getLast().atMillis() + window;
                    inWindow.clear();
                    return;
                }
                Entry gone = es.get(i);
                weight -= gone.weight();
                amount -= gone.amount();
                distinct.computeIfPresent(gone.value(), (v, n) -> n == 1 ? null : n - 1);
            }
        }

        private void sequence(Key k, ChainedEvent c, List<Integer> hits) {
            Entry x = entry(c, "");
            for (int i : hits) {
                int cap = Math.min(settings.maxEntriesPerKey(), Math.max(64, 4 * rule.steps().get(i).min()));
                insert(k.steps.get(i), x, cap);
            }
            List<RuleBook.Step> steps = rule.steps();
            for (Entry start : k.steps.getFirst()) {
                List<Entry> chain = chain(k, start, steps);
                if (chain != null) {
                    if (start.atMillis() < k.cooldownUntil) {
                        suppressed++;
                        return;
                    }
                    fire(c.event().at(), k.values, chain, chain.size(), steps.size() + " steps within "
                            + rule.within());
                    k.cooldownUntil = chain.getLast().atMillis() + window;
                    k.steps.forEach(List::clear);
                    return;
                }
            }
        }

        /** The earliest chain from {@code start}: each step's {@code min} events after the step before. */
        private List<Entry> chain(Key k, Entry start, List<RuleBook.Step> steps) {
            List<Entry> chain = new ArrayList<>();
            Entry prev = null;
            long end = start.atMillis() + window;
            for (int s = 0; s < steps.size(); s++) {
                int need = steps.get(s).min();
                for (Entry e : k.steps.get(s)) {
                    if (need == 0) {
                        break;
                    }
                    if (s == 0 && Entry.ORDER.compare(e, start) < 0) {
                        continue;
                    }
                    if (prev != null && Entry.ORDER.compare(e, prev) <= 0) {
                        continue;
                    }
                    if (e.atMillis() > end) {
                        break;
                    }
                    if (chain.contains(e)) {
                        continue;
                    }
                    chain.add(e);
                    prev = e;
                    need--;
                }
                if (need > 0) {
                    return null;
                }
            }
            return chain;
        }

        /** Drops idle keys and old entries; fires absence rules whose key went quiet. */
        void sweep(ChainedEvent c) {
            long horizon = clock - settings.lateness().toMillis() - window;
            if (lastSweep != Long.MIN_VALUE && clock - lastSweep < 60_000) {
                return;
            }
            lastSweep = clock;
            Iterator<Key> it = keys.values().iterator();
            while (it.hasNext()) {
                Key k = it.next();
                if (rule.kind() == RuleBook.Kind.ABSENCE) {
                    if (!k.absent && k.newest + window < clock - settings.lateness().toMillis()) {
                        k.absent = true;
                        Entry last = k.entries.getLast();
                        fire(c.event().at(), k.values, List.of(last), 1, "nothing for " + rule.within()
                                + " after the last event");
                    }
                    continue;
                }
                k.entries.removeIf(x -> x.atMillis() < horizon);
                k.steps.forEach(l -> l.removeIf(x -> x.atMillis() < horizon));
                if (k.newest < horizon && k.cooldownUntil < clock) {
                    it.remove();
                }
            }
        }

        private void fire(Instant eventTime, List<String> keyValues, List<Entry> evidence, long count, String what) {
            long hour = Math.floorDiv(eventTime.toEpochMilli(), 3_600_000L);
            int n = perHour.merge(hour, 1, Integer::sum);
            if (perHour.size() > 48) {
                perHour.keySet().removeIf(h -> h < hour - 24);
                floodHours.removeIf(h -> h < hour - 24);
                fullHours.removeIf(h -> h < hour - 24);
            }
            List<Long> seqs = evidence.stream().map(Entry::sequence).sorted().toList();
            if (seqs.size() > Alert.MAX_EVIDENCE) {
                seqs = seqs.subList(seqs.size() - Alert.MAX_EVIDENCE, seqs.size());
            }
            Instant raisedAt = evidence.stream().map(Entry::recordedAt).max(Comparator.naturalOrder()).orElseThrow();
            if (n > settings.maxAlertsPerHour()) {
                suppressed++;
                if (floodHours.add(hour)) {
                    emit(new Alert("al-" + FLOOD_RULE + "-" + rule.id() + "-" + seqs.getLast(), FLOOD_RULE,
                            Severity.HIGH, raisedAt, List.of(new Entity(Entity.Kind.RESOURCE, "rule:" + rule.id())),
                            seqs, n, "rule " + rule.id() + " raised more than " + settings.maxAlertsPerHour()
                            + " alerts this hour: the rest are counted, not raised"), List.of(), false);
                }
                return;
            }
            fired++;
            Set<Entity> entities = new LinkedHashSet<>();
            for (int i = 0; i < rule.by().size(); i++) {
                Optional<Entity.Kind> kind = Query.entityKind(rule.by().get(i));
                if (kind.isPresent()) {
                    entities.add(new Entity(kind.get(), keyValues.get(i)));
                }
            }
            for (Entry x : evidence) {
                for (Entity en : x.entities()) {
                    if (entities.size() < Alert.MAX_ENTITIES && en.kind() != Entity.Kind.RESOURCE) {
                        entities.add(en);
                    }
                }
            }
            if (entities.isEmpty()) {
                entities.add(new Entity(Entity.Kind.RESOURCE, "rule:" + rule.id()));
            }
            boolean actionable = evidence.stream().anyMatch(x -> !x.collected());
            String key = keyValues.isEmpty() ? "" : " for " + rule.by().stream().collect(Collectors.joining(","))
                    + "=" + String.join(",", keyValues);
            String mitre = rule.techniques().stream().map(Technique::id).collect(Collectors.joining(","));
            String summary = (actionable ? "" : COLLECTED_ONLY) + rule.title() + key
                    + (what.isEmpty() ? "" : ", " + what) + " [MITRE " + mitre + "]";
            List<Entity> named = entities.stream().limit(Alert.MAX_ENTITIES).toList();
            emit(new Alert("al-" + rule.id() + "-" + seqs.getLast(), rule.id(), rule.severity(), raisedAt, named,
                    seqs, count, summary), rule.techniques(), actionable);
        }

        private void stateFull(ChainedEvent c) {
            long hour = Math.floorDiv(c.event().at().toEpochMilli(), 3_600_000L);
            if (fullHours.add(hour)) {
                emit(new Alert("al-" + STATE_FULL_RULE + "-" + rule.id() + "-" + c.sequence(), STATE_FULL_RULE,
                        Severity.HIGH, c.recordedAt(), List.of(new Entity(Entity.Kind.RESOURCE, "rule:" + rule.id())),
                        List.of(c.sequence()), 1, "rule " + rule.id() + " is tracking " + settings.maxKeys()
                        + " keys: new keys are refused and counted (possible flood)"), List.of(), false);
            }
        }
    }

    /** The rule book this engine runs. */
    public RuleBook book() {
        return book;
    }
}

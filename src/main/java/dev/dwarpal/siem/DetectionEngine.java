package dev.dwarpal.siem;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditSource;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertSink;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Turns the audit trail into alerts. It reads through a keyed {@link AuditCursor} (so every event it
 * sees is proven to be Dwarpal's, in order, with nothing missing), runs the standard rules, and sends
 * {@link Alert}s to an {@link AlertSink}.
 *
 * <ul>
 *   <li><b>Deterministic</b>: alerts depend only on the trail. Times are audit times, ids are
 *       {@code al-<rule>-<sequence>}, windows close on audit time, so replaying a trail (or reading it in
 *       other batch sizes) gives the same alerts.</li>
 *   <li><b>Deduplicated</b>: one alert per rule and entity per window ({@link Settings#dedupWindow});
 *       repeats inside the window are counted and reported once, when the window closes, as a roll-up
 *       alert with that count.</li>
 *   <li><b>Throttled</b>: at most {@link Settings#maxAlertsPerRulePerHour} new alerts per rule per hour of
 *       audit time; beyond that one {@code alert-flood} alert for the rule and hour, and the rest are
 *       counted. CRITICAL rules (break-glass, honeytoken) have their own, higher cap
 *       ({@link Settings#maxCriticalPerRulePerHour}), so noise from other rules never buries them, yet an
 *       attacker who knows a honeytoken cannot page the SOC without end either (red-team R-A3). The
 *       trail's own alerts are raised once and never throttled.</li>
 *   <li><b>Bounded</b>: every rule's state, the open windows and the queue of alerts the sink refused
 *       have hard limits; when rule state is full, new keys are refused and counted, and a
 *       {@code detection-state-full} alert says so (once per hour).</li>
 *   <li><b>Fail closed on the trail</b>: a chain break, a source that throws, or a trail that disagrees
 *       with its {@link HeadAnchor} raises exactly one CRITICAL alert and stops detection for good.</li>
 *   <li><b>No silent loss</b>: an alert the sink refuses is kept and offered again; while any is waiting,
 *       nothing more is read (back-pressure).</li>
 * </ul>
 *
 * Detection state lives in memory: after a restart, {@link #resume} continues from a checkpoint, but
 * windows that were open start again from zero.
 */
public final class DetectionEngine {

    public static final String CHAIN_BREAK = "audit-chain-break";
    public static final String ANCHOR_MISMATCH = "audit-anchor-mismatch";
    public static final String ALERT_FLOOD = "alert-flood";
    public static final String STATE_FULL = "detection-state-full";
    private static final Entity TRAIL = new Entity(Entity.Kind.RESOURCE, "audit-trail");
    private static final Entity DETECTION = new Entity(Entity.Kind.RESOURCE, "detection-engine");
    private static final long HOUR_MILLIS = Duration.ofHours(1).toMillis();

    /**
     * @param dedupWindow             how long repeats of one rule and entity fold into one alert
     * @param maxAlertsPerRulePerHour   new non-CRITICAL alerts per rule per hour of audit time
     * @param maxCriticalPerRulePerHour new CRITICAL alerts per rule per hour of audit time
     * @param maxOpenWindows            deduplication windows kept at once
     * @param maxKeysPerRule            entities each counting rule tracks at once
     * @param readChunk                 events read per cursor call
     * @param maxEventsPerPoll          events one {@link #poll} reads at most
     */
    public record Settings(Duration dedupWindow, int maxAlertsPerRulePerHour, int maxCriticalPerRulePerHour,
                           int maxOpenWindows, int maxKeysPerRule, int readChunk, int maxEventsPerPoll) {
        public Settings {
            Objects.requireNonNull(dedupWindow, "dedupWindow");
            if (dedupWindow.compareTo(Duration.ofMinutes(1)) < 0 || dedupWindow.compareTo(Duration.ofDays(1)) > 0) {
                throw new IllegalArgumentException("dedupWindow must be 1 min to 1 day");
            }
            if (maxAlertsPerRulePerHour < 1 || maxAlertsPerRulePerHour > 10_000
                    || maxCriticalPerRulePerHour < 1 || maxCriticalPerRulePerHour > 10_000) {
                throw new IllegalArgumentException("alerts per rule per hour must be 1 to 10,000");
            }
            if (maxOpenWindows < 1 || maxOpenWindows > 1_000_000 || maxKeysPerRule < 1 || maxKeysPerRule > 1_000_000) {
                throw new IllegalArgumentException("state limits must be 1 to 1,000,000");
            }
            if (readChunk < 1 || readChunk > AuditSource.MAX_BATCH || maxEventsPerPoll < 1) {
                throw new IllegalArgumentException("readChunk must be 1 to " + AuditSource.MAX_BATCH
                        + " and maxEventsPerPoll positive");
            }
        }

        public static Settings defaults() {
            return new Settings(Duration.ofHours(1), 50, 200, 50_000, 20_000, 500, 1_000_000);
        }
    }

    /** What one {@link #poll} did. */
    public record Report(int events, int alerts, int waiting, Optional<String> stopped) {
        public Report {
            Objects.requireNonNull(stopped, "stopped");
        }
    }

    /** Running totals, for monitoring the monitor. */
    public record Stats(long events, long raised, long deduplicated, long throttled, long stateOverflow,
                        long refusedBySink, long lost, int openWindows, int ruleState) {
    }

    private static final class Open {
        final Rules.Hit first;
        final long firstSeq;
        final long closesAt;
        final List<Long> repeats = new ArrayList<>();
        long repeatCount;
        Instant lastAt;

        Open(Rules.Hit first, long closesAt) {
            this.first = first;
            this.firstSeq = first.evidence.getLast();
            this.closesAt = closesAt;
        }
    }

    private final Object lock = new Object();
    private final AuditCursor cursor;
    private final AlertSink sink;
    private final Supplier<Optional<AuditLog.Head>> anchor;
    private final Settings settings;
    private final List<Rules.Rule> rules;
    private final LinkedHashMap<String, Open> open = new LinkedHashMap<>();
    private final Map<String, long[]> perRuleHour = new HashMap<>();
    private final ArrayDeque<Alert> waiting = new ArrayDeque<>();
    private final int maxWaiting;
    private Instant lastTime = Instant.EPOCH;
    private long lastOverflow;
    private long stateFullHour = Long.MIN_VALUE;
    private String stopped;
    private long events;
    private long raised;
    private long deduplicated;
    private long throttled;
    private long refusedBySink;
    private long lost;

    /**
     * Detection from the first record.
     *
     * @param auditKey the audit HMAC key: detection never runs on records it cannot prove are Dwarpal's
     * @param anchor   the anchored head ({@code headAnchor::read}); an exception from it counts as tampering
     */
    public DetectionEngine(AuditSource source, SecretKey auditKey, AlertSink sink,
                           Supplier<Optional<AuditLog.Head>> anchor, Settings settings) {
        this(AuditCursor.fromStart(source, Objects.requireNonNull(auditKey, "auditKey")), sink, anchor, settings);
    }

    private DetectionEngine(AuditCursor cursor, AlertSink sink, Supplier<Optional<AuditLog.Head>> anchor,
                            Settings settings) {
        this.cursor = cursor;
        this.sink = Objects.requireNonNull(sink, "sink");
        this.anchor = Objects.requireNonNull(anchor, "anchor");
        this.settings = Objects.requireNonNull(settings, "settings");
        this.rules = Rules.standard(settings.maxKeysPerRule());
        this.maxWaiting = settings.maxOpenWindows() + settings.readChunk() * 16 + 64;
    }

    /** Detection after a checkpoint saved earlier ({@link #checkpoint()}), kept somewhere trusted. */
    public static DetectionEngine resume(AuditSource source, SecretKey auditKey, AuditLog.Head checkpoint,
                                         AlertSink sink, Supplier<Optional<AuditLog.Head>> anchor, Settings settings) {
        return new DetectionEngine(AuditCursor.resume(source, Objects.requireNonNull(auditKey, "auditKey"), checkpoint),
                sink, anchor, settings);
    }

    /** Reads what is new (up to {@link Settings#maxEventsPerPoll}) and raises what it finds. */
    public Report poll() {
        synchronized (lock) {
            long raisedBefore = raised;
            int read = 0;
            if (!retryWaiting() || stopped != null) {
                return report(read, raisedBefore);
            }
            Optional<AuditLog.Head> a;
            try {
                a = anchor.get();
            } catch (RuntimeException e) {
                stop(ANCHOR_MISMATCH, "audit anchor unusable: " + e.getMessage());
                return report(read, raisedBefore);
            }
            boolean caughtUp = false;
            while (read < settings.maxEventsPerPoll() && waiting.isEmpty()) {
                long position = cursor.checkpoint().sequence();
                int limit = Math.min(settings.readChunk(), settings.maxEventsPerPoll() - read);
                if (a.isPresent() && position < a.get().sequence()) {
                    limit = (int) Math.min(limit, a.get().sequence() - position);
                }
                AuditCursor.Batch batch;
                try {
                    batch = cursor.next(limit);
                } catch (RuntimeException e) {
                    stop(CHAIN_BREAK, "audit source failed after record " + position + ": " + e.getMessage());
                    return report(read, raisedBefore);
                }
                for (AuditEvent e : batch.events()) {
                    observe(e);
                    read++;
                }
                if (batch.problem().isPresent()) {
                    stop(CHAIN_BREAK, batch.problem().get());
                    return report(read, raisedBefore);
                }
                if (a.isPresent() && cursor.checkpoint().sequence() == a.get().sequence()) {
                    Optional<String> mismatch = cursor.checkAgainst(a.get());
                    if (mismatch.isPresent()) {
                        stop(ANCHOR_MISMATCH, mismatch.get());
                        return report(read, raisedBefore);
                    }
                }
                if (batch.events().isEmpty()) {
                    caughtUp = true;
                    break;
                }
            }
            if (caughtUp && a.isPresent()) {
                Optional<String> mismatch = cursor.checkAgainst(a.get());
                if (mismatch.isPresent()) {
                    stop(ANCHOR_MISMATCH, mismatch.get());
                }
            }
            return report(read, raisedBefore);
        }
    }

    /**
     * Closes every open window now, raising the roll-ups for repeats (for example at shutdown or at the end
     * of a replayed trail).
     */
    public Report flush() {
        synchronized (lock) {
            long before = raised;
            Iterator<Open> it = open.values().iterator();
            while (it.hasNext()) {
                rollUp(it.next());
                it.remove();
            }
            retryWaiting();
            return report(0, before);
        }
    }

    /** The last verified position: save it somewhere trusted to {@link #resume} later. */
    public AuditLog.Head checkpoint() {
        return cursor.checkpoint();
    }

    public Stats stats() {
        synchronized (lock) {
            return new Stats(events, raised, deduplicated, throttled, overflow(), refusedBySink, lost, open.size(),
                    ruleState());
        }
    }

    /** Why detection stopped for good, if it did. */
    public Optional<String> stopped() {
        synchronized (lock) {
            return Optional.ofNullable(stopped);
        }
    }

    // ---- per event -----------------------------------------------------------------------------------

    private void observe(AuditEvent e) {
        events++;
        if (e.at().isAfter(lastTime)) {
            lastTime = e.at();
        }
        closeWindows(e.at().toEpochMilli());
        Consumer<Rules.Hit> onHit = this::hit;
        for (Rules.Rule r : rules) {
            r.observe(e, onHit);
        }
        long o = overflow();
        if (o > lastOverflow) {
            long hour = Math.floorDiv(e.at().toEpochMilli(), HOUR_MILLIS);
            if (hour != stateFullHour) {
                stateFullHour = hour;
                emit(new Alert("al-" + STATE_FULL + "-" + e.sequence(), STATE_FULL, Severity.HIGH, e.at(),
                        List.of(DETECTION), List.of(e.sequence()), o - lastOverflow,
                        "detection state full: " + (o - lastOverflow) + " new entities not tracked (possible evasion flood)"));
            }
            lastOverflow = o;
        }
    }

    private void hit(Rules.Hit h) {
        String key = h.rule + "|" + h.key;
        Open o = open.get(key);
        if (o != null) {
            deduplicated++;
            o.repeatCount++;
            o.lastAt = h.at;
            long seq = h.evidence.getLast();
            if (o.repeats.size() < Alert.MAX_EVIDENCE) {
                o.repeats.add(seq);
            }
            return;
        }
        if (!withinRate(h)) {
            return;
        }
        Alert a = new Alert("al-" + h.rule + "-" + h.evidence.getLast(), h.rule, h.severity, h.at, h.entities,
                cap(h.evidence), 1, h.summary);
        emit(a);
        if (open.size() < settings.maxOpenWindows()) {
            open.put(key, new Open(h, h.at.toEpochMilli() + settings.dedupWindow().toMillis()));
        }
    }

    private boolean withinRate(Rules.Hit h) {
        long hour = Math.floorDiv(h.at.toEpochMilli(), HOUR_MILLIS);
        long[] c = perRuleHour.computeIfAbsent(h.rule, k -> new long[]{hour, 0});
        if (c[0] != hour) {
            c[0] = hour;
            c[1] = 0;
        }
        c[1]++;
        boolean critical = h.severity == Severity.CRITICAL;
        int cap = critical ? settings.maxCriticalPerRulePerHour() : settings.maxAlertsPerRulePerHour();
        if (c[1] <= cap) {
            return true;
        }
        throttled++;
        if (c[1] == cap + 1L) {
            long seq = h.evidence.getLast();
            emit(new Alert("al-" + ALERT_FLOOD + "-" + h.rule + "-" + seq, ALERT_FLOOD,
                    critical ? Severity.CRITICAL : Severity.HIGH, h.at,
                    List.of(new Entity(Entity.Kind.RESOURCE, "rule:" + h.rule)), List.of(seq), 1,
                    "rule " + h.rule + " raised more than " + cap
                            + " alerts this hour; further alerts are counted, not raised (possible flood)"));
        }
        return false;
    }

    private void closeWindows(long now) {
        Iterator<Open> it = open.values().iterator();
        while (it.hasNext()) {
            Open o = it.next();
            if (o.closesAt > now) {
                break;
            }
            rollUp(o);
            it.remove();
        }
    }

    private void rollUp(Open o) {
        if (o.repeatCount == 0) {
            return;
        }
        Rules.Hit h = o.first;
        emit(new Alert("al-" + h.rule + "-" + o.firstSeq + "-x" + o.repeatCount, h.rule, h.severity, o.lastAt,
                h.entities, o.repeats, o.repeatCount, o.repeatCount + " more within the window: " + h.summary));
    }

    // ---- the trail itself ----------------------------------------------------------------------------

    private void stop(String rule, String why) {
        if (stopped != null) {
            return;
        }
        stopped = why;
        long next = cursor.checkpoint().sequence() + 1;
        emit(new Alert("al-" + rule + "-" + next, rule, Severity.CRITICAL, lastTime, List.of(TRAIL), List.of(next), 1,
                (rule.equals(CHAIN_BREAK) ? "audit trail broken; detection stopped: " : "audit trail disagrees with its anchor; detection stopped: ")
                        + why));
    }

    // ---- output --------------------------------------------------------------------------------------

    private void emit(Alert a) {
        if (!waiting.isEmpty() || !offer(a)) {
            if (waiting.size() >= maxWaiting) {
                lost++;
                return;
            }
            waiting.addLast(a);
        }
    }

    private boolean offer(Alert a) {
        boolean ok;
        try {
            ok = sink.raise(a);
        } catch (RuntimeException e) {
            ok = false;
        }
        if (ok) {
            raised++;
        } else {
            refusedBySink++;
        }
        return ok;
    }

    /** @return whether nothing is waiting any more */
    private boolean retryWaiting() {
        while (!waiting.isEmpty()) {
            if (!offer(waiting.peekFirst())) {
                return false;
            }
            waiting.pollFirst();
        }
        return true;
    }

    private Report report(int read, long raisedBefore) {
        return new Report(read, (int) (raised - raisedBefore), waiting.size(), Optional.ofNullable(stopped));
    }

    private static List<Long> cap(List<Long> evidence) {
        return evidence.size() <= Alert.MAX_EVIDENCE ? evidence : evidence.subList(evidence.size() - Alert.MAX_EVIDENCE,
                evidence.size());
    }

    private long overflow() {
        long o = 0;
        for (Rules.Rule r : rules) {
            o += r.overflow();
        }
        return o;
    }

    private int ruleState() {
        int n = 0;
        for (Rules.Rule r : rules) {
            n += r.stateSize();
        }
        return n;
    }
}

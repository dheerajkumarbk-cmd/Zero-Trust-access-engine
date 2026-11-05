package dev.dwarpal.ueba;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

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
import dev.dwarpal.soc.Techniques;

/**
 * The UEBA detectors: per-entity baselines over the one stream of {@link SecurityEvent}s read from the audit
 * chain, explainable anomalies, and alerts when an entity's anomalies add up.
 *
 * <p>Each event is first <b>judged</b> against what was learned before it, then put in <b>quarantine</b>; it is
 * learned only after {@link UebaSettings#quarantine()} of audit time and only if nothing flagged it in the
 * meantime (an anomaly of this engine, or an alert of any rule reported through {@link #alerted}). An attacker
 * therefore cannot teach the baseline with the very events that are under suspicion.
 *
 * <p>Anomalies go to the {@code anomalies} consumer (normally {@link UebaRisk#add}); the anomalies of one entity
 * within {@link UebaSettings#correlationWindow()} are summed (the strongest per group) and raise one
 * {@code ueba-anomaly} alert each time the sum reaches a higher severity.
 */
public final class UebaEngine {

    public static final String RULE = "ueba-anomaly";
    public static final int MAX_ALERT_MEMORY = 100_000;
    public static final int MAX_WINDOW_ANOMALIES = 256;
    public static final int MAX_POLL = 100_000;

    /** Counters for the SOC's own health view. */
    public record Stats(long events, long malformed, long anomalies, long alerts, long refusedAlerts,
                        long refusedProfiles, long evictedProfiles, long quarantineDropped, long lateEvents,
                        int profiles, Optional<String> chainProblem) {
    }

    private record Pending(ChainedEvent event, List<Entity> entities) {
    }

    /** The anomalies of one entity inside the correlation window, and the level already alerted. */
    private static final class Window {
        final ArrayDeque<Anomaly> anomalies = new ArrayDeque<>();
        Severity raised;
        Instant raisedAt;
    }

    /** What a UEBA alert stood for, for techniques and for learning after a signed false positive. */
    record AlertMemory(Entity entity, List<Anomaly> anomalies, List<Technique> techniques) {
    }

    private final Object lock = new Object();
    private final UebaSettings settings;
    private final PeerGroups peers;
    private final EvidenceIndex index;
    private final Consumer<Anomaly> anomalies;
    private final AlertSink alerts;
    private final Baselines baselines;
    private final ArrayDeque<Pending> quarantine = new ArrayDeque<>();
    private final Set<Long> flagged = new HashSet<>();
    private final Map<Entity, Window> windows = new HashMap<>();
    private final Baselines.Lru<String, AlertMemory> alertMemory = new Baselines.Lru<>(MAX_ALERT_MEMORY);
    private Instant latestRecorded = Instant.EPOCH;
    private long events;
    private long malformed;
    private long anomalyCount;
    private long alertCount;
    private long refusedAlerts;
    private long quarantineDropped;
    private long lateEvents;
    private String chainProblem;

    public UebaEngine(UebaSettings settings, PeerGroups peers, EvidenceIndex index, Consumer<Anomaly> anomalies,
                      AlertSink alerts) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.peers = Objects.requireNonNull(peers, "peers");
        this.index = Objects.requireNonNull(index, "index");
        this.anomalies = Objects.requireNonNull(anomalies, "anomalies");
        this.alerts = Objects.requireNonNull(alerts, "alerts");
        this.baselines = new Baselines(settings);
    }

    /**
     * Reads up to {@code max} records from a keyed cursor and observes them. Records that do not convert are
     * counted as malformed, never guessed; once the chain breaks the engine stops reading from it for good.
     *
     * @return the number of records read
     */
    public int poll(AuditCursor cursor, int max) {
        Objects.requireNonNull(cursor, "cursor");
        if (max < 1 || max > MAX_POLL) {
            throw new IllegalArgumentException("max 1 to " + MAX_POLL);
        }
        synchronized (lock) {
            if (chainProblem != null) {
                return 0;
            }
        }
        AuditCursor.Batch b = cursor.next(max);
        for (AuditEvent a : b.events()) {
            ChainedEvent ce;
            try {
                ce = SecurityEvents.fromAudit(a);
            } catch (IllegalArgumentException e) {
                synchronized (lock) {
                    malformed++;
                }
                continue;
            }
            observe(ce);
        }
        b.problem().ifPresent(p -> {
            synchronized (lock) {
                chainProblem = p;
            }
        });
        return b.events().size();
    }

    /** Judges one event, quarantines it for learning, and returns the anomalies it caused. */
    public List<Anomaly> observe(ChainedEvent ce) {
        Objects.requireNonNull(ce, "event");
        List<Anomaly> found = new ArrayList<>();
        List<Alert> raised = new ArrayList<>();
        synchronized (lock) {
            events++;
            SecurityEvent e = ce.event();
            index.put(ce.sequence(), e.provenance());
            List<Entity> ents = new ArrayList<>();
            for (Entity en : e.entities()) {
                if (settings.baselined().contains(en.kind())) {
                    ents.add(en);
                }
            }
            for (Entity en : ents) {
                Optional<Baselines.Profile> p = baselines.profile(en);
                if (p.isEmpty()) {
                    continue;
                }
                judge(p.get(), ce, found);
            }
            if (!found.isEmpty()) {
                flagged.add(ce.sequence());
            }
            if (ce.recordedAt().isAfter(latestRecorded)) {
                latestRecorded = ce.recordedAt();
            }
            quarantine.addLast(new Pending(ce, List.copyOf(ents)));
            while (quarantine.size() > settings.maxQuarantine()) {
                Pending dropped = quarantine.removeFirst();
                flagged.remove(dropped.event().sequence());
                quarantineDropped++;
            }
            release();
            anomalyCount += found.size();
            for (Anomaly a : found) {
                correlate(a, raised);
            }
        }
        // Outside the lock: the consumers may take their own locks.
        found.forEach(anomalies);
        for (Alert a : raised) {
            boolean ok = alerts.raise(a);
            synchronized (lock) {
                if (ok) {
                    alertCount++;
                } else {
                    refusedAlerts++;
                }
            }
        }
        return List.copyOf(found);
    }

    /** An alert of any rule: its evidence still in quarantine will not be learned. */
    public void alerted(Alert alert) {
        Objects.requireNonNull(alert, "alert");
        synchronized (lock) {
            Set<Long> waiting = new HashSet<>();
            for (Pending p : quarantine) {
                waiting.add(p.event().sequence());
            }
            for (long s : alert.evidence()) {
                if (waiting.contains(s)) {
                    flagged.add(s);
                }
            }
        }
    }

    /** The techniques a UEBA alert points to (empty for other alerts or forgotten ones). */
    public List<Technique> techniques(String alertId) {
        synchronized (lock) {
            AlertMemory m = alertMemory.get(alertId);
            return m == null ? List.of() : m.techniques();
        }
    }

    /** The anomalies behind a UEBA alert (empty for other alerts or forgotten ones). */
    public List<Anomaly> anomaliesOf(String alertId) {
        synchronized (lock) {
            AlertMemory m = alertMemory.get(alertId);
            return m == null ? List.of() : m.anomalies();
        }
    }

    /**
     * After a signed false-positive verdict on a UEBA alert (checked by {@link Ueba#falsePositive}): the values it
     * flagged become known for its entity, so the same legitimate behaviour is not flagged again.
     */
    void learnFalsePositive(String alertId) {
        synchronized (lock) {
            AlertMemory m = alertMemory.remove(alertId);
            if (m == null) {
                return;
            }
            Optional<Baselines.Profile> p = baselines.existing(m.entity());
            if (p.isEmpty()) {
                return;
            }
            for (Anomaly a : m.anomalies()) {
                if (a.detector() == Anomaly.Detector.FIRST_SEEN) {
                    String[] fv = a.group().substring("new:".length()).split(":", 2);
                    if (fv.length == 2 && learnedValues.containsKey(a.group() + "@" + a.entity())) {
                        learn(p.get(), fv[0], learnedValues.remove(a.group() + "@" + a.entity()));
                    }
                }
            }
        }
    }

    public Stats stats() {
        synchronized (lock) {
            return new Stats(events, malformed, anomalyCount, alertCount, refusedAlerts, baselines.refusedProfiles,
                    baselines.evictedProfiles(), quarantineDropped, lateEvents, baselines.size(),
                    Optional.ofNullable(chainProblem));
        }
    }

    public UebaSettings settings() {
        return settings;
    }

    // ---- judging ---------------------------------------------------------------------------------------------

    /** Raw values behind first-seen anomalies (group@entity -> value), for learning after a false positive. */
    private final Baselines.Lru<String, String> learnedValues = new Baselines.Lru<>(MAX_ALERT_MEMORY);

    private static long hour(Instant t) {
        return Math.floorDiv(t.getEpochSecond(), 3600);
    }

    private void judge(Baselines.Profile p, ChainedEvent ce, List<Anomaly> out) {
        SecurityEvent e = ce.event();
        boolean actionable = e.provenance().actionable();
        long seq = ce.sequence();
        // Volume and bytes of this action in this hour.
        Baselines.Volume v = baselines.volume(p, e.action());
        if (v != null) {
            long h = hour(e.at());
            if (h > v.scoreHour) {
                v.scoreHour = h;
                v.scoreCount = 0;
                v.scoreBytes = 0;
                v.volumeFired = false;
                v.bytesFired = false;
            }
            if (h == v.scoreHour) {
                v.scoreCount++;
                v.scoreBytes += bytes(e);
                volume(p, e, v, seq, actionable, out);
            } else {
                lateEvents++;
            }
        }
        // First-time values: the action itself, then the configured fields.
        novelty(p, "action", e.action(), e, seq, actionable, out);
        for (String f : settings.noveltyFields()) {
            Optional<String> val = e.field(f);
            if (val.isPresent() && !val.get().isEmpty()) {
                novelty(p, f, val.get(), e, seq, actionable, out);
            }
        }
        // Machine-regular connections to a destination the entity does not know.
        Optional<String> dst = e.field("dst");
        if (dst.isPresent() && !dst.get().isEmpty()) {
            beacon(p, e, dst.get(), seq, actionable, out);
        }
        // Time of day.
        Baselines.TimeOfDay t = p.time;
        long h = hour(e.at());
        if (t.filled >= settings.timeMinSamples() && t.firedHour != h) {
            int minute = minuteOfDay(e.at());
            double l = t.logLikelihoodRatio(minute, settings.kappa());
            if (l >= settings.timeThreshold()) {
                t.firedHour = h;
                out.add(new Anomaly(p.entity, Anomaly.Detector.TIME_OF_DAY, "time", cap(l), e.at(), List.of(seq),
                        actionable, Techniques.VALID_ACCOUNTS, String.format(Locale.ROOT,
                        "activity at %02d:%02d UTC, unusual for %s (M6 over %d events: l=%.2f)",
                        minute / 60, minute % 60, p.entity.id(), t.filled, l)));
            }
        }
    }

    private static long bytes(SecurityEvent e) {
        Optional<String> b = e.field("bytes");
        if (b.isEmpty()) {
            return 0;
        }
        try {
            long n = Long.parseLong(b.get());
            return n < 0 ? 0 : Math.min(n, 1L << 40);
        } catch (NumberFormatException ex) {
            return 0;
        }
    }

    private static int minuteOfDay(Instant t) {
        return t.atOffset(ZoneOffset.UTC).getHour() * 60 + t.atOffset(ZoneOffset.UTC).getMinute();
    }

    private double cap(double l) {
        return Math.min(l, settings.maxDetectorWeight());
    }

    private void volume(Baselines.Profile p, SecurityEvent e, Baselines.Volume v, long seq, boolean actionable,
                        List<Anomaly> out) {
        if (v.filled < 3) {
            return;
        }
        String group = "burst:" + e.action();
        double lambda = Math.max(v.meanCount(), settings.minRate());
        int k = v.scoreCount;
        double z = (k - lambda) / Math.sqrt(lambda);
        if (!v.volumeFired && k >= settings.minCount() && z >= settings.volumeZ()) {
            double f = settings.attackRateFactor();
            // Poisson likelihood ratio of k events under f*lambda against lambda (section 8.8), clamped at 0.
            double l = Math.max(0, k * Math.log(f) - (f - 1) * lambda);
            if (l > 0) {
                v.volumeFired = true;
                v.flaggedHours.add(v.scoreHour);
                out.add(new Anomaly(p.entity, Anomaly.Detector.VOLUME, group, cap(l), e.at(), List.of(seq), actionable,
                        technique(e.action()), String.format(Locale.ROOT,
                        "%d x %s in one hour, usual %.2f per active hour over %d hours (z=%.1f, Poisson l=%.1f)",
                        k, e.action(), lambda, v.filled, z, l)));
            }
        }
        double usual = Math.max(v.meanBytes(), 1);
        double ratio = v.scoreBytes / usual;
        if (!v.bytesFired && v.scoreBytes >= settings.minBytes() && ratio >= settings.bytesRatio()) {
            v.bytesFired = true;
            v.flaggedHours.add(v.scoreHour);
            out.add(new Anomaly(p.entity, Anomaly.Detector.DATA_VOLUME, group, cap(Math.log(ratio)), e.at(),
                    List.of(seq), actionable, technique(e.action()), String.format(Locale.ROOT,
                    "%d MB of %s in one hour, usual %.1f MB per active hour (ratio %.0f, l=ln ratio)",
                    v.scoreBytes / 1_000_000, e.action(), usual / 1_000_000, ratio)));
        }
    }

    private void beacon(Baselines.Profile p, SecurityEvent e, String dst, long seq, boolean actionable,
                        List<Anomaly> out) {
        String key = e.dataset() + "|" + dst;
        java.util.ArrayDeque<Long> times = p.connections.get(key);
        if (times == null) {
            times = new java.util.ArrayDeque<>();
            p.connections.put(key, times);
        }
        long t = e.at().getEpochSecond();
        if (!times.isEmpty() && t < times.peekLast()) {
            return;
        }
        times.addLast(t);
        while (times.size() > Baselines.BEACON_TIMES) {
            times.removeFirst();
        }
        int intervals = times.size() - 1;
        long h = hour(e.at());
        if (intervals < settings.beaconMinIntervals() || p.beaconFired.getOrDefault(key, Long.MIN_VALUE) == h
                || baselines.novelty(p, "dst").knows(dst)) {
            return;
        }
        double sum = 0;
        double sq = 0;
        Long prev = null;
        for (long x : times) {
            if (prev != null) {
                double d = x - prev;
                sum += d;
                sq += d * d;
            }
            prev = x;
        }
        double mean = sum / intervals;
        double sd = Math.sqrt(Math.max(0, sq / intervals - mean * mean));
        if (mean < 1 || mean > 3600) {
            return;
        }
        double cv = sd / mean;
        if (cv > settings.beaconMaxCv()) {
            return;
        }
        if (p.beaconFired.size() >= Baselines.MAX_DESTINATIONS) {
            p.beaconFired.clear();
        }
        p.beaconFired.put(key, h);
        out.add(new Anomaly(p.entity, Anomaly.Detector.BEACON, "beacon:" + groupValue(dst), cap(settings.beaconWeight()),
                e.at(), List.of(seq), actionable, Techniques.APPLICATION_LAYER_PROTOCOL, String.format(Locale.ROOT,
                "%d connections to new destination %s every %.0f s (sd %.1f s, CV %.3f <= %.2f)", times.size(),
                shortValue(dst), mean, sd, cv, settings.beaconMaxCv())));
    }

    private void novelty(Baselines.Profile p, String field, String value, SecurityEvent e, long seq,
                         boolean actionable, List<Anomaly> out) {
        Baselines.Novelty n = baselines.novelty(p, field);
        if (n.observations < settings.minHistory() || n.knows(value)) {
            return;
        }
        int k = n.newCount();
        int w = n.filled;
        double pLegit = (k + 1.0) / (w + 2.0);
        double l = Math.log(settings.pNewAttack() / pLegit);
        StringBuilder why = new StringBuilder(String.format(Locale.ROOT,
                "first %s %s for %s; %d new in last %d (P=(k+1)/(w+2)=%.3f, l=%.2f)",
                field, shortValue(value), p.entity.id(), k, w, pLegit, l));
        Optional<String> g = peers.group(p.entity);
        if (g.isPresent() && peers.size(g.get()) >= settings.peerMinSize()) {
            int knowing = baselines.peersKnowing(g.get(), p.entity.kind(), field, value);
            double fraction = (double) knowing / peers.size(g.get());
            if (fraction < settings.peerRareFraction()) {
                l += settings.peerBonus();
                why.append(String.format(Locale.ROOT, "; rare in %s (%d of %d) +%.2f", g.get(), knowing,
                        peers.size(g.get()), settings.peerBonus()));
            } else if (fraction >= 0.5) {
                l *= 0.5;
                why.append(String.format(Locale.ROOT, "; common in %s (%d of %d) x0.5", g.get(), knowing,
                        peers.size(g.get())));
            }
        }
        if (l < settings.minNovelty()) {
            return;
        }
        String group = "new:" + field + ":" + groupValue(value);
        learnedValues.put(group + "@" + p.entity, value);
        out.add(new Anomaly(p.entity, Anomaly.Detector.FIRST_SEEN, group, cap(l), e.at(), List.of(seq), actionable,
                field.equals("action") ? technique(value) : techniqueOfValue(field, value), why.toString()));
    }

    /** A short, id-safe stand-in for a value inside a group id (values can contain anything). */
    private static String groupValue(String value) {
        return Integer.toHexString(value.hashCode());
    }

    private static String shortValue(String v) {
        return v.length() > 40 ? v.substring(0, 40) + "..." : v;
    }

    /** The technique an unusual action points to (an explainable, fixed table). */
    static Technique technique(String action) {
        if (action.startsWith("usb.")) {
            return Techniques.EXFIL_OVER_USB;
        }
        if (action.equals("share.create") || action.startsWith("file.download") || action.startsWith("file.upload")) {
            return Techniques.EXFIL_TO_CLOUD_STORAGE;
        }
        if (action.startsWith("file.read")) {
            return Techniques.DATA_FROM_NETWORK_SHARE;
        }
        if (action.startsWith("network.")) {
            return Techniques.APPLICATION_LAYER_PROTOCOL;
        }
        if (action.startsWith("process.")) {
            return Techniques.OBFUSCATED_FILES;
        }
        return Techniques.VALID_ACCOUNTS;
    }

    static Technique techniqueOfValue(String field, String value) {
        String v = value.toLowerCase(Locale.ROOT);
        if ((field.equals("process") || field.equals("parent")) && v.contains("powershell")) {
            return Techniques.POWERSHELL;
        }
        if (field.equals("process") && (v.startsWith("7z") || v.contains("rar") || v.contains("zip"))) {
            return Techniques.ARCHIVE_COLLECTED_DATA;
        }
        if (field.equals("dst") || field.equals("dport")) {
            return Techniques.APPLICATION_LAYER_PROTOCOL;
        }
        if (field.equals("share")) {
            return Techniques.EXFIL_TO_CLOUD_STORAGE;
        }
        if (field.equals("vendor")) {
            return Techniques.EXFIL_OVER_USB;
        }
        if (field.equals("country")) {
            return Techniques.VALID_ACCOUNTS;
        }
        return Techniques.OBFUSCATED_FILES;
    }

    // ---- learning --------------------------------------------------------------------------------------------

    private void release() {
        while (!quarantine.isEmpty()) {
            Pending p = quarantine.peekFirst();
            if (p.event().recordedAt().plus(settings.quarantine()).isAfter(latestRecorded)) {
                return;
            }
            quarantine.removeFirst();
            boolean bad = flagged.remove(p.event().sequence());
            if (!bad) {
                learnEvent(p);
            }
        }
    }

    /** Releases everything still in quarantine (end of a replay, tests). */
    public void flush() {
        synchronized (lock) {
            latestRecorded = Instant.MAX;
            release();
            latestRecorded = Instant.EPOCH;
        }
    }

    private void learnEvent(Pending pending) {
        SecurityEvent e = pending.event().event();
        for (Entity en : pending.entities()) {
            Optional<Baselines.Profile> op = baselines.existing(en);
            if (op.isEmpty()) {
                continue;
            }
            Baselines.Profile p = op.get();
            Baselines.Volume v = baselines.volume(p, e.action());
            long h = hour(e.at());
            if (v != null && !v.flaggedHours.contains(h)) {
                if (h > v.learnHour) {
                    if (v.learnHour != Long.MIN_VALUE) {
                        v.push(v.learnCount, v.learnBytes);
                    }
                    v.learnHour = h;
                    v.learnCount = 0;
                    v.learnBytes = 0;
                }
                if (h == v.learnHour) {
                    v.learnCount++;
                    v.learnBytes += bytes(e);
                }
            }
            learn(p, "action", e.action());
            for (String f : settings.noveltyFields()) {
                e.field(f).filter(s -> !s.isEmpty()).ifPresent(val -> learn(p, f, val));
            }
            p.time.learn(minuteOfDay(e.at()));
        }
    }

    private void learn(Baselines.Profile p, String field, String value) {
        baselines.novelty(p, field).learn(value);
        peers.group(p.entity).ifPresent(g -> baselines.peerLearn(g, p.entity, field, value));
    }

    // ---- correlation into alerts -----------------------------------------------------------------------------

    private void correlate(Anomaly a, List<Alert> raised) {
        Window w = windows.computeIfAbsent(a.entity(), x -> new Window());
        Instant from = a.at().minus(settings.correlationWindow());
        while (!w.anomalies.isEmpty() && w.anomalies.peekFirst().at().isBefore(from)) {
            w.anomalies.removeFirst();
        }
        if (w.raisedAt != null && w.raisedAt.isBefore(from)) {
            w.raised = null;
            w.raisedAt = null;
        }
        w.anomalies.addLast(a);
        while (w.anomalies.size() > MAX_WINDOW_ANOMALIES) {
            w.anomalies.removeFirst();
        }
        Map<String, Anomaly> strongest = new LinkedHashMap<>();
        for (Anomaly x : w.anomalies) {
            strongest.merge(x.group(), x, (o, n) -> n.weight() > o.weight() ? n : o);
        }
        double sum = strongest.values().stream().mapToDouble(Anomaly::weight).sum();
        Severity s = sum >= settings.alertCritical() ? Severity.CRITICAL : sum >= settings.alertHigh() ? Severity.HIGH
                : sum >= settings.alertMedium() ? Severity.MEDIUM : null;
        if (s == null || (w.raised != null && s.compareTo(w.raised) <= 0)) {
            return;
        }
        Instant newest = a.at();
        for (Anomaly x : w.anomalies) {
            if (x.at().isAfter(newest)) {
                newest = x.at();
            }
        }
        w.raised = s;
        w.raisedAt = newest;
        Set<Long> evidence = new LinkedHashSet<>();
        Set<Technique> techniques = new LinkedHashSet<>();
        List<Anomaly> parts = new ArrayList<>(strongest.values());
        parts.sort((x, y) -> Double.compare(y.weight(), x.weight()));
        for (Anomaly x : parts) {
            for (long q : x.evidence()) {
                if (evidence.size() < Alert.MAX_EVIDENCE) {
                    evidence.add(q);
                }
            }
            if (x.technique() != null && techniques.size() < 8) {
                techniques.add(x.technique());
            }
        }
        String id = "al-" + RULE + "-" + (alertCount + refusedAlerts + raised.size() + 1) + "-" + a.at().getEpochSecond();
        Alert alert = new Alert(id, RULE, s, newest, List.of(a.entity()), List.copyOf(evidence), parts.size(),
                String.format(Locale.ROOT, "UEBA: %d anomalies for %s %s within %d min, sum l=%.1f (strongest: %s)",
                        parts.size(), a.entity().kind().name().toLowerCase(Locale.ROOT), a.entity().id(),
                        settings.correlationWindow().toMinutes(), sum, parts.get(0).detector()));
        alertMemory.put(id, new AlertMemory(a.entity(), List.copyOf(parts), List.copyOf(techniques)));
        raised.add(alert);
    }
}

package dev.dwarpal.siem.platform;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.soc.EventSource;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.SecurityEvents;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Moves normalised events from collectors into the audit chain, as {@code SECURITY_EVENT} records written under
 * {@code collector:<dataset>} before anything else reads them. From then on they are tamper-evident and alerts
 * cite them by audit sequence number.
 *
 * <p>Checks, each counted per source and reason, and reported into the chain by one {@code ingest.refused}
 * summary event per source and pump (never dropped silently):
 * <ul>
 *   <li><b>One source, one dataset, one trust level.</b> A source may only write its own dataset, and no
 *       higher provenance than it was registered with: an unauthenticated source can never produce
 *       {@code SIGNED_SENSOR} events, and nothing can produce {@code VERIFIED_AUDIT}.</li>
 *   <li><b>Event time.</b> More than {@link Settings#maxFuture} ahead of the ingestion time is refused (a
 *       future-dated event would push every rule's clock forward and close open windows). More than
 *       {@link Settings#maxPast} behind is refused (backdating into windows long closed). Behind by more than
 *       {@link Settings#lateAfter} is written but flagged {@code ingest.late} with the lag.</li>
 *   <li><b>Fair share.</b> Each source has a token bucket ({@code perMinute}, {@code burst}); one pump takes
 *       sources in turn, so a flooding source fills its own bounded queue (and its overflow is counted) but
 *       cannot use the others' share.</li>
 *   <li><b>Fail closed.</b> If the audit write fails, the event is kept for the next pump and nothing more is
 *       read: the chain never skips an event that was taken from a source.</li>
 * </ul>
 */
public final class Ingestor {

    /** Time checks; defaults: 5 minutes ahead, 7 days behind, flagged when 1 hour late. */
    public record Settings(Duration maxFuture, Duration maxPast, Duration lateAfter) {
        public Settings {
            Objects.requireNonNull(maxFuture, "maxFuture");
            Objects.requireNonNull(maxPast, "maxPast");
            Objects.requireNonNull(lateAfter, "lateAfter");
            if (maxFuture.isNegative() || maxFuture.compareTo(Duration.ofHours(1)) > 0) {
                throw new IllegalArgumentException("maxFuture: 0 to 1 hour");
            }
            if (lateAfter.isNegative() || lateAfter.compareTo(maxPast) >= 0
                    || maxPast.compareTo(Duration.ofDays(30)) > 0) {
                throw new IllegalArgumentException("lateAfter must be below maxPast, maxPast at most 30 days");
            }
        }

        public static Settings defaults() {
            return new Settings(Duration.ofMinutes(5), Duration.ofDays(7), Duration.ofHours(1));
        }
    }

    /**
     * A source and what it may write.
     *
     * @param maxProvenance the most trusted provenance its events may carry ({@code COLLECTED} for syslog and
     *                      exports, {@code SIGNED_SENSOR} for a collector that verifies signatures)
     * @param perMinute     events per minute it may write on average, 1 to 1,000,000
     * @param burst         events it may write at once, 1 to 1,000,000
     */
    public record Registration(EventSource source, SecurityEvent.Provenance maxProvenance, int perMinute, int burst) {
        public Registration {
            Objects.requireNonNull(source, "source");
            Objects.requireNonNull(maxProvenance, "maxProvenance");
            if (maxProvenance == SecurityEvent.Provenance.VERIFIED_AUDIT) {
                throw new IllegalArgumentException("no collector may write VERIFIED_AUDIT events");
            }
            if (perMinute < 1 || perMinute > 1_000_000 || burst < 1 || burst > 1_000_000) {
                throw new IllegalArgumentException("perMinute and burst: 1 to 1,000,000");
            }
        }
    }

    /** What one pump did. */
    public record Report(int written, int late, Map<String, Long> refused, Optional<String> problem) {
        public Report {
            refused = Map.copyOf(refused);
            Objects.requireNonNull(problem, "problem");
        }
    }

    public static final int MAX_SOURCES = 32;
    public static final int MAX_PER_PUMP = 10_000;
    public static final String REFUSED_ACTION = "ingest.refused";

    private final AuditLog audit;
    private final Settings settings;
    private final List<Lane> lanes = new ArrayList<>();
    private long written;

    public Ingestor(AuditLog audit, List<Registration> sources, Settings settings) {
        this.audit = Objects.requireNonNull(audit, "audit");
        this.settings = Objects.requireNonNull(settings, "settings");
        if (sources.isEmpty() || sources.size() > MAX_SOURCES) {
            throw new IllegalArgumentException("1 to " + MAX_SOURCES + " sources");
        }
        for (Registration r : sources) {
            String dataset = SecurityEvents.collectorActor(r.source().name()).substring(
                    SecurityEvents.COLLECTOR_PREFIX.length());
            if (dataset.equals(SecurityEvents.NATIVE_DATASET)) {
                throw new IllegalArgumentException("no collector may use the native dataset");
            }
            for (Lane l : lanes) {
                if (l.reg.source().name().equals(dataset)) {
                    throw new IllegalArgumentException("two sources for dataset " + dataset);
                }
            }
            lanes.add(new Lane(r));
        }
    }

    /** The datasets this ingestor writes (for rule lint: a rule on any other dataset can never fire). */
    public List<String> datasets() {
        return lanes.stream().map(l -> l.reg.source().name()).toList();
    }

    /** Records written in total. */
    public synchronized long written() {
        return written;
    }

    /** Refusals so far, by source and reason. */
    public synchronized Map<String, Map<String, Long>> refusals() {
        Map<String, Map<String, Long>> out = new LinkedHashMap<>();
        for (Lane l : lanes) {
            out.put(l.reg.source().name(), Map.copyOf(l.refusedTotal));
        }
        return out;
    }

    /**
     * Writes up to {@code max} events (at most {@link #MAX_PER_PUMP}) from the sources, taking them in turn
     * within each one's quota.
     *
     * @param now ingestion time: the audit record time, and what event times are checked against
     */
    public synchronized Report pump(Instant now, int max) {
        Objects.requireNonNull(now, "now");
        if (max < 1) {
            throw new IllegalArgumentException("max must be positive");
        }
        int budget = Math.min(max, MAX_PER_PUMP);
        int done = 0;
        int late = 0;
        Map<String, Long> refused = new TreeMap<>();
        for (Lane l : lanes) {
            l.refill(now);
        }
        Optional<String> problem = Optional.empty();
        boolean progress = true;
        outer:
        while (done < budget && progress) {
            progress = false;
            int share = Math.max(1, (budget - done) / lanes.size());
            for (Lane l : lanes) {
                int take = (int) Math.min(Math.min(share, budget - done), l.tokens);
                if (take < 1) {
                    continue;
                }
                List<SecurityEvent> batch = l.take(take);
                for (int i = 0; i < batch.size(); i++) {
                    SecurityEvent e = batch.get(i);
                    Check c = check(l, e, now);
                    if (c.reason != null) {
                        l.refuse(c.reason);
                        refused.merge(l.reg.source().name() + ":" + c.reason, 1L, Long::sum);
                        l.tokens--;
                        progress = true;
                        continue;
                    }
                    try {
                        audit.append(SecurityEvents.RECORD_TYPE, SecurityEvents.collectorActor(e.dataset()), now,
                                SecurityEvents.toAuditFields(c.event));
                    } catch (RuntimeException failed) {
                        l.putBack(batch.subList(i, batch.size()));
                        problem = Optional.of("audit write failed (" + failed.getClass().getSimpleName()
                                + "): ingestion stopped, events kept");
                        break outer;
                    }
                    written++;
                    done++;
                    l.tokens--;
                    progress = true;
                    if (c.late) {
                        late++;
                    }
                }
            }
        }
        if (problem.isEmpty()) {
            for (Lane l : lanes) {
                Optional<String> p = l.reportRefusals(now);
                if (p.isPresent()) {
                    problem = p;
                    break;
                }
            }
        }
        return new Report(done, late, refused, problem);
    }

    private record Check(SecurityEvent event, String reason, boolean late) {
    }

    private Check check(Lane l, SecurityEvent e, Instant now) {
        if (!e.dataset().equals(l.reg.source().name())) {
            return new Check(e, "wrong-dataset", false);
        }
        if (e.provenance().compareTo(l.reg.maxProvenance()) < 0) {
            return new Check(e, "provenance-above-source", false);
        }
        for (String f : e.fields().keySet()) {
            if (f.startsWith("ingest.")) {
                return new Check(e, "reserved-field", false);
            }
        }
        if (e.at().isAfter(now.plus(settings.maxFuture()))) {
            return new Check(e, "future-time", false);
        }
        if (e.at().isBefore(now.minus(settings.maxPast()))) {
            return new Check(e, "too-old", false);
        }
        if (e.at().isBefore(now.minus(settings.lateAfter()))) {
            if (e.fields().size() + 2 > SecurityEvent.MAX_FIELDS) {
                return new Check(e, "too-many-fields", false);
            }
            Map<String, String> f = new LinkedHashMap<>(e.fields());
            f.put("ingest.late", "true");
            f.put("ingest.lagSeconds", Long.toString(Duration.between(e.at(), now).toSeconds()));
            return new Check(new SecurityEvent(e.id(), e.at(), e.dataset(), e.category(), e.action(), e.outcome(),
                    e.provenance(), e.entities(), f), null, true);
        }
        return new Check(e, null, false);
    }

    /** One source with its quota, its events taken but not yet written, and its refusals to report. */
    private final class Lane {
        private final Registration reg;
        private final ArrayDeque<SecurityEvent> held = new ArrayDeque<>();
        private final Map<String, Long> refusedTotal = new TreeMap<>();
        private final Map<String, Long> unreported = new TreeMap<>();
        private double tokens;
        private Instant refilled;

        Lane(Registration reg) {
            this.reg = reg;
            this.tokens = reg.burst();
        }

        void refill(Instant now) {
            if (refilled != null && now.isAfter(refilled)) {
                double minutes = Duration.between(refilled, now).toMillis() / 60_000.0;
                tokens = Math.min(reg.burst(), tokens + minutes * reg.perMinute());
            }
            if (refilled == null || now.isAfter(refilled)) {
                refilled = now;
            }
        }

        List<SecurityEvent> take(int n) {
            List<SecurityEvent> out = new ArrayList<>(n);
            while (out.size() < n && !held.isEmpty()) {
                out.add(held.poll());
            }
            if (out.size() < n) {
                out.addAll(reg.source().poll(n - out.size()));
            }
            return out.size() > n ? out.subList(0, n) : out;
        }

        void putBack(List<SecurityEvent> events) {
            for (int i = events.size() - 1; i >= 0; i--) {
                held.addFirst(events.get(i));
            }
        }

        void refuse(String reason) {
            refusedTotal.merge(reason, 1L, Long::sum);
            unreported.merge(reason, 1L, Long::sum);
        }

        /** Writes one summary of this pump's refusals into the chain, with counts only (no refused content). */
        Optional<String> reportRefusals(Instant now) {
            if (unreported.isEmpty()) {
                return Optional.empty();
            }
            Map<String, String> f = new LinkedHashMap<>();
            unreported.forEach((reason, n) -> f.put("refused." + reason.replace('-', '_'), Long.toString(n)));
            SecurityEvent summary = new SecurityEvent("ingest-" + reg.source().name() + "-" + (written + 1) + "-"
                    + now.toEpochMilli(), now, reg.source().name(), SecurityEvent.Category.SYSTEM, REFUSED_ACTION,
                    SecurityEvent.EventOutcome.FAILURE, SecurityEvent.Provenance.COLLECTED, List.of(), f);
            try {
                audit.append(SecurityEvents.RECORD_TYPE, SecurityEvents.collectorActor(reg.source().name()), now,
                        SecurityEvents.toAuditFields(summary));
            } catch (RuntimeException failed) {
                return Optional.of("audit write failed (" + failed.getClass().getSimpleName()
                        + "): refusal summary kept for the next pump");
            }
            written++;
            unreported.clear();
            return Optional.empty();
        }
    }
}

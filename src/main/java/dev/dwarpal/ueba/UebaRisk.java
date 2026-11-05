package dev.dwarpal.ueba;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import dev.dwarpal.domain.Validate;
import dev.dwarpal.response.VerdictGate;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertSink;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EntityRisk;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Verdict;

/**
 * One risk score per entity (implements {@link EntityRisk}), built from alerts, UEBA anomalies and watches.
 *
 * <p><b>The arithmetic</b>, all of it checkable by hand:
 * <ol>
 *   <li>Every contribution has a weight w₀ in log-odds and a half-life T (M5): {@code w(t) = w₀ · 0.5^(age/T)}.
 *       Contributions dated after {@code now} do not count yet (replays give the same answer).</li>
 *   <li>Contributions of one <i>group</i> are one piece of evidence: only the strongest counts (the event count
 *       and the bytes of one burst are not two independent facts; ten copies of one alert are not ten).</li>
 *   <li>Each group is capped at ln 1000 (the attack cap of M3).</li>
 *   <li>Groups backed only by {@code COLLECTED} events together count for at most {@link Settings#collectedCap}
 *       (ln 1000, a score of at most 50, MEDIUM), scaled down proportionally: forged syslog lines alone cannot make
 *       anyone high risk.</li>
 *   <li>Σ of the counted weights goes through Bayes with the base rate (M3):
 *       {@code p = σ(logit(prior) + Σ)}, shown as {@code score = 100 · (p − prior) / (1 − prior)}, so nothing
 *       known is exactly 0 and Σ = ln 1000 with prior 0.001 is about 50.</li>
 * </ol>
 * Risk goes down only by time (the decay) or by a signed false-positive verdict through
 * {@link #falsePositive}; nothing an entity does can lower it, because no input subtracts.
 *
 * <p>UEBA alerts ({@link UebaEngine#RULE}) are not added again when raised: their anomalies are already here.
 */
public final class UebaRisk implements EntityRisk, AlertSink {

    /** Weight and half-life of one kind of contribution. */
    public record Weight(double logOdds, Duration halfLife) {
        public Weight {
            Validate.finite(logOdds, "logOdds");
            if (logOdds <= 0) {
                throw new IllegalArgumentException("weights add risk");
            }
            Objects.requireNonNull(halfLife, "halfLife");
            if (halfLife.isNegative() || halfLife.isZero() || halfLife.compareTo(Duration.ofDays(365)) > 0) {
                throw new IllegalArgumentException("half-life above 0, at most a year");
            }
        }
    }

    /**
     * @param prior           base rate P(attack) of M3
     * @param groupCap        cap per group in log-odds (ln 1000)
     * @param collectedCap    cap on the total of groups backed only by collected events (ln 1000)
     * @param anomalyHalfLife half-life of UEBA anomalies
     * @param severity        weight of an alert by severity
     * @param maxEntities     entities remembered; when full the lowest-risk entity makes room
     * @param maxPerEntity    contributions per entity; when full the weakest (now) makes room
     */
    public record Settings(double prior, double groupCap, double collectedCap, Duration anomalyHalfLife,
                           Map<Severity, Weight> severity, int maxEntities, int maxPerEntity) {
        public Settings {
            Validate.probability(prior, "prior");
            if (prior <= 0 || prior >= 1) {
                throw new IllegalArgumentException("prior strictly between 0 and 1");
            }
            if (!(groupCap > 0) || !(collectedCap > 0) || !Double.isFinite(groupCap) || !Double.isFinite(collectedCap)) {
                throw new IllegalArgumentException("caps must be positive");
            }
            new Weight(1, anomalyHalfLife);
            severity = Map.copyOf(severity);
            if (severity.size() != Severity.values().length) {
                throw new IllegalArgumentException("a weight for every severity");
            }
            if (maxEntities < 1 || maxEntities > 10_000_000 || maxPerEntity < 1 || maxPerEntity > 10_000) {
                throw new IllegalArgumentException("maxEntities 1 to 10,000,000, maxPerEntity 1 to 10,000");
            }
        }

        /** Reference values (assumptions, see docs/layer-5-2/part-e.md). */
        public static Settings reference() {
            Map<Severity, Weight> w = new EnumMap<>(Severity.class);
            w.put(Severity.LOW, new Weight(Math.log(3), Duration.ofDays(1)));
            w.put(Severity.MEDIUM, new Weight(Math.log(10), Duration.ofDays(3)));
            w.put(Severity.HIGH, new Weight(Math.log(100), Duration.ofDays(7)));
            w.put(Severity.CRITICAL, new Weight(Math.log(1000), Duration.ofDays(14)));
            return new Settings(0.001, Math.log(1000), Math.log(1000), Duration.ofDays(1), w, 100_000, 256);
        }
    }

    private record Raw(String source, String group, double weight, Duration halfLife, Instant at, List<Long> evidence,
                       boolean actionable, String alertId, String reason) {
        double now(Instant t) {
            double age = Duration.between(at, t).toMillis();
            return weight * Math.pow(0.5, age / halfLife.toMillis());
        }
    }

    private static final double FORGET = 1e-3;

    private final Object lock = new Object();
    private final Settings settings;
    private final EvidenceIndex index;
    private final Map<Entity, List<Raw>> entities = new HashMap<>();
    private long dropped;

    public UebaRisk(Settings settings, EvidenceIndex index) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.index = Objects.requireNonNull(index, "index");
    }

    /** Adds a UEBA anomaly (the engine's consumer). */
    public void add(Anomaly a) {
        Objects.requireNonNull(a, "anomaly");
        put(a.entity(), new Raw(a.source(), a.group(), a.weight(), settings.anomalyHalfLife(), a.at(), a.evidence(),
                a.actionable(), null, a.reason()));
    }

    /** Adds an alert of any rule except UEBA's own: every entity it names gets the severity's weight. */
    @Override
    public boolean raise(Alert alert) {
        Objects.requireNonNull(alert, "alert");
        if (alert.rule().equals(UebaEngine.RULE)) {
            return true;
        }
        Weight w = settings.severity().get(alert.severity());
        boolean actionable = index.anyActionable(alert.evidence());
        for (Entity e : alert.entities()) {
            put(e, new Raw("alert:" + alert.rule(), "alert:" + alert.rule(), w.logOdds(), w.halfLife(), alert.raisedAt(),
                    alert.evidence(), actionable, alert.id(), alert.severity() + " alert " + alert.id() + ": "
                    + alert.summary()));
        }
        return true;
    }

    /** A watch (for example from a playbook): its own weight and half-life. */
    public void watch(Entity entity, String source, Weight weight, Instant at, List<Long> evidence, String reason) {
        Objects.requireNonNull(entity, "entity");
        Validate.id(source, "source");
        Objects.requireNonNull(weight, "weight");
        Objects.requireNonNull(at, "at");
        put(entity, new Raw(source, source, weight.logOdds(), weight.halfLife(), at, List.copyOf(evidence),
                index.anyActionable(evidence), null, reason));
    }

    /**
     * Removes what an alert added, if the verdict is a false positive that the gate admits (signed by a SOC analyst,
     * fresh, used once). The only way besides time to lower anyone's risk.
     *
     * @return whether the verdict counted
     */
    public boolean falsePositive(Verdict verdict, VerdictGate gate) {
        Objects.requireNonNull(verdict, "verdict");
        Objects.requireNonNull(gate, "gate");
        if (verdict.outcome() != Verdict.Outcome.FALSE_POSITIVE || gate.admit(verdict).isPresent()) {
            return false;
        }
        removeAlert(verdict.alertId(), List.of());
        return true;
    }

    /** Removes an alert's contributions and the given anomalies (after a verdict was admitted). */
    void removeAlert(String alertId, List<Anomaly> anomalies) {
        synchronized (lock) {
            for (List<Raw> l : entities.values()) {
                l.removeIf(r -> alertId.equals(r.alertId()));
            }
            for (Anomaly a : anomalies) {
                List<Raw> l = entities.get(a.entity());
                if (l != null) {
                    l.removeIf(r -> r.group().equals(a.group()) && r.at().equals(a.at())
                            && r.evidence().equals(a.evidence()));
                }
            }
            entities.values().removeIf(List::isEmpty);
        }
    }

    @Override
    public RiskView view(Entity entity, Instant now) {
        Objects.requireNonNull(entity, "entity");
        Objects.requireNonNull(now, "now");
        synchronized (lock) {
            List<Raw> l = entities.get(entity);
            return l == null ? RiskView.none(entity, now) : compute(entity, l, now);
        }
    }

    /** Every contribution of an entity now, not cut at {@link RiskView#MAX_CONTRIBUTIONS}. */
    public List<Contribution> contributions(Entity entity, Instant now) {
        synchronized (lock) {
            List<Raw> l = entities.get(entity);
            return l == null ? List.of() : counted(l, now);
        }
    }

    @Override
    public List<RiskView> top(int n, Instant now) {
        if (n < 1 || n > MAX_TOP) {
            throw new IllegalArgumentException("n is 1 to " + MAX_TOP);
        }
        Objects.requireNonNull(now, "now");
        List<RiskView> all = new ArrayList<>();
        synchronized (lock) {
            for (Map.Entry<Entity, List<Raw>> e : entities.entrySet()) {
                RiskView v = compute(e.getKey(), e.getValue(), now);
                if (v.score() > 0) {
                    all.add(v);
                }
            }
        }
        all.sort(Comparator.comparingDouble(RiskView::score).reversed()
                .thenComparing(v -> v.entity().kind()).thenComparing(v -> v.entity().id()));
        return List.copyOf(all.subList(0, Math.min(n, all.size())));
    }

    public long dropped() {
        synchronized (lock) {
            return dropped;
        }
    }

    public int size() {
        synchronized (lock) {
            return entities.size();
        }
    }

    // ---- internals -------------------------------------------------------------------------------------------

    private void put(Entity e, Raw r) {
        synchronized (lock) {
            List<Raw> l = entities.get(e);
            if (l == null) {
                if (entities.size() >= settings.maxEntities() && !makeRoom(r.at())) {
                    dropped++;
                    return;
                }
                l = new ArrayList<>();
                entities.put(e, l);
            }
            Instant t = r.at();
            l.removeIf(x -> x.now(t) < FORGET && !x.at().isAfter(t));
            if (l.size() >= settings.maxPerEntity()) {
                Raw weakest = l.stream().min(Comparator.comparingDouble(x -> x.now(t))).orElseThrow();
                if (weakest.now(t) >= r.weight()) {
                    dropped++;
                    return;
                }
                l.remove(weakest);
                dropped++;
            }
            l.add(r);
        }
    }

    /** Drops the entity with the lowest risk at {@code t}, if any; never one riskier than nothing. */
    private boolean makeRoom(Instant t) {
        Entity lowest = null;
        double low = Double.POSITIVE_INFINITY;
        for (Map.Entry<Entity, List<Raw>> e : entities.entrySet()) {
            double s = e.getValue().stream().mapToDouble(x -> x.now(t)).sum();
            if (s < low) {
                low = s;
                lowest = e.getKey();
            }
        }
        if (lowest == null) {
            return false;
        }
        entities.remove(lowest);
        dropped++;
        return true;
    }

    /** One merged contribution per group, with its counted weight, largest first. */
    private List<Contribution> counted(List<Raw> raws, Instant now) {
        Map<String, List<Raw>> groups = new LinkedHashMap<>();
        for (Raw r : raws) {
            if (!r.at().isAfter(now)) {
                groups.computeIfAbsent(r.group(), g -> new ArrayList<>()).add(r);
            }
        }
        record Merged(Raw strongest, double weight, int n, boolean actionable, Set<Long> evidence) {
        }
        List<Merged> merged = new ArrayList<>();
        for (List<Raw> g : groups.values()) {
            Raw best = g.get(0);
            boolean actionable = false;
            Set<Long> ev = new LinkedHashSet<>();
            for (Raw r : g) {
                if (r.now(now) > best.now(now)) {
                    best = r;
                }
                actionable |= r.actionable();
            }
            for (long s : best.evidence()) {
                ev.add(s);
            }
            for (Raw r : g) {
                for (long s : r.evidence()) {
                    if (ev.size() < Alert.MAX_EVIDENCE) {
                        ev.add(s);
                    }
                }
            }
            double w = Math.min(best.now(now), settings.groupCap());
            if (w >= FORGET) {
                merged.add(new Merged(best, w, g.size(), actionable, ev));
            }
        }
        // Groups backed only by collected events count together for at most collectedCap, scaled proportionally
        // (as M3 scales reassurance), so forged syslog alone cannot make anyone high risk (E-R2).
        double collected = merged.stream().filter(m -> !m.actionable()).mapToDouble(Merged::weight).sum();
        double scale = collected > settings.collectedCap() ? settings.collectedCap() / collected : 1;
        List<Contribution> out = new ArrayList<>();
        for (Merged m : merged) {
            String reason = m.strongest().reason() + (m.n() > 1 ? " (x" + m.n() + ")" : "");
            double w = m.weight();
            if (!m.actionable() && scale < 1) {
                w *= scale;
                reason = String.format(Locale.ROOT, "%s [collected only, x%.2f]", reason, scale);
            }
            out.add(new Contribution(m.strongest().source(), w, m.strongest().at(), List.copyOf(m.evidence()), reason));
        }
        out.sort(Comparator.comparingDouble(Contribution::weight).reversed().thenComparing(Contribution::source));
        return out;
    }

    private RiskView compute(Entity entity, List<Raw> raws, Instant now) {
        List<Contribution> all = counted(raws, now);
        double sum = all.stream().mapToDouble(Contribution::weight).sum();
        double prior = settings.prior();
        double z = Math.log(prior / (1 - prior)) + sum;
        double p = 1 / (1 + Math.exp(-z));
        double score = Math.max(0, Math.min(100, 100 * (p - prior) / (1 - prior)));
        if (sum <= 0) {
            score = 0;
        }
        List<Contribution> shown = all;
        if (all.size() > RiskView.MAX_CONTRIBUTIONS) {
            shown = new ArrayList<>(all.subList(0, RiskView.MAX_CONTRIBUTIONS - 1));
            List<Contribution> rest = all.subList(RiskView.MAX_CONTRIBUTIONS - 1, all.size());
            double w = rest.stream().mapToDouble(Contribution::weight).sum();
            Instant latest = rest.stream().map(Contribution::at).max(Instant::compareTo).orElse(now);
            shown.add(new Contribution("ueba:other", w, latest, List.of(), String.format(Locale.ROOT,
                    "%d smaller contributions, together %.2f", rest.size(), w)));
        }
        return new RiskView(entity, score, Level.of(score), now, shown);
    }
}

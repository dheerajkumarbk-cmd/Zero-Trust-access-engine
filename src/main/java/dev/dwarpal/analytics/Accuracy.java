package dev.dwarpal.analytics;

import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Outcome;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalDouble;
import java.util.TreeMap;

/**
 * Accuracy of the engine on labelled traffic: confusion table, detection and false-alarm rates, ROC curve
 * and its area, and expected cost (M2), overall and per scenario.
 *
 * <p><b>Operating point.</b> A request is <em>flagged</em> when the engine challenged or blocked it
 * (STEP_UP or DENY); ALLOW and ALLOW_LIMITED let the requester in and count as not flagged. The stricter
 * point "blocked" (DENY only) is reported too.
 *
 * <p><b>Cost per request</b>, with the engine's own costs: a legitimate request costs 0 when let in,
 * C_F when challenged and C_D when blocked; an attack costs C_B when let in (ALLOW_LIMITED too: a
 * read-only attacker still reads), beta C_B when challenged and 0 when blocked.
 *
 * <p>A rate whose denominator is empty is undefined and reported as "n/a", never as 0 (finding C7: a
 * run with no legitimate traffic must not read as "0% false alarms").
 */
public final class Accuracy {

    public static final int MAX_OBSERVATIONS = 1_000_000;
    public static final int MAX_ROC_POINTS_REPORTED = 21;

    /** Counts at one operating point; positives are attacks. */
    public record Confusion(long truePositives, long falseNegatives, long falsePositives, long trueNegatives) {
        public OptionalDouble detectionRate() {
            return ratio(truePositives, truePositives + falseNegatives);
        }

        public OptionalDouble falseAlarmRate() {
            return ratio(falsePositives, falsePositives + trueNegatives);
        }

        public OptionalDouble precision() {
            return ratio(truePositives, truePositives + falsePositives);
        }
    }

    /** One point of the ROC curve: flag everything scoring at least {@code threshold}. */
    public record RocPoint(double threshold, double falseAlarmRate, double detectionRate) {
    }

    public record ScenarioStats(String scenario, boolean attack, long count, Map<Outcome, Long> outcomes,
                                double meanCost) {
        public ScenarioStats {
            outcomes = Map.copyOf(outcomes);
        }

        /** For an attack scenario the detection rate, for a legitimate one the false-alarm rate. */
        public double flaggedRate() {
            long flagged = outcomes.getOrDefault(Outcome.STEP_UP, 0L) + outcomes.getOrDefault(Outcome.DENY, 0L);
            return (double) flagged / count;
        }
    }

    private final long n;
    private final Confusion flagged;
    private final Confusion blocked;
    private final List<RocPoint> roc;
    private final OptionalDouble auc;
    private final double meanCost;
    private final List<ScenarioStats> scenarios;
    private final CostModel costs;

    private Accuracy(long n, Confusion flagged, Confusion blocked, List<RocPoint> roc, OptionalDouble auc,
                     double meanCost, List<ScenarioStats> scenarios, CostModel costs) {
        this.n = n;
        this.flagged = flagged;
        this.blocked = blocked;
        this.roc = List.copyOf(roc);
        this.auc = auc;
        this.meanCost = meanCost;
        this.scenarios = List.copyOf(scenarios);
        this.costs = costs;
    }

    public static Accuracy of(List<Observation> data, CostModel costs) {
        Objects.requireNonNull(data, "data");
        Objects.requireNonNull(costs, "costs");
        if (data.isEmpty()) {
            throw new IllegalArgumentException("no observations: accuracy is undefined");
        }
        if (data.size() > MAX_OBSERVATIONS) {
            throw new IllegalArgumentException("at most " + MAX_OBSERVATIONS + " observations");
        }
        long[] f = new long[4];
        long[] b = new long[4];
        double totalCost = 0;
        Map<String, List<Observation>> byScenario = new TreeMap<>();
        for (Observation o : Objects.requireNonNull(data, "data")) {
            Objects.requireNonNull(o, "observation");
            count(f, o.attack(), o.outcome() == Outcome.STEP_UP || o.outcome() == Outcome.DENY);
            count(b, o.attack(), o.outcome() == Outcome.DENY);
            totalCost += cost(o, costs);
            byScenario.computeIfAbsent(o.scenario(), k -> new ArrayList<>()).add(o);
        }
        List<ScenarioStats> per = new ArrayList<>();
        for (Map.Entry<String, List<Observation>> e : byScenario.entrySet()) {
            Map<Outcome, Long> oc = new EnumMap<>(Outcome.class);
            double c = 0;
            boolean attack = false;
            for (Observation o : e.getValue()) {
                oc.merge(o.outcome(), 1L, Long::sum);
                c += cost(o, costs);
                attack |= o.attack();
            }
            per.add(new ScenarioStats(e.getKey(), attack, e.getValue().size(), oc, c / e.getValue().size()));
        }
        List<RocPoint> roc = roc(data);
        return new Accuracy(data.size(), confusion(f), confusion(b), roc, auc(data),
                totalCost / data.size(), per, costs);
    }

    private static void count(long[] c, boolean attack, boolean positive) {
        // index: 0 TP, 1 FN, 2 FP, 3 TN
        c[attack ? (positive ? 0 : 1) : (positive ? 2 : 3)]++;
    }

    private static Confusion confusion(long[] c) {
        return new Confusion(c[0], c[1], c[2], c[3]);
    }

    static double cost(Observation o, CostModel m) {
        if (o.attack()) {
            return switch (o.outcome()) {
                case ALLOW, ALLOW_LIMITED -> m.breachCost();
                case STEP_UP -> m.stepUpBypassProbability() * m.breachCost();
                case DENY -> 0;
            };
        }
        return switch (o.outcome()) {
            case ALLOW, ALLOW_LIMITED -> 0;
            case STEP_UP -> m.frictionCost();
            case DENY -> m.wrongDenyCost();
        };
    }

    /** The full ROC curve over the distinct scores, from (0, 0) to (1, 1). Empty if a class is missing. */
    static List<RocPoint> roc(List<Observation> data) {
        long pos = data.stream().filter(Observation::attack).count();
        long neg = data.size() - pos;
        if (pos == 0 || neg == 0) {
            return List.of();
        }
        List<Observation> sorted = new ArrayList<>(data);
        sorted.sort(Comparator.comparingDouble(Observation::score).reversed());
        List<RocPoint> out = new ArrayList<>();
        out.add(new RocPoint(Double.POSITIVE_INFINITY, 0, 0));
        long tp = 0;
        long fp = 0;
        int i = 0;
        while (i < sorted.size()) {
            double s = sorted.get(i).score();
            while (i < sorted.size() && sorted.get(i).score() == s) {
                if (sorted.get(i).attack()) {
                    tp++;
                } else {
                    fp++;
                }
                i++;
            }
            out.add(new RocPoint(s, (double) fp / neg, (double) tp / pos));
        }
        return out;
    }

    /**
     * Area under the ROC curve, as the Mann-Whitney statistic: the probability that a random attack scores
     * higher than a random legitimate request, ties counting one half. Equal to the trapezoid area.
     */
    static OptionalDouble auc(List<Observation> data) {
        List<RocPoint> r = roc(data);
        if (r.isEmpty()) {
            return OptionalDouble.empty();
        }
        double area = 0;
        for (int i = 1; i < r.size(); i++) {
            area += (r.get(i).falseAlarmRate() - r.get(i - 1).falseAlarmRate())
                    * (r.get(i).detectionRate() + r.get(i - 1).detectionRate()) / 2;
        }
        return OptionalDouble.of(area);
    }

    static OptionalDouble ratio(long num, long den) {
        return den == 0 ? OptionalDouble.empty() : OptionalDouble.of((double) num / den);
    }

    public long observations() {
        return n;
    }

    public Confusion flagged() {
        return flagged;
    }

    public Confusion blocked() {
        return blocked;
    }

    public List<RocPoint> roc() {
        return roc;
    }

    public OptionalDouble auc() {
        return auc;
    }

    public double meanCost() {
        return meanCost;
    }

    public List<ScenarioStats> scenarios() {
        return scenarios;
    }

    public Report report(DataSource source) {
        Report.Builder b = Report.builder("Accuracy on labelled traffic", source.withRequests(n));
        b.section("Costs used").number("C_B breach", costs.breachCost()).number("C_F friction", costs.frictionCost())
                .number("C_D wrong deny", costs.wrongDenyCost()).number("beta", costs.stepUpBypassProbability());
        confusion(b, "Flagged (STEP_UP or DENY)", flagged);
        confusion(b, "Blocked (DENY)", blocked);
        b.section("ROC (score = outcome, then P(attack))").rate("area under curve", auc);
        int step = Math.max(1, (roc.size() + MAX_ROC_POINTS_REPORTED - 1) / MAX_ROC_POINTS_REPORTED);
        java.util.SortedSet<Integer> shown = new java.util.TreeSet<>();
        for (int i = 0; i < roc.size(); i += step) {
            shown.add(i);
        }
        if (!roc.isEmpty()) {
            shown.add(roc.size() - 1);   // always end at (1, 1)
        }
        for (int i : shown) {
            RocPoint p = roc.get(i);
            b.text("point " + i, String.format(java.util.Locale.ROOT, "false alarms %.4f, detection %.4f",
                    p.falseAlarmRate(), p.detectionRate()));
        }
        b.section("Expected cost").number("mean cost per request", meanCost);
        b.section("Per scenario");
        for (ScenarioStats s : scenarios) {
            b.text(s.scenario(), String.format(java.util.Locale.ROOT, "%s n=%d %s=%.4f mean cost=%.4f outcomes=%s",
                    s.attack() ? "attack" : "legitimate", s.count(), s.attack() ? "detected" : "false alarms",
                    s.flaggedRate(), s.meanCost(), new TreeMap<>(s.outcomes())));
        }
        return b.build();
    }

    private static void confusion(Report.Builder b, String name, Confusion c) {
        b.section(name).count("true positives (attack flagged)", c.truePositives())
                .count("false negatives (attack let in)", c.falseNegatives())
                .count("false positives (legitimate flagged)", c.falsePositives())
                .count("true negatives (legitimate let in)", c.trueNegatives())
                .rate("detection rate", c.detectionRate()).rate("false-alarm rate", c.falseAlarmRate())
                .rate("precision", c.precision());
    }
}

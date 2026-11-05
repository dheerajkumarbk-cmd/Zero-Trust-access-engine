package dev.dwarpal.analytics;

import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.Validate;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalDouble;

/**
 * How the cost-optimal action (M2) and step-up resolution (M3 with M9's beta) move when the MFA beta
 * values and the three costs change.
 *
 * <p>Closed forms (project state 8.2): STEP_UP beats ALLOW above p1 = C_F / (C_F + C_B (1 - beta)), DENY
 * beats STEP_UP above p2 = (C_D - C_F) / ((C_D - C_F) + beta C_B). Solved for beta at a fixed p:
 * STEP_UP stops beating ALLOW when beta > 1 - C_F (1 - p) / (p C_B), and DENY starts beating STEP_UP when
 * beta > (C_D - C_F)(1 - p) / (p C_B).
 *
 * <p>Sweeps re-decide each observed posterior with the swept model and count how many cost-optimal actions
 * change. This is the risk layer only: hard gates and policy floors (which do not depend on costs) are
 * left as they were, and the report says so.
 */
public final class Sensitivity {

    public static final int MAX_GRID = 1_000;
    public static final int MAX_POSTERIORS = 1_000_000;

    /** Thresholds for one beta. */
    public record Thresholds(double beta, double stepUpAbove, double denyAbove) {
    }

    /** Counts of cost-optimal actions at one point of a sweep, and how many differ from the base model. */
    public record Point(String parameter, double value, Map<Outcome, Long> actions, long changed,
                        double stepUpAbove, double denyAbove) {
        public Point {
            actions = Map.copyOf(actions);
        }
    }

    /** For one MFA beta: of the STEP_UP requests, how many a passed challenge resolves to ALLOW. */
    public record MfaPoint(double beta, long stepUps, long resolvedToAllow, long stillStepUp, long denied) {
    }

    private Sensitivity() {
    }

    public static Thresholds thresholds(CostModel base, double beta) {
        CostModel m = withBeta(base, beta);
        return new Thresholds(beta, m.stepUpOverAllowThreshold(), m.denyOverStepUpThreshold());
    }

    /** The beta above which STEP_UP no longer beats ALLOW at posterior p (empty if it always or never does). */
    public static OptionalDouble betaWhereStepUpLosesToAllow(CostModel m, double p) {
        Validate.probability(p, "p");
        if (p == 0) {
            return OptionalDouble.empty();
        }
        double b = 1 - m.frictionCost() * (1 - p) / (p * m.breachCost());
        return b > 0 && b < 1 ? OptionalDouble.of(b) : OptionalDouble.empty();
    }

    /** The beta above which DENY beats STEP_UP at posterior p (empty if it always or never does). */
    public static OptionalDouble betaWhereDenyBeatsStepUp(CostModel m, double p) {
        Validate.probability(p, "p");
        double net = m.wrongDenyCost() - m.frictionCost();
        if (p == 0 || net <= 0) {
            return OptionalDouble.empty();
        }
        double b = net * (1 - p) / (p * m.breachCost());
        return b > 0 && b < 1 ? OptionalDouble.of(b) : OptionalDouble.empty();
    }

    /** Sweeps beta over {@code betas} for the given posteriors. */
    public static List<Point> sweepBeta(CostModel base, List<Double> posteriors, double[] betas) {
        check(posteriors, betas);
        List<Point> out = new ArrayList<>();
        for (double beta : betas) {
            out.add(point("beta", beta, base, withBeta(base, beta), posteriors));
        }
        return out;
    }

    /** Which cost to scale in {@link #sweepCost}. */
    public enum Cost { BREACH, FRICTION, WRONG_DENY }

    /** Scales one cost by each of {@code multipliers}, keeping the others. */
    public static List<Point> sweepCost(CostModel base, Cost which, List<Double> posteriors, double[] multipliers) {
        Objects.requireNonNull(which, "which");
        check(posteriors, multipliers);
        List<Point> out = new ArrayList<>();
        for (double k : multipliers) {
            Validate.positive(k, "multiplier");
            CostModel m = switch (which) {
                case BREACH -> new CostModel(base.breachCost() * k, base.frictionCost(), base.wrongDenyCost(),
                        base.stepUpBypassProbability());
                case FRICTION -> new CostModel(base.breachCost(), base.frictionCost() * k, base.wrongDenyCost(),
                        base.stepUpBypassProbability());
                case WRONG_DENY -> new CostModel(base.breachCost(), base.frictionCost(), base.wrongDenyCost() * k,
                        base.stepUpBypassProbability());
            };
            out.add(point(which.name().toLowerCase(Locale.ROOT) + " x", k, base, m, posteriors));
        }
        return out;
    }

    /**
     * For each MFA beta, what a passed challenge does to the requests that were STEP_UP under the base
     * model: P(attack | passed) = p beta / (p beta + 1 - p), then the base model decides again.
     */
    public static List<MfaPoint> sweepMfa(CostModel base, List<Double> posteriors, double[] betas) {
        check(posteriors, betas);
        List<MfaPoint> out = new ArrayList<>();
        for (double beta : betas) {
            Validate.probability(beta, "beta");
            long stepUps = 0;
            long allow = 0;
            long still = 0;
            long deny = 0;
            for (double p : posteriors) {
                if (base.bestAction(p) != Outcome.STEP_UP) {
                    continue;
                }
                stepUps++;
                double den = p * beta + 1 - p;
                double after = den == 0 ? 1 : p * beta / den;   // p = 1, beta = 0 is undefined: stay strict
                switch (base.bestAction(after)) {
                    case ALLOW -> allow++;
                    case STEP_UP -> still++;
                    default -> deny++;
                }
            }
            out.add(new MfaPoint(beta, stepUps, allow, still, deny));
        }
        return out;
    }

    private static Point point(String name, double value, CostModel base, CostModel m, List<Double> ps) {
        Map<Outcome, Long> counts = new EnumMap<>(Outcome.class);
        long changed = 0;
        for (double p : ps) {
            Outcome o = m.bestAction(p);
            counts.merge(o, 1L, Long::sum);
            if (o != base.bestAction(p)) {
                changed++;
            }
        }
        return new Point(name, value, counts, changed, m.stepUpOverAllowThreshold(), m.denyOverStepUpThreshold());
    }

    private static CostModel withBeta(CostModel base, double beta) {
        Validate.probability(beta, "beta");
        return new CostModel(base.breachCost(), base.frictionCost(), base.wrongDenyCost(), beta);
    }

    private static void check(List<Double> posteriors, double[] grid) {
        Objects.requireNonNull(posteriors, "posteriors");
        Objects.requireNonNull(grid, "grid");
        if (grid.length == 0 || grid.length > MAX_GRID) {
            throw new IllegalArgumentException("grid must have 1 to " + MAX_GRID + " points");
        }
        if (posteriors.size() > MAX_POSTERIORS) {
            throw new IllegalArgumentException("at most " + MAX_POSTERIORS + " posteriors");
        }
        posteriors.forEach(p -> Validate.probability(Objects.requireNonNull(p, "posterior"), "posterior"));
    }

    public static Report report(DataSource source, CostModel base, List<Thresholds> thresholds,
                                List<List<Point>> sweeps, List<MfaPoint> mfa) {
        Report.Builder b = Report.builder("Sensitivity of the cost model (M2) and MFA strength (M9)", source);
        b.section("Base model").number("C_B", base.breachCost()).number("C_F", base.frictionCost())
                .number("C_D", base.wrongDenyCost()).number("beta", base.stepUpBypassProbability())
                .text("scope", "cost-optimal action only; hard gates and policy floors are unchanged by costs");
        b.section("Thresholds as functions of beta");
        for (Thresholds t : thresholds) {
            b.text("beta " + Report.number(t.beta()), "step up above " + Report.number(t.stepUpAbove())
                    + ", deny above " + (Double.isFinite(t.denyAbove()) ? Report.number(t.denyAbove()) : "always"));
        }
        for (List<Point> sweep : sweeps) {
            if (sweep.isEmpty()) {
                continue;
            }
            b.section("Sweep: " + sweep.get(0).parameter());
            for (Point p : sweep) {
                b.text(p.parameter() + " " + Report.number(p.value()), String.format(Locale.ROOT,
                        "actions %s, changed %d; step up above %.6f, deny above %s", new java.util.TreeMap<>(p.actions()),
                        p.changed(), p.stepUpAbove(), Double.isFinite(p.denyAbove()) ? Report.number(p.denyAbove()) : "always"));
            }
        }
        b.section("Step-up resolution by MFA beta");
        for (MfaPoint m : mfa) {
            b.text("beta " + Report.number(m.beta()), String.format(Locale.ROOT,
                    "of %d step-ups: %d resolve to ALLOW, %d still STEP_UP, %d DENY",
                    m.stepUps(), m.resolvedToAllow(), m.stillStepUp(), m.denied()));
        }
        return b.build();
    }
}

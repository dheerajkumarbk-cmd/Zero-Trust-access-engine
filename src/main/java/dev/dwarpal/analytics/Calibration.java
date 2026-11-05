package dev.dwarpal.analytics;

import dev.dwarpal.domain.Validate;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalDouble;
import java.util.TreeMap;

/**
 * Estimates the probabilities and rates the engine assumes, with Bayesian credible intervals, and says
 * whether the value in use is consistent with the data.
 *
 * <ul>
 *   <li><b>Proportions</b> (for example P(new country | legitimate), P(impossible travel | attack)): k
 *       successes in n trials with a uniform Beta(1, 1) prior give the posterior Beta(1 + k, 1 + n - k);
 *       its mean is Laplace's (k + 1) / (n + 2), the same rule of succession as M1.</li>
 *   <li><b>Poisson rates</b> (M8.8, failures per window): k events over an exposure of t windows with
 *       Jeffreys' prior give Gamma(k + 1/2, rate t).</li>
 *   <li><b>Risk factors</b>: from labelled decisions, how often each factor fired (added risk) among
 *       attacks and among legitimate requests; the ratio of the two is the likelihood ratio the data
 *       supports, compared with the mean ln LR the engine actually used when the factor fired.</li>
 * </ul>
 *
 * Intervals are equal-tailed at the given level (default 95%). "Consistent" means the value in use lies
 * inside the interval; it does not mean the value is right for real traffic.
 */
public final class Calibration {

    public static final double DEFAULT_LEVEL = 0.95;
    public static final int MAX_ESTIMATES = 1_000;

    /** A posterior estimate of one parameter and its comparison with the value in use. */
    public record Estimate(String name, String model, long events, double trials, double mean, double low,
                           double high, OptionalDouble inUse) {
        public Estimate {
            Validate.id(name, "name");
            Objects.requireNonNull(model, "model");
            Objects.requireNonNull(inUse, "inUse");
        }

        /** Empty when there is no value in use to compare with. */
        public java.util.Optional<Boolean> consistent() {
            return inUse.isPresent() ? java.util.Optional.of(inUse.getAsDouble() >= low && inUse.getAsDouble() <= high)
                    : java.util.Optional.empty();
        }
    }

    /** A factor's firing rates and the likelihood ratio they imply, against what the engine used. */
    public record FactorCheck(String factor, Estimate givenAttack, Estimate givenLegit, double impliedLnLr,
                              double impliedLnLrLow, double impliedLnLrHigh, OptionalDouble usedLnLr) {
        public java.util.Optional<Boolean> consistent() {
            return usedLnLr.isPresent()
                    ? java.util.Optional.of(usedLnLr.getAsDouble() >= impliedLnLrLow && usedLnLr.getAsDouble() <= impliedLnLrHigh)
                    : java.util.Optional.empty();
        }
    }

    private Calibration() {
    }

    public static Estimate proportion(String name, long successes, long trials, OptionalDouble inUse) {
        return proportion(name, successes, trials, inUse, DEFAULT_LEVEL);
    }

    public static Estimate proportion(String name, long successes, long trials, OptionalDouble inUse, double level) {
        if (trials < 0 || successes < 0 || successes > trials || trials > 1_000_000_000L) {
            throw new IllegalArgumentException("need 0 <= successes <= trials <= 1e9");
        }
        checkLevel(level);
        inUse.ifPresent(v -> Validate.probability(v, "inUse"));
        double a = 1.0 + successes;
        double b = 1.0 + trials - successes;
        double tail = (1 - level) / 2;
        return new Estimate(name, "Beta(1+k, 1+n-k)", successes, trials, a / (a + b),
                Stats.betaQuantile(tail, a, b), Stats.betaQuantile(1 - tail, a, b), inUse);
    }

    public static Estimate rate(String name, long events, double exposure, OptionalDouble inUse) {
        return rate(name, events, exposure, inUse, DEFAULT_LEVEL);
    }

    /** Events per unit of exposure (for example failures per 15-minute window). */
    public static Estimate rate(String name, long events, double exposure, OptionalDouble inUse, double level) {
        if (events < 0 || events > 1_000_000_000L) {
            throw new IllegalArgumentException("need 0 <= events <= 1e9");
        }
        Validate.positive(exposure, "exposure");
        checkLevel(level);
        inUse.ifPresent(v -> Validate.positive(v, "inUse"));
        double shape = events + 0.5;
        double tail = (1 - level) / 2;
        return new Estimate(name, "Gamma(k+1/2, t)", events, exposure, shape / exposure,
                Stats.gammaQuantile(tail, shape) / exposure, Stats.gammaQuantile(1 - tail, shape) / exposure, inUse);
    }

    /** Base rate of attacks in the data, compared with the engine's prior. */
    public static Estimate baseRate(List<Observation> data, double priorInUse) {
        long attacks = data.stream().filter(Observation::attack).count();
        return proportion("base-rate", attacks, data.size(), OptionalDouble.of(priorInUse));
    }

    /**
     * For each risk factor seen in {@code data}: P(fires | attack), P(fires | legitimate), the ln LR they
     * imply (with a conservative interval from the two intervals' ends), and the mean ln LR the engine
     * used when the factor fired. A factor fires when it added risk (ln LR above zero). Requests a hard gate
     * decided are left out: their factors were never computed.
     */
    public static List<FactorCheck> factors(List<Observation> data) {
        Objects.requireNonNull(data, "data");
        List<Observation> scored = data.stream().filter(o -> !o.gated()).toList();
        long nAttack = scored.stream().filter(Observation::attack).count();
        long nLegit = scored.size() - nAttack;
        Map<String, long[]> fired = new TreeMap<>();     // [attack fired, legit fired]
        Map<String, double[]> used = new TreeMap<>();    // [sum, count]
        for (Observation o : scored) {
            for (Map.Entry<String, Double> f : o.factors().entrySet()) {
                if (f.getValue() > 0) {
                    fired.computeIfAbsent(f.getKey(), k -> new long[2])[o.attack() ? 0 : 1]++;
                    double[] u = used.computeIfAbsent(f.getKey(), k -> new double[2]);
                    u[0] += f.getValue();
                    u[1]++;
                }
            }
            if (fired.size() > MAX_ESTIMATES) {
                throw new IllegalArgumentException("too many distinct factors");
            }
        }
        List<FactorCheck> out = new ArrayList<>();
        if (nAttack == 0 || nLegit == 0) {
            return out;
        }
        for (Map.Entry<String, long[]> e : fired.entrySet()) {
            Estimate att = proportion(e.getKey(), e.getValue()[0], nAttack, OptionalDouble.empty());
            Estimate leg = proportion(e.getKey(), e.getValue()[1], nLegit, OptionalDouble.empty());
            double[] u = used.get(e.getKey());
            out.add(new FactorCheck(e.getKey(), att, leg, Math.log(att.mean() / leg.mean()),
                    Math.log(att.low() / leg.high()), Math.log(att.high() / leg.low()),
                    OptionalDouble.of(u[0] / u[1])));
        }
        return out;
    }

    public static Report report(DataSource source, List<Estimate> estimates, List<FactorCheck> factors) {
        if (estimates.size() + factors.size() > MAX_ESTIMATES) {
            throw new IllegalArgumentException("too many estimates for one report");
        }
        Report.Builder b = Report.builder("Calibration of assumed parameters", source);
        b.section("Parameters (posterior mean [95% interval] vs value in use)");
        for (Estimate e : estimates) {
            b.text(e.name(), String.format(Locale.ROOT, "%.6f [%.6f, %.6f] from %d in %.0f, %s; in use %s -> %s",
                    e.mean(), e.low(), e.high(), e.events(), e.trials(), e.model(),
                    e.inUse().isPresent() ? Report.number(e.inUse().getAsDouble()) : "none",
                    e.consistent().map(c -> c ? "consistent" : "NOT consistent").orElse("no comparison")));
        }
        b.section("Risk factors (fires = adds risk)");
        for (FactorCheck f : factors) {
            b.text(f.factor(), String.format(Locale.ROOT,
                    "P(fire|attack) %.4f [%.4f, %.4f]; P(fire|legit) %.4f [%.4f, %.4f]; implied ln LR %.3f [%.3f, %.3f];"
                            + " used %s -> %s",
                    f.givenAttack().mean(), f.givenAttack().low(), f.givenAttack().high(),
                    f.givenLegit().mean(), f.givenLegit().low(), f.givenLegit().high(),
                    f.impliedLnLr(), f.impliedLnLrLow(), f.impliedLnLrHigh(),
                    f.usedLnLr().isPresent() ? String.format(Locale.ROOT, "%.3f", f.usedLnLr().getAsDouble()) : "none",
                    f.consistent().map(c -> c ? "consistent" : "NOT consistent").orElse("no comparison")));
        }
        if (factors.isEmpty()) {
            b.text("none", "no factor fired, or one class (attack or legitimate) is missing");
        }
        return b.build();
    }

    private static void checkLevel(double level) {
        if (!(level > 0.5 && level < 1)) {
            throw new IllegalArgumentException("level must be in (0.5, 1)");
        }
    }
}

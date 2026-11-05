package dev.dwarpal.analytics;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.OptionalDouble;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CalibrationTest {

    // ---- special functions against known values -----------------------------------------------------------

    @Test
    void logGammaKnownValues() {
        assertEquals(0, Stats.logGamma(1), 1e-12);
        assertEquals(0, Stats.logGamma(2), 1e-12);
        assertEquals(Math.log(24), Stats.logGamma(5), 1e-11);
        assertEquals(0.5 * Math.log(Math.PI), Stats.logGamma(0.5), 1e-11);
        assertEquals(Math.log(Math.sqrt(Math.PI) / 2), Stats.logGamma(1.5), 1e-11);
        assertEquals(1.2880225246980774, Stats.logGamma(0.25), 1e-10);   // ln Gamma(1/4)
        assertThrows(IllegalArgumentException.class, () -> Stats.logGamma(0));
        assertThrows(IllegalArgumentException.class, () -> Stats.logGamma(Double.NaN));
    }

    @Test
    void betaAndGammaCdfKnownValues() {
        assertEquals(0.3, Stats.betaCdf(0.3, 1, 1), 1e-12);                   // uniform
        assertEquals(0.09, Stats.betaCdf(0.3, 2, 1), 1e-12);                  // x^2
        assertEquals(1 - Math.pow(0.7, 3), Stats.betaCdf(0.3, 1, 3), 1e-12);  // 1 - (1-x)^3
        assertEquals(0.5, Stats.betaCdf(0.5, 7.5, 7.5), 1e-12);               // symmetric
        assertEquals(0, Stats.betaCdf(-1, 2, 2));
        assertEquals(1, Stats.betaCdf(2, 2, 2));
        assertEquals(1 - Math.exp(-2), Stats.gammaCdf(2, 1), 1e-12);          // exponential
        assertEquals(1 - Math.exp(-5) * (1 + 5), Stats.gammaCdf(5, 2), 1e-12); // Erlang 2, upper branch
        assertEquals(1 - Math.exp(-0.5) * 1.5, Stats.gammaCdf(0.5, 2), 1e-12);  // series branch
        assertEquals(0, Stats.gammaCdf(0, 3));
        assertThrows(IllegalArgumentException.class, () -> Stats.gammaCdf(1, 0));
        assertThrows(IllegalArgumentException.class, () -> Stats.betaCdf(0.5, 0, 1));
        assertThrows(IllegalArgumentException.class, () -> Stats.betaCdf(0.5, 1, Double.POSITIVE_INFINITY));
    }

    @Test
    void quantilesInvertTheCdf() {
        for (double q : new double[]{0.025, 0.5, 0.975}) {
            assertEquals(q, Stats.betaCdf(Stats.betaQuantile(q, 3, 40), 3, 40), 1e-9);
            assertEquals(q, Stats.gammaCdf(Stats.gammaQuantile(q, 12.5), 12.5), 1e-9);
            assertEquals(q, Stats.gammaCdf(Stats.gammaQuantile(q, 0.5), 0.5), 1e-9);
        }
        assertEquals(-Math.log(0.5), Stats.gammaQuantile(0.5, 1), 1e-9);
        assertThrows(IllegalArgumentException.class, () -> Stats.betaQuantile(0, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> Stats.gammaQuantile(1, 1));
    }

    // ---- estimators recover planted parameters ---------------------------------------------------------------

    @Test
    void proportionRecoversPlantedProbability() {
        Random rnd = new Random(11);
        for (double planted : new double[]{0.02, 0.3, 0.6}) {
            int n = 5_000;
            int k = 0;
            for (int i = 0; i < n; i++) {
                k += rnd.nextDouble() < planted ? 1 : 0;
            }
            Calibration.Estimate e = Calibration.proportion("planted", k, n, OptionalDouble.of(planted));
            assertTrue(e.low() < planted && planted < e.high(), e.toString());
            assertTrue(e.consistent().orElseThrow());
            assertEquals((k + 1.0) / (n + 2.0), e.mean(), 1e-12);          // rule of succession
            assertTrue(e.high() - e.low() < 0.04, "interval narrows with data");
        }
    }

    @Test
    void wrongAssumptionIsCaught() {
        Calibration.Estimate e = Calibration.proportion("p-new-country-legit", 300, 1_000, OptionalDouble.of(0.02));
        assertFalse(e.consistent().orElseThrow());
        Calibration.Estimate none = Calibration.proportion("x", 0, 0, OptionalDouble.empty());
        assertEquals(0.5, none.mean(), 1e-12);    // no data: the uniform prior
        assertTrue(none.consistent().isEmpty());
    }

    @Test
    void rateRecoversPlantedPoissonRate() {
        Random rnd = new Random(5);
        for (double lambda : new double[]{0.2, 5, 20}) {
            int windows = 2_000;
            long events = 0;
            for (int i = 0; i < windows; i++) {
                events += poisson(rnd, lambda);
            }
            Calibration.Estimate e = Calibration.rate("lambda", events, windows, OptionalDouble.of(lambda));
            assertTrue(e.low() < lambda && lambda < e.high(), e.toString());
            assertEquals((events + 0.5) / windows, e.mean(), 1e-12);
        }
        Calibration.Estimate zero = Calibration.rate("zero", 0, 100, OptionalDouble.empty());
        assertTrue(zero.low() >= 0 && zero.high() < 0.05);
    }

    private static int poisson(Random rnd, double lambda) {
        double l = Math.exp(-lambda);
        int k = 0;
        double p = 1;
        do {
            k++;
            p *= rnd.nextDouble();
        } while (p > l);
        return k - 1;
    }

    @Test
    void factorChecksRecoverPlantedLikelihoodRatio() {
        // Plant a factor that fires for 60% of attacks and 2% of legitimate requests: ln LR = ln 30.
        Random rnd = new Random(2);
        List<Observation> data = new ArrayList<>();
        for (int i = 0; i < 20_000; i++) {
            boolean attack = i % 2 == 0;
            boolean fires = rnd.nextDouble() < (attack ? 0.60 : 0.02);
            Map<String, Double> f = fires ? Map.of("planted", Math.log(30)) : Map.of("planted", -0.1);
            data.add(new Observation(attack ? "A" : "L", attack, dev.dwarpal.decision.Outcome.ALLOW, false, 0.01, false, f));
        }
        data.add(new Observation("G", true, dev.dwarpal.decision.Outcome.DENY, false, 0.001, true, Map.of("gated", 5.0)));
        List<Calibration.FactorCheck> checks = Calibration.factors(data);
        assertEquals(1, checks.size(), "gated observations are left out");
        Calibration.FactorCheck c = checks.getFirst();
        assertEquals("planted", c.factor());
        assertTrue(c.impliedLnLrLow() < Math.log(30) && Math.log(30) < c.impliedLnLrHigh(), c.toString());
        assertEquals(Math.log(30), c.usedLnLr().getAsDouble(), 1e-12);
        assertTrue(c.consistent().orElseThrow());
        assertTrue(Calibration.factors(data.subList(0, 1)).isEmpty(), "one class missing: no comparison");
    }

    @Test
    void baseRateAndReport() {
        List<Observation> data = List.of(AnalyticsRedTeamTest.obs("A", true, dev.dwarpal.decision.Outcome.DENY, 0.9),
                AnalyticsRedTeamTest.obs("L", false, dev.dwarpal.decision.Outcome.ALLOW, 0.001));
        Calibration.Estimate b = Calibration.baseRate(data, 0.001);
        assertEquals(0.5, b.mean(), 1e-12);
        Report r = Calibration.report(DataSource.simulated(7, 60, 8, 2), List.of(b), Calibration.factors(data));
        String text = r.text();
        assertTrue(text.contains("base-rate: 0.500000"), text);
        assertTrue(text.contains("NOT consistent"), text);
        assertTrue(text.contains("no factor fired"), text);
        assertThrows(IllegalArgumentException.class, () -> Calibration.report(DataSource.simulated(1, 1, 1, 1),
                java.util.Collections.nCopies(Calibration.MAX_ESTIMATES + 1, b), List.of()));
        assertThrows(IllegalArgumentException.class, () -> Calibration.proportion("p", 1, 2, OptionalDouble.empty(), 0.4));
        assertThrows(IllegalArgumentException.class, () -> Calibration.rate("p", -1, 2, OptionalDouble.empty()));
    }
}

package dev.dwarpal.risk;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BayesianRiskAggregatorTest {

    @Test
    void noEvidenceLeavesThePriorUnchanged() {
        var agg = new BayesianRiskAggregator(0.001, 7);
        RiskAssessment r = agg.aggregate(List.of(), List.of());
        assertEquals(0.001, r.posteriorAttack(), 1e-12);
    }

    /**
     * Axelsson (2000): base rate 1/10,000, detector TPR 0.99, FPR 0.01. An alarm has likelihood
     * ratio 0.99/0.01 = 99, yet P(attack | alarm) is only ~0.98%: 99 of 100 alarms are false.
     */
    @Test
    void reproducesTheBaseRateFallacy() {
        var agg = new BayesianRiskAggregator(1.0 / 10_000, 10);
        double llr = Math.log(0.99 / 0.01);
        RiskAssessment r = agg.aggregate(List.of(new RiskFactor("ids-alarm", llr, "alarm fired")), List.of());
        double exact = (0.0001 * 0.99) / (0.0001 * 0.99 + 0.9999 * 0.01);
        assertEquals(exact, r.posteriorAttack(), 1e-9);
        assertTrue(r.posteriorAttack() < 0.01);
    }

    @Test
    void evidenceAddsInLogSpace() {
        var agg = new BayesianRiskAggregator(0.5, 10);
        RiskAssessment r = agg.aggregate(List.of(
                new RiskFactor("a", Math.log(4), "x4"),
                new RiskFactor("b", Math.log(0.5), "x0.5")), List.of());
        // prior odds 1 * 4 * 0.5 = 2 -> p = 2/3
        assertEquals(2.0 / 3.0, r.posteriorAttack(), 1e-12);
        assertEquals(Math.log(2), r.totalLogLikelihoodRatio(), 1e-12);
    }

    @Test
    void oneFactorCannotDominate() {
        var agg = new BayesianRiskAggregator(0.001, 3);
        RiskAssessment r = agg.aggregate(List.of(new RiskFactor("noisy", 50, "wild")), List.of());
        assertEquals(3, r.totalLogLikelihoodRatio(), 1e-12);
        assertTrue(r.factors().get(0).evidence().endsWith("[capped]"));
    }

    @Test
    void reassuranceIsCappedPerFactorAndInTotalIndependentOfOrder() {
        var agg = new BayesianRiskAggregator(0.001, Math.log(1000), Math.log(10), Math.log(10));
        RiskFactor attack = new RiskFactor("travel", Math.log(1000), "x");
        RiskFactor f1 = new RiskFactor("ua", Math.log(0.001), "x");
        RiskFactor f2 = new RiskFactor("dev", Math.log(0.001), "x");
        RiskAssessment a = agg.aggregate(List.of(attack, f1, f2), List.of());
        RiskAssessment b = agg.aggregate(List.of(f2, attack, f1), List.of());
        // +ln1000 - ln10 (total reassurance cap) = ln100
        assertEquals(Math.log(100), a.totalLogLikelihoodRatio(), 1e-9);
        assertEquals(a.totalLogLikelihoodRatio(), b.totalLogLikelihoodRatio(), 1e-12);
        assertEquals(Math.log(10) / 2, -a.factors().get(1).logLikelihoodRatio(), 1e-9, "scaled proportionally");
    }

    @Test
    void attackEvidenceIsNotScaledByTheReassuranceCap() {
        var agg = new BayesianRiskAggregator(0.5, 5, 1, 1);
        RiskAssessment r = agg.aggregate(List.of(new RiskFactor("a", 4, "x"), new RiskFactor("b", -0.5, "x")), List.of());
        assertEquals(3.5, r.totalLogLikelihoodRatio(), 1e-12);
    }

    @Test
    void recordsFailedScorers() {
        var agg = new BayesianRiskAggregator(0.01, 5);
        RiskAssessment r = agg.aggregate(List.of(), List.of("geoip"));
        assertTrue(r.degraded());
    }

    @Test
    void rejectsDegeneratePriors() {
        assertThrows(IllegalArgumentException.class, () -> new BayesianRiskAggregator(0, 5));
        assertThrows(IllegalArgumentException.class, () -> new BayesianRiskAggregator(1, 5));
        assertThrows(IllegalArgumentException.class, () -> new BayesianRiskAggregator(0.1, 0));
        assertThrows(IllegalArgumentException.class, () -> new RiskFactor("x", Double.NaN, ""));
    }
}

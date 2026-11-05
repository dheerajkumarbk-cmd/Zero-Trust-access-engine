package dev.dwarpal.analytics;

import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Outcome;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static dev.dwarpal.analytics.AnalyticsRedTeamTest.costs;
import static dev.dwarpal.analytics.AnalyticsRedTeamTest.obs;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccuracyTest {

    /** A hand-built table: 4 attacks, 6 legitimate requests, every outcome present. */
    private static List<Observation> table() {
        return List.of(
                obs("A1", true, Outcome.DENY, 0.95),
                obs("A1", true, Outcome.STEP_UP, 0.40),
                obs("A2", true, Outcome.ALLOW, 0.0009),
                obs("A2", true, Outcome.ALLOW_LIMITED, 0.0008),
                obs("L1", false, Outcome.ALLOW, 0.0005),
                obs("L1", false, Outcome.ALLOW, 0.0002),
                obs("L1", false, Outcome.ALLOW, 0.0001),
                obs("L2", false, Outcome.STEP_UP, 0.01),
                obs("L2", false, Outcome.DENY, 0.30),
                obs("L2", false, Outcome.ALLOW_LIMITED, 0.0003));
    }

    @Test
    void confusionTablesAndRates() {
        Accuracy a = Accuracy.of(table(), costs());
        assertEquals(new Accuracy.Confusion(2, 2, 2, 4), a.flagged());
        assertEquals(new Accuracy.Confusion(1, 3, 1, 5), a.blocked());
        assertEquals(0.5, a.flagged().detectionRate().getAsDouble(), 1e-12);
        assertEquals(2.0 / 6, a.flagged().falseAlarmRate().getAsDouble(), 1e-12);
        assertEquals(0.5, a.flagged().precision().getAsDouble(), 1e-12);
        assertEquals(10, a.observations());
    }

    @Test
    void expectedCostFollowsM2() {
        // attacks: 0 + 0.05*1000 + 1000 + 1000; legitimate: 0 + 0 + 0 + 1 + 20 + 0
        Accuracy a = Accuracy.of(table(), costs());
        assertEquals((50 + 1000 + 1000 + 1 + 20) / 10.0, a.meanCost(), 1e-9);
        Accuracy.ScenarioStats a2 = a.scenarios().stream().filter(s -> s.scenario().equals("A2")).findFirst().orElseThrow();
        assertEquals(1000, a2.meanCost(), 1e-9);
        assertEquals(0, a2.flaggedRate(), 1e-12);
        assertTrue(a2.attack());
        Accuracy.ScenarioStats l2 = a.scenarios().stream().filter(s -> s.scenario().equals("L2")).findFirst().orElseThrow();
        assertEquals(2.0 / 3, l2.flaggedRate(), 1e-12);
        assertEquals(Map.of(Outcome.STEP_UP, 1L, Outcome.DENY, 1L, Outcome.ALLOW_LIMITED, 1L), l2.outcomes());
    }

    @Test
    void rocCurveAndArea() {
        Accuracy a = Accuracy.of(table(), costs());
        List<Accuracy.RocPoint> roc = a.roc();
        assertEquals(0, roc.getFirst().falseAlarmRate());
        assertEquals(1, roc.getLast().falseAlarmRate(), 1e-12);
        assertEquals(1, roc.getLast().detectionRate(), 1e-12);
        // Mann-Whitney by brute force over all attack/legitimate pairs.
        double pairs = 0;
        double wins = 0;
        for (Observation x : table()) {
            for (Observation y : table()) {
                if (x.attack() && !y.attack()) {
                    pairs++;
                    wins += x.score() > y.score() ? 1 : x.score() == y.score() ? 0.5 : 0;
                }
            }
        }
        assertEquals(wins / pairs, a.auc().getAsDouble(), 1e-12);
    }

    @Test
    void perfectAndRandomSeparation() {
        List<Observation> perfect = List.of(obs("A", true, Outcome.DENY, 0.9), obs("L", false, Outcome.ALLOW, 0.001));
        assertEquals(1.0, Accuracy.auc(perfect).getAsDouble(), 1e-12);
        List<Observation> tied = List.of(obs("A", true, Outcome.ALLOW, 0.1), obs("L", false, Outcome.ALLOW, 0.1));
        assertEquals(0.5, Accuracy.auc(tied).getAsDouble(), 1e-12);
        Random rnd = new Random(3);
        List<Observation> noise = new ArrayList<>();
        for (int i = 0; i < 4_000; i++) {
            noise.add(obs("N", rnd.nextBoolean(), Outcome.ALLOW, rnd.nextDouble()));
        }
        assertEquals(0.5, Accuracy.auc(noise).getAsDouble(), 0.03);
    }

    @Test
    void reportStatesSourceAndCosts() {
        Report r = Accuracy.of(table(), new CostModel(500, 2, 30, 0.1)).report(DataSource.simulated(9, 3, 2, 0));
        String text = r.text();
        assertTrue(text.contains("seed 9"));
        assertTrue(text.contains("10 requests"));
        assertTrue(text.contains("C_B breach: 500.000000"));
        assertTrue(text.contains("area under curve"));
        assertTrue(text.contains("A1: attack n=2"));
        assertTrue(r.json().startsWith("{\"title\":\"Accuracy on labelled traffic\""));
    }

    @Test
    void limits() {
        assertThrows(NullPointerException.class, () -> Accuracy.of(null, costs()));
        assertThrows(NullPointerException.class, () -> Accuracy.of(table(), null));
        List<Observation> big = java.util.Collections.nCopies(Accuracy.MAX_OBSERVATIONS + 1, table().getFirst());
        assertThrows(IllegalArgumentException.class, () -> Accuracy.of(big, costs()));
        assertTrue(Accuracy.ratio(1, 0).isEmpty());
    }

    @Test
    void observationFromDecision() {
        Observation o = Observation.of("L1_NORMAL", false, AnalyticsRedTeamTest.decision("d", Outcome.ALLOW, 0.002));
        assertEquals(0.002, o.posterior());
        assertEquals(false, o.gated());
        Observation g = Observation.of("A5_TOR", true, new dev.dwarpal.decision.Decision("d", Outcome.DENY, false, false,
                "hard-gate:deny-list", "v", dev.dwarpal.risk.RiskAssessment.notEvaluated(0.001), List.of(),
                dev.dwarpal.Fixtures.T0));
        assertTrue(g.gated());
        assertTrue(g.score() > o.score());
    }
}

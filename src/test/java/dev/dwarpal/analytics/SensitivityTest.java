package dev.dwarpal.analytics;

import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Outcome;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.OptionalDouble;

import static dev.dwarpal.analytics.AnalyticsRedTeamTest.costs;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SensitivityTest {

    @Test
    void thresholdsMatchTheClosedFormsAndTheTableInProjectState() {
        // project-state 8.2: beta, step up above, deny above (reference costs 1000 / 1 / 20)
        double[][] table = {{0.01, 0.00101, 0.655}, {0.05, 0.00105, 0.275}, {0.30, 0.00143, 0.0596}};
        for (double[] row : table) {
            Sensitivity.Thresholds t = Sensitivity.thresholds(costs(), row[0]);
            assertEquals(1.0 / (1 + 1000 * (1 - row[0])), t.stepUpAbove(), 1e-15);
            assertEquals(19.0 / (19 + row[0] * 1000), t.denyAbove(), 1e-15);
            assertEquals(row[1], t.stepUpAbove(), 5e-6);
            assertEquals(row[2], t.denyAbove(), 5e-4);
        }
    }

    @Test
    void closedFormThresholdsAreWhereTheCostModelSwitches() {
        CostModel m = costs();
        double up = m.stepUpOverAllowThreshold();
        double deny = m.denyOverStepUpThreshold();
        assertEquals(Outcome.ALLOW, m.bestAction(up * 0.999));
        assertEquals(Outcome.STEP_UP, m.bestAction(up * 1.001));
        assertEquals(Outcome.STEP_UP, m.bestAction(deny * 0.999));
        assertEquals(Outcome.DENY, m.bestAction(deny * 1.001));
    }

    @Test
    void betaBreakpointsMatchTheSweep() {
        CostModel base = costs();
        double p = 0.1;   // STEP_UP at beta 0.05 (between 0.00105 and 0.275)
        double betaDeny = Sensitivity.betaWhereDenyBeatsStepUp(base, p).getAsDouble();
        assertEquals(19 * 0.9 / (0.1 * 1000), betaDeny, 1e-12);   // 0.171
        List<Sensitivity.Point> sweep = Sensitivity.sweepBeta(base, List.of(p),
                new double[]{betaDeny - 1e-6, betaDeny + 1e-6});
        assertEquals(1L, sweep.get(0).actions().get(Outcome.STEP_UP));
        assertEquals(1L, sweep.get(1).actions().get(Outcome.DENY));
        assertEquals(0, sweep.get(0).changed());
        assertEquals(1, sweep.get(1).changed());

        double small = 0.001;   // ALLOW at beta 0.05; STEP_UP once beta is small enough
        double betaAllow = Sensitivity.betaWhereStepUpLosesToAllow(base, small).getAsDouble();
        assertEquals(1 - 0.999 / (0.001 * 1000), betaAllow, 1e-12);   // 0.001
        assertEquals(Outcome.STEP_UP, new CostModel(1000, 1, 20, betaAllow - 1e-6).bestAction(small));
        assertEquals(Outcome.ALLOW, new CostModel(1000, 1, 20, betaAllow + 1e-6).bestAction(small));

        assertEquals(OptionalDouble.empty(), Sensitivity.betaWhereDenyBeatsStepUp(base, 0));
        assertEquals(OptionalDouble.empty(), Sensitivity.betaWhereStepUpLosesToAllow(base, 0));
        assertEquals(OptionalDouble.empty(), Sensitivity.betaWhereDenyBeatsStepUp(base, 0.01));   // beyond (0,1)
        assertEquals(OptionalDouble.empty(), Sensitivity.betaWhereDenyBeatsStepUp(new CostModel(1000, 5, 5, 0.05), 0.5));
        assertEquals(OptionalDouble.empty(), Sensitivity.betaWhereStepUpLosesToAllow(base, 0.00001));
    }

    @Test
    void costSweepsMoveDecisionsTheRightWay() {
        List<Double> ps = List.of(0.0005, 0.002, 0.1, 0.5);
        // base: ALLOW, STEP_UP, STEP_UP, DENY
        List<Sensitivity.Point> breach = Sensitivity.sweepCost(costs(), Sensitivity.Cost.BREACH, ps, new double[]{0.1, 1, 10});
        assertEquals(0, breach.get(1).changed());
        assertTrue(breach.get(2).actions().getOrDefault(Outcome.ALLOW, 0L) == 0, "a costlier breach allows less");
        assertEquals("breach x", breach.getFirst().parameter());
        List<Sensitivity.Point> deny = Sensitivity.sweepCost(costs(), Sensitivity.Cost.WRONG_DENY, ps, new double[]{100});
        assertEquals(0L, deny.getFirst().actions().getOrDefault(Outcome.DENY, 0L), "wrong denies 100x dearer: no DENY");
        List<Sensitivity.Point> friction = Sensitivity.sweepCost(costs(), Sensitivity.Cost.FRICTION, ps, new double[]{25});
        // friction above C_D: DENY always beats STEP_UP
        assertEquals(0L, friction.getFirst().actions().getOrDefault(Outcome.STEP_UP, 0L));
        assertTrue(Double.isInfinite(friction.getFirst().denyAbove()));
    }

    @Test
    void mfaSweepResolvesStepUps() {
        List<Double> ps = List.of(0.002, 0.01, 0.1, 0.25, 0.5);   // 0.5 is DENY at base and not counted
        List<Sensitivity.MfaPoint> m = Sensitivity.sweepMfa(costs(), ps, new double[]{0.01, 0.3, 1.0});
        assertEquals(4, m.getFirst().stepUps());
        // p' = p beta / (p beta + 1 - p), then ALLOW below 0.00105:
        // beta 0.01: 0.002 -> 0.00002, 0.01 -> 0.0001 resolve; 0.1 -> 0.0011 and 0.25 -> 0.0033 stay STEP_UP
        assertEquals(2, m.get(0).resolvedToAllow());
        assertEquals(2, m.get(0).stillStepUp());
        // beta 0.3: only 0.002 -> 0.0006 resolves
        assertEquals(1, m.get(1).resolvedToAllow());
        // beta 1 (a password): passing proves nothing
        assertEquals(0, m.get(2).resolvedToAllow());
        assertEquals(4, m.get(2).stillStepUp());
        assertEquals(0, Sensitivity.sweepMfa(costs(), List.of(1.0), new double[]{0.0}).getFirst().stepUps());
    }

    @Test
    void reportListsThresholdsSweepsAndScope() {
        List<Double> ps = List.of(0.0005, 0.002, 0.1, 0.5);
        double[] betas = {0.01, 0.05, 0.30};
        List<Sensitivity.Thresholds> th = java.util.Arrays.stream(betas).mapToObj(b -> Sensitivity.thresholds(costs(), b)).toList();
        Report r = Sensitivity.report(DataSource.simulated(7, 60, 8, ps.size()), costs(), th,
                List.of(Sensitivity.sweepBeta(costs(), ps, betas), List.of(),
                        Sensitivity.sweepCost(new CostModel(1000, 25, 20, 0.05), Sensitivity.Cost.FRICTION, ps, new double[]{1})),
                Sensitivity.sweepMfa(costs(), ps, betas));
        String text = r.text();
        assertTrue(text.contains("beta 0.050000: step up above 0.001052, deny above 0.275362"), text);
        assertTrue(text.contains("cost-optimal action only"), text);
        assertTrue(text.contains("Sweep: beta"), text);
        assertTrue(text.contains("deny above always"), text);
        assertTrue(text.contains("Step-up resolution by MFA beta"), text);
        assertThrows(NullPointerException.class, () -> Sensitivity.sweepCost(costs(), null, ps, betas));
        assertThrows(NullPointerException.class, () -> Sensitivity.sweepBeta(costs(), null, betas));
        assertThrows(IllegalArgumentException.class, () -> Sensitivity.thresholds(costs(), -0.1));
    }
}

package dev.dwarpal.decision;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CostModelTest {

    // Breach costs 1000x a step-up prompt; wrongly blocking costs 20x a prompt; MFA is bypassed 5% of the time.
    private final CostModel model = new CostModel(1000, 1, 20, 0.05);

    @Test
    void lowRiskAllowsMidRiskStepsUpHighRiskDenies() {
        assertEquals(Outcome.ALLOW, model.bestAction(0.0001));
        assertEquals(Outcome.STEP_UP, model.bestAction(0.05));
        assertEquals(Outcome.DENY, model.bestAction(0.9));
    }

    @Test
    void argminAgreesWithClosedFormThresholds() {
        double stepUp = model.stepUpOverAllowThreshold();
        double deny = model.denyOverStepUpThreshold();
        assertTrue(stepUp < deny, "thresholds must be ordered for this cost setting");
        for (int i = 0; i <= 10_000; i++) {
            double p = i / 10_000.0;
            Outcome expected = p > deny ? Outcome.DENY : p > stepUp ? Outcome.STEP_UP : Outcome.ALLOW;
            // Exactly at a threshold, ties go to the stricter action, which the strict '>' above does not model.
            if (Math.abs(p - stepUp) < 1e-9 || Math.abs(p - deny) < 1e-9) {
                continue;
            }
            assertEquals(expected, model.bestAction(p), "p=" + p);
        }
    }

    @Test
    void weakerMfaMakesTheEngineDenySooner() {
        CostModel strongMfa = new CostModel(1000, 1, 20, 0.01);   // e.g. WebAuthn
        CostModel weakMfa = new CostModel(1000, 1, 20, 0.30);     // push MFA under fatigue attack
        assertTrue(weakMfa.denyOverStepUpThreshold() < strongMfa.denyOverStepUpThreshold());

        double p = 0.08;
        assertEquals(Outcome.STEP_UP, strongMfa.bestAction(p));
        assertEquals(Outcome.DENY, weakMfa.bestAction(p));
    }

    @Test
    void perfectMfaNeverPrefersDenyWhenBlockingCostsMoreThanAPrompt() {
        CostModel perfect = new CostModel(1000, 1, 20, 0.0);
        assertEquals(1.0, perfect.denyOverStepUpThreshold(), 1e-12);
        assertEquals(Outcome.STEP_UP, perfect.bestAction(0.99));
    }

    @Test
    void whenBlockingIsCheaperThanPromptingDenyAlwaysBeatsStepUp() {
        CostModel odd = new CostModel(1000, 5, 1, 0.1);
        assertEquals(Double.NEGATIVE_INFINITY, odd.denyOverStepUpThreshold());
    }

    @Test
    void tiesResolveToTheStricterAction() {
        CostModel m = new CostModel(10, 10, 10, 0.0);
        // At p=0.5: ALLOW=5, STEP_UP=5, DENY=5 -> must pick DENY.
        assertEquals(Outcome.DENY, m.bestAction(0.5));
    }

    @Test
    void rejectsNonsenseParameters() {
        assertThrows(IllegalArgumentException.class, () -> new CostModel(-1, 1, 1, 0.1));
        assertThrows(IllegalArgumentException.class, () -> new CostModel(1, 1, 1, 1.5));
        assertThrows(IllegalArgumentException.class, () -> new CostModel(Double.NaN, 1, 1, 0.1));
        assertThrows(IllegalArgumentException.class, () -> model.bestAction(1.1));
        assertThrows(IllegalArgumentException.class, () -> model.expectedLoss(Outcome.ALLOW_LIMITED, 0.5));
    }
}

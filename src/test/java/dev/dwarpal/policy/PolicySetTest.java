package dev.dwarpal.policy;

import dev.dwarpal.Fixtures;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicySetTest {

    private static final EvaluationContext ALICE = new EvaluationContext(Fixtures.request().build(), 0.0);
    private static final Condition MATCH = new Conditions.Always();
    private static final Condition ENGINEER = new Conditions.RoleIn(Set.of("engineer"));
    private static final Condition MANAGED = new Conditions.DeviceManaged(true);

    private static Policy p(String id, Condition c, Effect e) {
        return new Policy(id, "", c, e);
    }

    @Test
    void aConstraintAloneNeverGrantsAccess() {
        var set = new PolicySet("v", CombiningAlgorithm.DENY_OVERRIDES, Effect.DENY,
                List.of(p("MFA", MATCH, Effect.REQUIRE_STEP_UP)));
        var r = set.evaluate(ALICE);
        assertEquals(Effect.DENY, r.effect());
        assertTrue(r.defaulted());
    }

    @Test
    void constraintTightensAGrant() {
        var set = new PolicySet("v", CombiningAlgorithm.DENY_OVERRIDES, Effect.DENY,
                List.of(p("OK", ENGINEER, Effect.PERMIT), p("MFA", MANAGED, Effect.REQUIRE_STEP_UP)));
        var r = set.evaluate(ALICE);
        assertEquals(Effect.REQUIRE_STEP_UP, r.effect());
        assertEquals("MFA", r.policyId());
        assertFalse(r.defaulted());
    }

    @Test
    void mostRestrictiveGrantWinsUnderDenyOverrides() {
        var set = new PolicySet("v", CombiningAlgorithm.DENY_OVERRIDES, Effect.DENY,
                List.of(p("FULL", ENGINEER, Effect.PERMIT), p("RO", MANAGED, Effect.PERMIT_LIMITED)));
        assertEquals(Effect.PERMIT_LIMITED, set.evaluate(ALICE).effect());
    }

    @Test
    void aStricterConstraintKeepsTheReadOnlyFlagOfTheGrant() {
        var set = new PolicySet("v", CombiningAlgorithm.DENY_OVERRIDES, Effect.DENY,
                List.of(p("RO", ENGINEER, Effect.PERMIT_LIMITED), p("MFA", MANAGED, Effect.REQUIRE_STEP_UP)));
        var r = set.evaluate(ALICE);
        assertEquals(Effect.REQUIRE_STEP_UP, r.effect());
        assertTrue(r.limited(), "read-only must survive the step-up constraint");
        assertFalse(new PolicySet("v", CombiningAlgorithm.DENY_OVERRIDES, Effect.DENY,
                List.of(p("OK", ENGINEER, Effect.PERMIT))).evaluate(ALICE).limited());
    }

    @Test
    void failOpenDefaultIsStillTightenedByConstraints() {
        var set = new PolicySet("v", CombiningAlgorithm.DENY_OVERRIDES, Effect.PERMIT,
                List.of(p("BLOCK", ENGINEER, Effect.DENY)));
        var r = set.evaluate(ALICE);
        assertEquals(Effect.DENY, r.effect());
        assertEquals("BLOCK", r.policyId());
    }

    @Test
    void firstApplicableKeepsEarlierStepUpButStopsAtFirstGrant() {
        var set = new PolicySet("v", CombiningAlgorithm.FIRST_APPLICABLE, Effect.DENY,
                List.of(p("MFA", MANAGED, Effect.REQUIRE_STEP_UP), p("OK", ENGINEER, Effect.PERMIT),
                        p("LATE-DENY", MATCH, Effect.DENY)));
        var r = set.evaluate(ALICE);
        assertEquals(Effect.REQUIRE_STEP_UP, r.effect());
    }

    @Test
    void firstApplicableDenyStopsEvaluation() {
        var set = new PolicySet("v", CombiningAlgorithm.FIRST_APPLICABLE, Effect.PERMIT,
                List.of(p("NO", ENGINEER, Effect.DENY), p("OK", MATCH, Effect.PERMIT)));
        assertEquals(Effect.DENY, set.evaluate(ALICE).effect());
    }

    @Test
    void grantsAndConstraintsAreClassifiedCorrectly() {
        assertTrue(Effect.PERMIT.grants());
        assertTrue(Effect.PERMIT_LIMITED.grants());
        assertFalse(Effect.REQUIRE_STEP_UP.grants());
        assertFalse(Effect.DENY.grants());
    }
}

package dev.dwarpal.analytics;

import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.policy.PolicySet;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static dev.dwarpal.analytics.SmallWorld.ENGINEERING_READS_CONFIDENTIAL;
import static dev.dwarpal.analytics.SmallWorld.ENGINEERING_READS_PAYROLL;
import static dev.dwarpal.analytics.SmallWorld.INTERNAL_APPS;
import static dev.dwarpal.analytics.SmallWorld.policies;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WhatIfTest {

    private static final PolicySet BASE = policies("v1", INTERNAL_APPS);

    private static WhatIf.Result replay(PolicySet proposed) {
        return new WhatIf(SmallWorld.engine(BASE), proposed, SmallWorld.DIRECTORY)
                .replay(SmallWorld.everything(), SignalSnapshot.empty());
    }

    @Test
    void identicalPolicyGivesNoChange() {
        WhatIf.Result r = replay(policies("v1b", INTERNAL_APPS));
        assertEquals(18, r.replayed());
        assertEquals(18, r.unchanged());
        assertTrue(r.changes().isEmpty());
        assertTrue(r.valid());
        assertEquals("v1", r.currentVersion());
        assertEquals("v1b", r.proposedVersion());
    }

    @Test
    void addingOneGrantGivesExactlyTheExpectedDiff() {
        WhatIf.Result r = replay(policies("v2", INTERNAL_APPS, ENGINEERING_READS_CONFIDENTIAL));
        assertEquals(1, r.gains());
        assertEquals(0, r.losses());
        assertEquals(17, r.unchanged());
        WhatIf.Change c = r.changes().getFirst();
        assertEquals(new WhatIf.Change("alice", "design-docs", Action.READ, DataClassification.CONFIDENTIAL,
                Outcome.DENY, false, "default", Outcome.ALLOW, false, "P-02-eng-confidential",
                WhatIf.Direction.GAIN, false), c);
        assertTrue(r.sensitiveGrants().isEmpty());
        assertEquals(List.of(new WhatIf.Tally("P-02-eng-confidential", 1, 0), new WhatIf.Tally("default", 1, 0)),
                r.byPolicy());
        assertEquals(List.of(new WhatIf.Tally("alice", 1, 0)), r.bySubject());
        assertEquals(List.of(new WhatIf.Tally("design-docs", 1, 0)), r.byResource());
        assertEquals(List.of(new WhatIf.Tally("READ", 1, 0)), r.byAction());
        assertTrue(r.fidelityMismatches().isEmpty());
    }

    @Test
    void grantToRestrictedResourceIsFlagged() {
        WhatIf.Result r = replay(policies("v3", INTERNAL_APPS, ENGINEERING_READS_PAYROLL));
        assertEquals(3, r.gains());
        assertEquals(3, r.sensitiveGrants().size());
        assertTrue(r.sensitiveGrants().stream().allMatch(c -> c.subject().equals("alice")
                && c.resource().equals("payroll") && c.classification() == DataClassification.RESTRICTED));
        Report rep = r.report(DataSource.simulated(1, 2, 1, 18));
        assertEquals("3", rep.line("Summary", "new grants to RESTRICTED resources or ADMIN actions").orElseThrow().text());
    }

    @Test
    void removingAGrantShowsLossesAndGains() {
        WhatIf.Result r = replay(policies("v4", ENGINEERING_READS_CONFIDENTIAL));
        assertEquals(5, r.losses());
        assertEquals(1, r.gains());
        // bob loses all three wiki actions; alice loses WRITE and ADMIN on the wiki
        assertEquals(new WhatIf.Tally("bob", 0, 3), r.bySubject().stream().filter(t -> t.key().equals("bob"))
                .findFirst().orElseThrow());
        assertEquals(new WhatIf.Tally("alice", 1, 2), r.bySubject().stream().filter(t -> t.key().equals("alice"))
                .findFirst().orElseThrow());
        assertTrue(r.changes().stream().filter(c -> c.direction() == WhatIf.Direction.LOSS)
                .allMatch(c -> c.before() == Outcome.ALLOW && c.after() == Outcome.DENY));
    }

    @Test
    void sameSignalsForBothPolicies() {
        // a deny-listed subject stays denied under both: the deny list is not a policy change
        SignalSnapshot s = new SignalSnapshot(Set.of(), Set.of("alice"), Set.of(), Set.of());
        PolicyEngine e = SmallWorld.builder(BASE).gate(new dev.dwarpal.engine.DenyListGate()).build();
        WhatIf.Result r = new WhatIf(e, policies("v3", INTERNAL_APPS, ENGINEERING_READS_PAYROLL), SmallWorld.DIRECTORY)
                .replay(SmallWorld.everything(), s);
        assertEquals(0, r.gains());
        assertEquals(18, r.unchanged());
    }

    @Test
    void restrictedFlagChangeCountsAsGainOrLoss() {
        dev.dwarpal.policy.Policy limited = new dev.dwarpal.policy.Policy("P-01-limited", "read-only internal apps",
                INTERNAL_APPS.when(), dev.dwarpal.policy.Effect.PERMIT_LIMITED);
        WhatIf.Result r = replay(policies("v5", limited));
        assertEquals(6, r.losses());
        // READ becomes read-only access; WRITE and ADMIN are refused by the read-only obligation
        assertTrue(r.changes().stream().filter(c -> c.action() == Action.READ)
                .allMatch(c -> c.after() == Outcome.ALLOW_LIMITED && c.restrictedAfter()));
        assertTrue(r.changes().stream().filter(c -> c.action() != Action.READ).allMatch(c -> c.after() == Outcome.DENY));
    }

    @Test
    void reportStatesItsSourceAndValidity() {
        Report rep = replay(policies("v2", INTERNAL_APPS, ENGINEERING_READS_CONFIDENTIAL))
                .report(DataSource.simulated(42, 2, 1, 0));
        String text = rep.text();
        assertTrue(text.contains("seed 42"), text);
        assertTrue(text.contains("18 requests"), text);
        assertTrue(text.contains("not real-world accuracy"), text);
        assertTrue(text.contains("status: VALID"), text);
        assertTrue(rep.json().contains("\"seed\":42"));
    }

    @Test
    void manyChangesAreCountedButListBounded() {
        java.util.List<AccessRequest> many = new java.util.ArrayList<>();
        for (int i = 0; i < WhatIf.MAX_CHANGES_KEPT + 5; i++) {
            many.add(SmallWorld.request("m" + i, SmallWorld.ALICE, SmallWorld.DESIGN, Action.READ));
        }
        WhatIf.Result r = new WhatIf(SmallWorld.engine(BASE), policies("v2", INTERNAL_APPS, ENGINEERING_READS_CONFIDENTIAL),
                SmallWorld.DIRECTORY).replay(many, SignalSnapshot.empty());
        assertEquals(WhatIf.MAX_CHANGES_KEPT + 5, r.gains());
        assertEquals(WhatIf.MAX_CHANGES_KEPT, r.changes().size());
        assertEquals(5, r.changesNotKept());
        String text = r.report(DataSource.simulated(1, 1, 1, 0)).text();
        assertTrue(text.contains("more not shown"));
        assertTrue(text.contains("changes counted but not listed: 5"));
    }

    @Test
    void tooManyRequestsRefused() {
        WhatIf w = new WhatIf(SmallWorld.engine(BASE), BASE, SmallWorld.DIRECTORY);
        List<AccessRequest> huge = java.util.Collections.nCopies(WhatIf.MAX_REQUESTS + 1,
                SmallWorld.request("x", SmallWorld.ALICE, SmallWorld.WIKI, Action.READ));
        assertThrows(IllegalArgumentException.class, () -> w.replay(huge, SignalSnapshot.empty()));
        List<RecordedRequest> hugeRec = java.util.Collections.nCopies(WhatIf.MAX_REQUESTS + 1, null);
        assertThrows(IllegalArgumentException.class, () -> w.replayRecorded(hugeRec, SignalSnapshot.empty()));
        assertThrows(NullPointerException.class, () -> w.replay(List.of(), null));
    }

    @Test
    void accessRankOrdersOutcomes() {
        assertFalse(WhatIf.accessRank(decision(Outcome.DENY, false)) >= WhatIf.accessRank(decision(Outcome.STEP_UP, false)));
        assertTrue(WhatIf.accessRank(decision(Outcome.ALLOW, false)) > WhatIf.accessRank(decision(Outcome.ALLOW_LIMITED, true)));
        assertTrue(WhatIf.accessRank(decision(Outcome.STEP_UP, false)) > WhatIf.accessRank(decision(Outcome.STEP_UP, true)));
    }

    static dev.dwarpal.decision.Decision decision(Outcome o, boolean restricted) {
        return new dev.dwarpal.decision.Decision("d", o, restricted, true, "p", "v",
                dev.dwarpal.risk.RiskAssessment.notEvaluated(0.001), List.of(), dev.dwarpal.Fixtures.T0);
    }
}

package dev.dwarpal.engine;

import dev.dwarpal.Fixtures;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.domain.FailMode;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.policy.CombiningAlgorithm;
import dev.dwarpal.policy.Condition;
import dev.dwarpal.policy.Effect;
import dev.dwarpal.policy.EvaluationContext;
import dev.dwarpal.policy.Policy;
import dev.dwarpal.policy.PolicySet;
import dev.dwarpal.policy.SafePolicyLoader;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.RiskScorer;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PolicyEngineTest {

    public static final PolicySet POLICIES =
            new SafePolicyLoader().load(Fixtures.resource("/policies/default-policy.yaml"));

    /** Test scorer that reports a fixed likelihood ratio. */
    public static RiskScorer fixed(String name, double likelihoodRatio) {
        return new RiskScorer() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public Optional<RiskFactor> score(AccessRequest r, SignalSnapshot s) {
                return Optional.of(new RiskFactor(name, Math.log(likelihoodRatio), "test evidence"));
            }
        };
    }

    static RiskScorer broken(String name) {
        return new RiskScorer() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public Optional<RiskFactor> score(AccessRequest r, SignalSnapshot s) {
                throw new IllegalStateException("geoip database unreachable");
            }
        };
    }

    public static PolicyEngine engine(RiskScorer... scorers) {
        return PolicyEngine.builder()
                .policySet(POLICIES)
                .directory(Fixtures.emptyDirectory()).keyRing(Fixtures.KEYRING)
                .gate(new HoneytokenGate())
                .gate(new DenyListGate())
                .scorers(List.of(scorers))
                .aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                .costModel(new CostModel(1000, 1, 20, 0.05))
                .build();
    }

    /** Decide with a directory that agrees with the request (an honest PEP). */
    public static Decision decide(PolicyEngine e, AccessRequest r) {
        return e.withDirectory(Fixtures.directoryFor(r)).decide(r, SignalSnapshot.empty());
    }

    // ---- normal behaviour ----------------------------------------------------------------------

    @Test
    void normalEmployeeOnInternalAppIsAllowed() {
        Decision d = decide(engine(), Fixtures.request().build());
        assertEquals(Outcome.ALLOW, d.outcome());
        assertFalse(d.restricted());
        assertEquals("P-01-employees-internal-apps", d.matchedPolicyId());
        assertEquals("2026.11.01-1", d.policyVersion());
    }

    @Test
    void nothingMatchedMeansDefaultDeny() {
        Decision d = decide(engine(), Fixtures.request().workload().build());
        assertEquals(Outcome.DENY, d.outcome());
        assertEquals(PolicySet.DEFAULT_POLICY_ID, d.matchedPolicyId());
    }

    @Test
    void riskEscalatesAPermitToStepUpAndThenDeny() {
        assertEquals(Outcome.STEP_UP, decide(engine(fixed("new-device", 10)), Fixtures.request().build()).outcome());
        assertEquals(Outcome.DENY, decide(engine(fixed("travel", 1000), fixed("asn", 1000)),
                Fixtures.request().build()).outcome());
    }

    @Test
    void reassuringEvidenceCannotLoosenAPolicyFloor() {
        AccessRequest r = Fixtures.request().roles("finance")
                .posture(new DevicePosture(true, true, true, AssuranceLevel.HARDWARE_ATTESTED))
                .resource("payroll", ResourceKind.PRIVATE_APP, DataClassification.RESTRICTED).build();
        assertEquals(Outcome.STEP_UP, decide(engine(fixed("familiar", 0.001)), r).outcome());
    }

    @Test
    void selfReportedHealthIsNotEnoughForConfidentialData() {
        AccessRequest r = Fixtures.request().roles("finance")
                .posture(new DevicePosture(true, true, true, AssuranceLevel.SELF_REPORTED))
                .resource("ledger", ResourceKind.PRIVATE_APP, DataClassification.CONFIDENTIAL).build();
        Decision d = decide(engine(), r);
        assertEquals(Outcome.DENY, d.outcome());
        assertEquals("P-03-confidential-needs-attested-health", d.matchedPolicyId());
    }

    @Test
    void unmanagedDeviceGetsReadOnlySaaS() {
        AccessRequest r = Fixtures.request().unmanaged()
                .resource("crm-notes", ResourceKind.SAAS_DATA, DataClassification.INTERNAL).build();
        Decision d = decide(engine(), r);
        assertEquals(Outcome.ALLOW_LIMITED, d.outcome());
        assertTrue(d.restricted());
    }

    @Test
    void adminActionNeedsStepUp() {
        assertEquals(Outcome.STEP_UP, decide(engine(), Fixtures.request().action(Action.ADMIN).build()).outcome());
    }

    // ---- hard gates & failure handling ---------------------------------------------------------

    @Test
    void honeytokenUseIsDeniedBeforeScoringEvenIfTheDecoyIsNotInTheDirectory() {
        AccessRequest r = Fixtures.request().subject("svc-backup-legacy").build();
        SignalSnapshot s = new SignalSnapshot(Set.of("svc-backup-legacy"), Set.of(), Set.of(), Set.of());
        Decision d = engine(fixed("familiar", 0.001)).decide(r, s);
        assertEquals(Outcome.DENY, d.outcome());
        assertEquals("hard-gate:honeytoken", d.matchedPolicyId());
        assertTrue(d.risk().factors().isEmpty(), "scoring must not run after a hard gate fires");
    }

    @Test
    void honeytokenDeviceAndDenyListsAreEnforced() {
        PolicyEngine e = engine();
        AccessRequest r = Fixtures.request().build();
        assertEquals(Outcome.DENY, e.decide(r, new SignalSnapshot(Set.of("laptop-alice"), Set.of(), Set.of(), Set.of())).outcome());
        assertEquals(Outcome.DENY, e.decide(r, new SignalSnapshot(Set.of(), Set.of("alice"), Set.of(), Set.of())).outcome());
        assertEquals(Outcome.DENY, e.decide(r, new SignalSnapshot(Set.of(), Set.of(), Set.of("laptop-alice"), Set.of())).outcome());
        Decision byIp = e.decide(r, new SignalSnapshot(Set.of(), Set.of(), Set.of(), Set.of("203.0.113.10")));
        assertEquals("hard-gate:deny-list", byIp.matchedPolicyId());
    }

    @Test
    void unavailableSignalFailsClosedOrStepsUpButNeverAllows() {
        Decision closed = decide(engine(broken("geoip")), Fixtures.request().failMode(FailMode.FAIL_CLOSED).build());
        assertEquals(Outcome.DENY, closed.outcome());
        assertEquals("fail-closed", closed.matchedPolicyId());

        Decision degraded = decide(engine(broken("geoip")), Fixtures.request().failMode(FailMode.FAIL_STEP_UP).build());
        assertEquals(Outcome.STEP_UP, degraded.outcome());
        assertEquals(List.of("geoip"), degraded.risk().failedScorers());
    }

    @Test
    void brokenHardGateFailsClosed() {
        HardGate exploding = new HardGate() {
            @Override
            public String name() {
                return "threat-intel";
            }

            @Override
            public Optional<String> check(AccessRequest r, SignalSnapshot s) {
                throw new IllegalStateException("feed down");
            }
        };
        PolicyEngine e = PolicyEngine.builder().policySet(POLICIES).directory(Fixtures.emptyDirectory()).keyRing(Fixtures.KEYRING)
                .gate(exploding).aggregator(new BayesianRiskAggregator(0.001, 7))
                .costModel(new CostModel(1000, 1, 20, 0.05)).build();
        assertEquals(Outcome.DENY, decide(e, Fixtures.request().build()).outcome());
    }

    @Test
    void unexpectedEngineErrorFailsClosedWithoutLeakingDetails() {
        Condition exploding = new Condition() {
            @Override
            public boolean matches(EvaluationContext c) {
                throw new IllegalStateException("bug in a condition");
            }

            @Override
            public String describe() {
                return "exploding";
            }
        };
        PolicySet buggy = new PolicySet("bug-1", CombiningAlgorithm.DENY_OVERRIDES, Effect.DENY,
                List.of(new Policy("P-BUG", "", exploding, Effect.PERMIT)));
        Decision d = decide(engine().withPolicySet(buggy), Fixtures.request().build());
        assertEquals(Outcome.DENY, d.outcome());
        assertEquals("engine-error", d.matchedPolicyId());
        assertFalse(d.analystReport().contains("bug in a condition"), "internal details must not leak");
    }

    @Test
    void stackOverflowInAConditionIsADenyNotACrash() {
        Condition recursive = new Condition() {
            @Override
            public boolean matches(EvaluationContext c) {
                return matches(c);
            }

            @Override
            public String describe() {
                return "recursive";
            }
        };
        PolicySet set = new PolicySet("so-1", CombiningAlgorithm.DENY_OVERRIDES, Effect.DENY,
                List.of(new Policy("P-REC", "", recursive, Effect.PERMIT)));
        Decision d = decide(engine().withPolicySet(set), Fixtures.request().build());
        assertEquals(Outcome.DENY, d.outcome());
        assertTrue(d.analystReport().contains("StackOverflowError"));
    }

    @Test
    void scorerBreakingItsContractCountsAsAnUnavailableSignal() {
        RiskScorer rogue = new RiskScorer() {
            @Override
            public String name() {
                return "rogue";
            }

            @Override
            public Optional<RiskFactor> score(AccessRequest r, SignalSnapshot s) {
                return null;
            }
        };
        Decision d = decide(engine(rogue), Fixtures.request().build());
        assertEquals(Outcome.DENY, d.outcome());
        assertEquals(List.of("rogue"), d.risk().failedScorers());
    }

    @Test
    void nullInputsAreProgrammingErrorsAndRejectedLoudly() {
        PolicyEngine e = engine();
        assertThrows(NullPointerException.class, () -> e.decide(Fixtures.request().build(), null));
        assertThrows(NullPointerException.class, () -> e.decide(null, SignalSnapshot.empty()));
        assertThrows(NullPointerException.class, () -> PolicyEngine.builder().policySet(POLICIES)
                .aggregator(new BayesianRiskAggregator(0.001, 7)).costModel(new CostModel(1, 1, 1, 0)).build(),
                "an engine without a directory would have to trust the request");
    }

    @Test
    void programmaticPolicySetsAreLintGatedToo() {
        Condition c = new dev.dwarpal.policy.Conditions.RoleIn(Set.of("x"));
        PolicySet conflicting = new PolicySet("c-1", CombiningAlgorithm.DENY_OVERRIDES, Effect.DENY,
                List.of(new Policy("A", "", c, Effect.PERMIT), new Policy("B", "", c, Effect.DENY)));
        assertThrows(IllegalArgumentException.class, () -> engine().withPolicySet(conflicting));
    }

    // ---- explainability, determinism -----------------------------------------------------------

    @Test
    void userMessageNeverRevealsWhichSignalFired() {
        Decision d = decide(engine(fixed("impossible-travel", 1000), fixed("new-asn", 1000)), Fixtures.request().build());
        assertEquals(Outcome.DENY, d.outcome());
        assertFalse(d.userMessage().contains("travel"));
        assertFalse(d.userMessage().contains("asn"));
        assertTrue(d.userMessage().contains(d.requestId()));
        assertTrue(d.analystReport().contains("impossible-travel"));
    }

    @Test
    void decisionsAreDeterministic() {
        PolicyEngine e = engine(fixed("new-device", 10));
        AccessRequest r = Fixtures.request().build();
        assertEquals(decide(e, r), decide(e, r));
    }

    @Test
    void withPolicySetSwapsPoliciesButKeepsEverythingElse() {
        PolicySet denyAll = new SafePolicyLoader().load("""
                version: "lockdown-1"
                algorithm: FIRST_APPLICABLE
                default: DENY
                policies: []
                """);
        PolicyEngine original = engine();
        PolicyEngine lockdown = original.withPolicySet(denyAll);
        assertEquals(Outcome.ALLOW, decide(original, Fixtures.request().build()).outcome());
        Decision d = decide(lockdown, Fixtures.request().build());
        assertEquals(Outcome.DENY, d.outcome());
        assertEquals("lockdown-1", d.policyVersion());
        assertEquals(original.costModel(), lockdown.costModel());
    }
}

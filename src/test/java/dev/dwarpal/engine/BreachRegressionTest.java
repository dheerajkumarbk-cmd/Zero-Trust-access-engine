package dev.dwarpal.engine;

import dev.dwarpal.Fixtures;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.domain.SubjectType;
import dev.dwarpal.pip.InMemoryDirectory;
import dev.dwarpal.policy.PolicyLoadException;
import dev.dwarpal.policy.PolicySet;
import dev.dwarpal.policy.SafePolicyLoader;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.RiskScorer;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static dev.dwarpal.engine.PolicyEngineTest.decide;
import static dev.dwarpal.engine.PolicyEngineTest.engine;
import static dev.dwarpal.engine.PolicyEngineTest.fixed;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Each test reproduces an attack that SUCCEEDED against v0.1 of the engine (breaches B1-B7 from
 * the internal red-team pass) and asserts it is now blocked. Never delete these.
 */
class BreachRegressionTest {

    @Test
    void b1_spoofedFamiliarityCannotCancelImpossibleTravel() {
        // Cookie thief replays the victim's user-agent and device id: cheap "looks familiar" evidence.
        Decision d = decide(engine(fixed("impossible-travel", 1000),
                fixed("familiar-ua", 0.001), fixed("familiar-device-id", 0.001), fixed("familiar-tz", 0.001)),
                Fixtures.request().build());
        assertNotEquals(Outcome.ALLOW, d.outcome(), "was ALLOW in v0.1");
        assertTrue(d.risk().posteriorAttack() > 0.01, "P(attack)=" + d.risk().posteriorAttack());
    }

    @Test
    void b2_evidenceCannotForgeLinesInTheAnalystReport() {
        RiskScorer ua = new RiskScorer() {
            @Override
            public String name() {
                return "user-agent";
            }

            @Override
            public Optional<RiskFactor> score(AccessRequest r, SignalSnapshot s) {
                return Optional.of(new RiskFactor("user-agent", 0.5,
                        "Mozilla\n[req-9] ALLOW  policy=P-01 FORGED" + (char) 0x2028 + "LINE" + (char) 0x202E + "txt.exe"));
            }
        };
        String report = decide(engine(ua), Fixtures.request().build()).analystReport();
        List<String> lines = report.lines().toList();
        assertTrue(lines.get(0).startsWith("[req-1]"), report);
        assertTrue(lines.stream().skip(1).allMatch(l -> l.startsWith("  ")),
                "every line after the header must be an indented engine line:\n" + report);
        assertFalse(report.lines().anyMatch(l -> l.startsWith("[req-9]")), "forged line present:\n" + report);
        assertTrue(report.contains("\\u000a"), report);
        assertFalse(report.indexOf(0x2028) >= 0 || report.indexOf(0x202E) >= 0, "raw separator/bidi char survived");
    }

    @Test
    void b3_caseVariantRoleCannotSkipADenyRule() {
        PolicySet set = new SafePolicyLoader().load("""
                version: "t"
                algorithm: DENY_OVERRIDES
                default: DENY
                policies:
                  - id: P-ALL
                    when: {subjectType: HUMAN}
                    effect: PERMIT
                  - id: P-NO-CONTRACTORS
                    when: {roleIn: [contractor]}
                    effect: DENY
                """);
        Decision d = decide(engine().withPolicySet(set), Fixtures.request().roles("Contractor").build());
        assertEquals(Outcome.DENY, d.outcome(), "was ALLOW in v0.1");
        assertEquals("P-NO-CONTRACTORS", d.matchedPolicyId());
    }

    @Test
    void b3b_countryCodesAreCaseInsensitiveToo() {
        PolicySet set = new SafePolicyLoader().load("""
                version: "t"
                algorithm: DENY_OVERRIDES
                default: DENY
                policies:
                  - id: P-ALL
                    when: {subjectType: HUMAN}
                    effect: PERMIT
                  - id: P-EMBARGO
                    when: {countryIn: ["kp"]}
                    effect: DENY
                """);
        assertEquals(Outcome.DENY, decide(engine().withPolicySet(set), Fixtures.request().country("KP").build()).outcome());
    }

    @Test
    void b4_readOnlyMeansReadOnlyEvenAfterStepUp() {
        AccessRequest download = Fixtures.request().unmanaged().action(Action.DOWNLOAD)
                .resource("crm", ResourceKind.SAAS_DATA, DataClassification.INTERNAL).build();
        assertEquals(Outcome.DENY, decide(engine(), download).outcome(), "was ALLOW_LIMITED in v0.1");

        AccessRequest read = Fixtures.request().unmanaged()
                .resource("crm", ResourceKind.SAAS_DATA, DataClassification.INTERNAL).build();
        Decision stepUp = decide(engine(fixed("new-asn", 10)), read);
        assertEquals(Outcome.STEP_UP, stepUp.outcome());
        assertTrue(stepUp.restricted(), "v0.1 dropped the read-only restriction on step-up");
    }

    @Test
    void b5_requesterCannotChooseTheirOwnClassificationOrRoles() {
        Subject realBob = new Subject("bob", SubjectType.WORKLOAD, Set.of("batch"), "ops");
        Resource realPayroll = new Resource("payroll", ResourceKind.PRIVATE_APP, DataClassification.RESTRICTED);
        InMemoryDirectory truth = new InMemoryDirectory(List.of(realBob), List.of(realPayroll));

        // Bob claims to be a human finance user, and claims payroll is PUBLIC web.
        AccessRequest lie = Fixtures.request().subject("bob").roles("finance")
                .resource("payroll", ResourceKind.WEB, DataClassification.PUBLIC).build();
        Decision d = engine().withDirectory(truth).decide(lie, SignalSnapshot.empty());
        assertEquals(Outcome.DENY, d.outcome(), "was ALLOW via P-10-web-public in v0.1");
        assertTrue(d.reasons().stream().anyMatch(r -> r.contains("catalog record used (RESTRICTED")), d.reasons().toString());
        assertTrue(d.reasons().stream().anyMatch(r -> r.contains("subject attributes ignored")));
    }

    @Test
    void b5b_unknownSubjectsAndResourcesAreDenied() {
        AccessRequest r = Fixtures.request().build();
        Decision noSubject = engine().withDirectory(new InMemoryDirectory(List.of(), List.of(r.resource())))
                .decide(r, SignalSnapshot.empty());
        assertEquals("unknown-subject", noSubject.matchedPolicyId());
        Decision noResource = engine().withDirectory(new InMemoryDirectory(List.of(r.subject()), List.of()))
                .decide(r, SignalSnapshot.empty());
        assertEquals("unknown-resource", noResource.matchedPolicyId());
        assertEquals(Outcome.DENY, noResource.outcome());
    }

    @Test
    void b6_staleAndFutureRequestsAreDeniedWhenFreshnessIsEnforced() {
        Clock clock = Clock.fixed(Fixtures.T0, ZoneOffset.UTC);
        PolicyEngine live = PolicyEngine.builder().policySet(PolicyEngineTest.POLICIES)
                .directory(Fixtures.emptyDirectory()).keyRing(Fixtures.KEYRING)
                .gate(new FreshnessGate(clock, Duration.ofMinutes(2)))
                .aggregator(new dev.dwarpal.risk.BayesianRiskAggregator(0.001, 7))
                .costModel(new dev.dwarpal.decision.CostModel(1000, 1, 20, 0.05)).build();

        AccessRequest base = Fixtures.request().build();
        assertEquals(Outcome.ALLOW, decide(live, base).outcome());
        for (Instant t : List.of(Instant.parse("2019-01-01T00:00:00Z"), Fixtures.T0.plus(Duration.ofHours(10)))) {
            AccessRequest shifted = new AccessRequest("r-t", t, base.subject(), base.device(), base.resource(),
                    base.action(), base.network(), base.pepRegion());
            Decision d = decide(live, shifted);
            assertEquals(Outcome.DENY, d.outcome(), "was ALLOW in v0.1 for " + t);
            assertEquals("hard-gate:freshness", d.matchedPolicyId());
        }
        assertThrows(IllegalArgumentException.class, () -> new FreshnessGate(clock, Duration.ZERO));
    }

    @Test
    void b7_firstApplicableShadowingIsRejectedAtLoad() {
        String yaml = """
                version: "t"
                algorithm: FIRST_APPLICABLE
                default: DENY
                policies:
                  - id: P-ENGINEERS
                    when: {roleIn: [engineer]}
                    effect: PERMIT
                  - id: P-NO-UNMANAGED
                    when: {deviceManaged: false}
                    effect: DENY
                """;
        PolicyLoadException e = assertThrows(PolicyLoadException.class, () -> new SafePolicyLoader().load(yaml));
        assertTrue(e.getMessage().contains("shadowed"), e.getMessage());
        // Authoring tools may still open it to show the warning.
        new SafePolicyLoader(false).load(yaml);
    }
}

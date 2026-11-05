package dev.dwarpal.analytics;

import dev.dwarpal.Fixtures;
import dev.dwarpal.behavior.TrustLedger;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.engine.PolicyEngineTest;
import dev.dwarpal.risk.RiskAssessment;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.sim.SimOrganisation;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.OptionalDouble;
import java.util.Set;

import static dev.dwarpal.analytics.SmallWorld.ENGINEERING_READS_PAYROLL;
import static dev.dwarpal.analytics.SmallWorld.INTERNAL_APPS;
import static dev.dwarpal.analytics.SmallWorld.policies;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Red-team pass on part C. Each test first reproduces the weakness as a working probe (what an attacker or
 * a careless caller could do with the naive design), then checks the fix. Numbering matches docs/layer-5/part-c.md.
 */
class AnalyticsRedTeamTest {

    // ---- C1: a What-If with side effects ------------------------------------------------------------------

    @Test
    void c1_replayThroughThePipelineWouldLearnAndAudit_whatIfAcceptsOnlyThePureEngine() {
        SimOrganisation org = SimOrganisation.create(7, 12);
        List<SimOrganisation.Step> traffic = org.traffic();
        List<AccessRequest> requests = traffic.stream().filter(s -> s instanceof SimOrganisation.RequestStep)
                .map(s -> ((SimOrganisation.RequestStep) s).labelled().request()).toList();
        String user = org.users.getFirst().id();
        Instant probeTime = SimOrganisation.DAY_ZERO.plus(java.time.Duration.ofDays(30));

        // Probe: the naive design (replay through any DecisionPoint) given the live pipeline.
        SimOrganisation probeOrg = SimOrganisation.create(7, 12);
        DecisionPoint live = probeOrg.pipeline(probeOrg.engine());
        long auditBefore = probeOrg.sink.lastSequence();
        long loginsBefore = probeOrg.history.logins(user);
        for (AccessRequest r : requests.subList(0, 20)) {
            live.decide(r, SignalSnapshot.empty());
        }
        assertTrue(probeOrg.sink.lastSequence() > auditBefore, "probe: the pipeline writes audit records");
        assertTrue(probeOrg.history.logins(user) > loginsBefore || probeOrg.sink.lastSequence() > auditBefore,
                "probe: the pipeline learns");

        // Fix: WhatIf takes a PolicyEngine (final, pure); nothing in its API accepts a DecisionPoint.
        for (Constructor<?> c : WhatIf.class.getConstructors()) {
            assertFalse(Arrays.asList(c.getParameterTypes()).contains(DecisionPoint.class));
        }
        for (Method m : WhatIf.class.getMethods()) {
            assertFalse(Arrays.asList(m.getParameterTypes()).contains(DecisionPoint.class), m.toString());
        }
        long audit = org.sink.lastSequence();
        long logins = org.history.logins(user);
        int users = org.history.userCount();
        TrustLedger.Trust trust = org.trust.trust(TrustLedger.subjectKey(user), probeTime);
        SignalSnapshot signals = org.signals.snapshot(probeTime);
        WhatIf.Result r = new WhatIf(org.engine(), PolicyEngineTest.POLICIES, org.directory)
                .replay(requests, signals);
        assertEquals(requests.size(), r.replayed());
        assertEquals(audit, org.sink.lastSequence(), "no audit side effect");
        assertEquals(logins, org.history.logins(user), "no learning");
        assertEquals(users, org.history.userCount());
        assertEquals(trust, org.trust.trust(TrustLedger.subjectKey(user), probeTime), "trust untouched");
        assertEquals(signals, org.signals.snapshot(probeTime), "signals untouched");
    }

    // ---- C2: a live freshness gate makes every replay "no change" ------------------------------------------

    @Test
    void c2_freshnessGateWouldHideTheDiff_replayUsesAReplayCopy() {
        PolicyEngine live = SmallWorld.liveEngine(policies("v1", INTERNAL_APPS));
        // Probe (before integration): with the live gate both policies denied everything, so a dangerous edit
        // showed no change. Fix at part C: the run was marked INVALID. Fix at integration: WhatIf replays on
        // PolicyEngine.forReplay(), which drops only the clock-reading gate, so the real diff is measured.
        assertTrue(live.checksFreshness());
        assertFalse(live.forReplay().checksFreshness());
        WhatIf.Result r = new WhatIf(live, policies("v3", INTERNAL_APPS, ENGINEERING_READS_PAYROLL),
                SmallWorld.DIRECTORY).replay(SmallWorld.everything(), SignalSnapshot.empty());
        assertTrue(r.valid(), r.invalid().toString());
        assertTrue(r.gains() > 0, "the payroll grants are visible");
        assertTrue(live.checksFreshness(), "the live engine keeps its gate");
    }

    // ---- C3: classification claimed by the request -----------------------------------------------------------

    @Test
    void c3_requestClaimingLowerClassificationCannotHideARestrictedGrant() {
        // The recorded request says payroll is INTERNAL; the directory (the engine's truth) says RESTRICTED.
        AccessRequest lying = Fixtures.request().id("lie").subject("alice").resource("payroll",
                ResourceKind.PRIVATE_APP, DataClassification.INTERNAL).action(Action.READ).build();
        WhatIf.Result r = new WhatIf(SmallWorld.engine(policies("v1", INTERNAL_APPS)),
                policies("v3", INTERNAL_APPS, ENGINEERING_READS_PAYROLL), SmallWorld.DIRECTORY)
                .replay(List.of(lying), SignalSnapshot.empty());
        assertEquals(1, r.gains());
        assertEquals(DataClassification.INTERNAL.name(),
                lying.resource().classification().name(), "probe: the request's own claim");
        assertEquals(1, r.sensitiveGrants().size(), "flag comes from the directory");
        assertEquals(DataClassification.RESTRICTED, r.sensitiveGrants().getFirst().classification());
    }

    @Test
    void c3b_resourceUnknownToTheDirectoryCountsAsRestricted() {
        // A directory that drops payroll: the engine still sees the request (with a permissive edit) but WhatIf
        // cannot learn the classification, so it must assume the worst.
        dev.dwarpal.pip.AttributeDirectory partial = new dev.dwarpal.pip.AttributeDirectory() {
            @Override
            public java.util.Optional<dev.dwarpal.domain.Subject> subject(String id) {
                return SmallWorld.DIRECTORY.subject(id);
            }

            @Override
            public java.util.Optional<dev.dwarpal.domain.Resource> resource(String id) {
                return id.equals("payroll") ? java.util.Optional.empty() : SmallWorld.DIRECTORY.resource(id);
            }

            @Override
            public boolean isManagedDevice(String id) {
                return SmallWorld.DIRECTORY.isManagedDevice(id);
            }
        };
        WhatIf.Result r = new WhatIf(SmallWorld.engine(policies("v1", INTERNAL_APPS)),
                policies("v3", INTERNAL_APPS, ENGINEERING_READS_PAYROLL), partial)
                .replay(SmallWorld.everything(), SignalSnapshot.empty());
        assertEquals(3, r.sensitiveGrants().size());
    }

    @Test
    void c3c_newAdminGrantIsFlaggedEvenOnAnInternalResource() {
        dev.dwarpal.policy.Policy adminWiki = new dev.dwarpal.policy.Policy("P-04-admin-wiki", "everyone administers the wiki",
                new dev.dwarpal.policy.Conditions.ResourceIdIn(Set.of("wiki")), dev.dwarpal.policy.Effect.PERMIT);
        WhatIf.Result r = new WhatIf(SmallWorld.engine(policies("v1", SmallWorld.ENGINEERING_READS_CONFIDENTIAL)),
                policies("v6", SmallWorld.ENGINEERING_READS_CONFIDENTIAL, adminWiki), SmallWorld.DIRECTORY)
                .replay(SmallWorld.everything(), SignalSnapshot.empty());
        assertTrue(r.sensitiveGrants().stream().anyMatch(c -> c.action() == Action.ADMIN
                && c.classification() == DataClassification.INTERNAL));
    }

    // ---- C4: a report that leaks request data -----------------------------------------------------------------

    @Test
    void c4_reportsCarryNoRequestIdsAddressesDevicesOrEvidence() {
        SimOrganisation org = SimOrganisation.create(7, 12);
        List<SimOrganisation.Result> results = org.run(org.engine(), org.traffic());
        List<AccessRequest> requests = results.stream().map(x -> x.labelled().request()).toList();
        PolicySetEdits edits = new PolicySetEdits();
        WhatIf.Result w = new WhatIf(org.engine(), edits.withoutInternalApps(), org.directory)
                .replay(requests, SignalSnapshot.empty());
        assertTrue(w.losses() > 0, "the edit must change something for the check to mean anything");
        List<Observation> obs = results.stream().map(x -> Observation.of(x.labelled().scenario().name(),
                x.labelled().scenario().attack(), x.decision())).toList();
        DataSource src = DataSource.simulated(org.seed, org.users.size(), 8, requests.size());
        List<String> outputs = new ArrayList<>();
        for (Report rep : List.of(w.report(src), Accuracy.of(obs, costs()).report(src),
                Calibration.report(src, List.of(Calibration.baseRate(obs, 0.001)), Calibration.factors(obs)))) {
            outputs.add(rep.text());
            outputs.add(rep.json());
        }
        for (AccessRequest r : requests) {
            for (String out : outputs) {
                assertFalse(out.contains(r.requestId() + " ") || out.contains("\"" + r.requestId() + "\""),
                        "request id leaked: " + r.requestId());
                assertFalse(out.contains(r.network().ip()), "address leaked: " + r.network().ip());
                assertFalse(out.contains(r.device().id()), "device leaked: " + r.device().id());
            }
        }
        // Observations and What-If changes have no field that could carry these at all.
        for (RecordComponent c : WhatIf.Change.class.getRecordComponents()) {
            assertFalse(Set.of("requestId", "ip", "device", "evidence", "network").contains(c.getName()));
        }
        for (RecordComponent c : Observation.class.getRecordComponents()) {
            assertFalse(Set.of("requestId", "ip", "device", "evidence", "network", "subject").contains(c.getName()));
        }
    }

    // ---- C5: recorder keeps replayable proofs -----------------------------------------------------------------

    @Test
    void c5_recorderStripsSignedEvidence() {
        AccessRequest signed = Fixtures.request().id("s1").authenticated(dev.dwarpal.domain.AuthMethod.WEBAUTHN,
                java.time.Duration.ofSeconds(30)).build();
        // Probe: the live request carries two proofs an attacker could replay within their windows.
        assertTrue(signed.evidence().postureProof().isPresent());
        assertTrue(signed.evidence().authenticationProof().isPresent());
        RequestRecorder rec = new RequestRecorder(SmallWorld.engine(policies("v1", INTERNAL_APPS)), 10, 10);
        Decision d = rec.decide(signed, SignalSnapshot.empty());
        RecordedRequest kept = rec.snapshot().getFirst();
        assertEquals(Evidence.none(), kept.request().evidence());
        assertTrue(kept.hadAuthentication());
        assertEquals(d.deviceVerified(), kept.liveDeviceVerified());
        // A record cannot even be built with evidence.
        assertThrows(IllegalArgumentException.class, () -> new RecordedRequest(signed, Outcome.ALLOW, false, true,
                false, "p", 0.001));
        // And no component of the record type is a proof.
        for (RecordComponent c : RecordedRequest.class.getRecordComponents()) {
            assertNotEquals(SignatureProof.class, c.getType());
        }
    }

    // ---- C6: one subject floods the recorder to evict everyone else --------------------------------------------

    @Test
    void c6_floodingSubjectCannotEvictOthers() {
        PolicyFixture f = new PolicyFixture();
        RequestRecorder rec = new RequestRecorder(f.engine, 100, 10);
        for (int i = 0; i < 50; i++) {
            rec.decide(SmallWorld.request("v" + i, SmallWorld.BOB, SmallWorld.WIKI, Action.READ), SignalSnapshot.empty());
        }
        // Probe: an attacker sends thousands of requests from one account...
        for (int i = 0; i < 5_000; i++) {
            rec.decide(SmallWorld.request("x" + i, SmallWorld.ALICE, SmallWorld.WIKI, Action.READ), SignalSnapshot.empty());
        }
        // ...but holds at most its quota, and bob's traffic is still there.
        List<RecordedRequest> kept = rec.snapshot();
        assertEquals(10, kept.stream().filter(r -> r.request().subject().id().equals("alice")).count());
        assertEquals(10, kept.stream().filter(r -> r.request().subject().id().equals("bob")).count());
        assertEquals(4_990 + 40, rec.stats().refusedQuota());
    }

    // ---- C7: undefined rates shown as zero ------------------------------------------------------------------

    @Test
    void c7_noLegitimateTrafficIsNotZeroFalseAlarms() {
        List<Observation> attacksOnly = List.of(obs("A1", true, Outcome.DENY, 0.9), obs("A2", true, Outcome.ALLOW, 0.01));
        Accuracy a = Accuracy.of(attacksOnly, costs());
        assertTrue(a.flagged().falseAlarmRate().isEmpty());
        assertTrue(a.auc().isEmpty());
        String text = a.report(DataSource.simulated(1, 1, 1, 2)).text();
        assertTrue(text.contains("false-alarm rate: n/a"), text);
        assertTrue(a.report(DataSource.simulated(1, 1, 1, 2)).json().contains("\"value\":null"));
        assertThrows(IllegalArgumentException.class, () -> Accuracy.of(List.of(), costs()));
    }

    // ---- C8: hard-gate denials ranked as most benign ----------------------------------------------------------

    @Test
    void c8_gateDenialsRankAsMostSuspicious() {
        // A Tor login denied by a gate keeps the prior as its posterior.
        Observation gated = obs("A5", true, Outcome.DENY, 0.001);
        Observation legit = obs("L1", false, Outcome.ALLOW, 0.0005);
        Observation legitHigher = obs("L2", false, Outcome.ALLOW, 0.002);
        // Probe: by posterior alone the gated attack ranks below a legitimate request.
        assertTrue(gated.posterior() < legitHigher.posterior());
        // Fix: the score orders by outcome first, so AUC is 1 here.
        assertEquals(1.0, Accuracy.auc(List.of(gated, legit, legitHigher)).getAsDouble(), 1e-12);
    }

    // ---- C9: report line forging and size --------------------------------------------------------------------

    @Test
    void c9_hostileTextCannotForgeReportLines() {
        String rlo = String.valueOf((char) 0x202E);
        String ls = String.valueOf((char) 0x2028);
        String forged = "sim\nAccuracy: detection rate: 1.000000" + rlo;
        DataSource src = new DataSource(DataSource.Kind.RECORDED, forged, -1, 1, 1, 1);
        Report r = Report.builder("t\r\nfake title", src).section("s\nx").text("l\nfake: 1", "v" + ls + "w").build();
        String text = r.text();
        assertFalse(text.contains("\nAccuracy:"), text);
        assertFalse(text.contains("\nfake"), text);
        assertFalse(text.contains(rlo) || text.contains(ls), text);
        assertEquals(6, text.split("\n", -1).length, text);  // title, statement, blank, section, one line, end
        assertFalse(r.json().contains("\n"));
        Report.Builder b = Report.builder("big", src).section("s");
        assertThrows(IllegalStateException.class, () -> {
            for (int i = 0; i <= Report.MAX_LINES; i++) {
                b.count("n", i);
            }
        });
        assertTrue(Report.builder("x", src).section("s").text("v", "a".repeat(10_000)).build().text().length() < 1_000);
    }

    // ---- C10: an edit that could never be installed reported as "no change" -----------------------------------

    @Test
    void c10_proposalWithLinterErrorsIsRefused() {
        dev.dwarpal.policy.Condition same = new dev.dwarpal.policy.Conditions.ResourceIdIn(Set.of("wiki"));
        dev.dwarpal.policy.PolicySet conflicting = policies("bad",
                new dev.dwarpal.policy.Policy("A", "", same, dev.dwarpal.policy.Effect.PERMIT),
                new dev.dwarpal.policy.Policy("B", "", same, dev.dwarpal.policy.Effect.DENY));
        assertThrows(IllegalArgumentException.class, () -> new WhatIf(SmallWorld.engine(policies("v1", INTERNAL_APPS)),
                conflicting, SmallWorld.DIRECTORY));
    }

    // ---- C11: the SOC as a target: a forged audit record feeding analytics -------------------------------------

    @Test
    void c11_forgedAuditRecordsStopTheReaderAndAreNotUsed() {
        AuditDecisionsTest.World w = new AuditDecisionsTest.World();
        w.decideSome(5);
        // The attacker appends a record under their own key claiming P(attack) for everyone was 0.
        w.forgeOne();
        AuditDecisions.Result r = AuditDecisions.read(dev.dwarpal.audit.AuditCursor.fromStart(w.sink, w.key), 1000);
        assertEquals(5, r.entries().size());
        assertTrue(r.problem().isPresent());
        assertTrue(r.source("trail").statement().contains("chain broken after sequence 5"));
    }

    // ---- C12: degenerate inputs to the estimators ------------------------------------------------------------

    @Test
    void c12_estimatorsRefuseImpossibleInputs() {
        assertThrows(IllegalArgumentException.class, () -> Calibration.proportion("p", 5, 3, OptionalDouble.empty()));
        assertThrows(IllegalArgumentException.class, () -> Calibration.proportion("p", -1, 3, OptionalDouble.empty()));
        assertThrows(IllegalArgumentException.class, () -> Calibration.rate("r", 1, Double.NaN, OptionalDouble.empty()));
        assertThrows(IllegalArgumentException.class, () -> Calibration.rate("r", 1, 0, OptionalDouble.empty()));
        assertThrows(IllegalArgumentException.class, () -> Calibration.proportion("p", 1, 3, OptionalDouble.of(2)));
        assertThrows(IllegalArgumentException.class, () -> Calibration.proportion("bad name\n", 1, 3, OptionalDouble.empty()));
        assertThrows(IllegalArgumentException.class, () -> Sensitivity.sweepBeta(costs(), List.of(0.5), new double[0]));
        assertThrows(IllegalArgumentException.class, () -> Sensitivity.sweepBeta(costs(), List.of(0.5),
                new double[Sensitivity.MAX_GRID + 1]));
        assertThrows(IllegalArgumentException.class, () -> Sensitivity.sweepBeta(costs(), List.of(Double.NaN), new double[]{0.1}));
        assertThrows(IllegalArgumentException.class, () -> Sensitivity.sweepBeta(costs(), List.of(0.5), new double[]{1.5}));
        assertThrows(IllegalArgumentException.class, () -> Sensitivity.sweepCost(costs(), Sensitivity.Cost.BREACH,
                List.of(0.5), new double[]{-1}));
        assertThrows(IllegalArgumentException.class, () -> new Observation("s", false, Outcome.ALLOW, false, 2, false, Map.of()));
        assertThrows(IllegalArgumentException.class, () -> new Observation("s", false, Outcome.ALLOW, false, 0.1, false,
                Map.of("f", Double.POSITIVE_INFINITY)));
    }

    // ---- helpers ---------------------------------------------------------------------------------------------

    static CostModel costs() {
        return new CostModel(1000, 1, 20, 0.05);
    }

    static Observation obs(String scenario, boolean attack, Outcome o, double p) {
        return new Observation(scenario, attack, o, false, p, false, Map.of());
    }

    static Decision decision(String id, Outcome o, double p) {
        return new Decision(id, o, false, true, "p", "v",
                new RiskAssessment(List.of(), 0.001, 0, p, List.of()), List.of(), Fixtures.T0);
    }

    private static final class PolicyEngineTestShim {
        DataSource source() {
            return DataSource.simulated(0, 2, 1, 18);
        }
    }

    private static final class PolicyFixture {
        final dev.dwarpal.engine.PolicyEngine engine = SmallWorld.engine(policies("v1", INTERNAL_APPS));
    }

    /** Edits of the reference policy for the simulated organisation. */
    static final class PolicySetEdits {
        dev.dwarpal.policy.PolicySet withoutInternalApps() {
            dev.dwarpal.policy.PolicySet base = PolicyEngineTest.POLICIES;
            return new dev.dwarpal.policy.PolicySet(base.version() + "-edit", base.algorithm(), base.defaultEffect(),
                    base.policies().stream().filter(p -> !p.id().equals("P-01-employees-internal-apps")).toList());
        }
    }
}

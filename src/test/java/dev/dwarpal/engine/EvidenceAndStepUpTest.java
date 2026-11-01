package dev.dwarpal.engine;

import dev.dwarpal.Fixtures;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.domain.ResourceKind;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.EnumMap;
import java.util.Map;

import static dev.dwarpal.engine.PolicyEngineTest.decide;
import static dev.dwarpal.engine.PolicyEngineTest.engine;
import static dev.dwarpal.engine.PolicyEngineTest.fixed;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Signed evidence (device posture, authentication) and MFA-aware step-up, attacked from every side. */
class EvidenceAndStepUpTest {

    private static final DevicePosture HEALTHY = new DevicePosture(true, true, true, AssuranceLevel.AGENT_SIGNED);

    private static Fixtures.RequestBuilder financeOnLedger() {
        return Fixtures.request().roles("finance").posture(HEALTHY)
                .resource("ledger", ResourceKind.PRIVATE_APP, DataClassification.CONFIDENTIAL);
    }

    private static boolean noted(Decision d, String text) {
        return d.reasons().stream().anyMatch(r -> r.contains(text));
    }

    // ---- device posture ------------------------------------------------------------------------

    @Test
    void signedPostureIsBelieved() {
        assertEquals(Outcome.ALLOW, decide(engine(), financeOnLedger().build()).outcome());
    }

    @Test
    void unsignedPostureClaimingAgentSignedIsDowngraded() {
        Decision d = decide(engine(), financeOnLedger().unsignedPosture().build());
        assertEquals(Outcome.DENY, d.outcome());
        assertEquals("P-03-confidential-needs-attested-health", d.matchedPolicyId());
        assertTrue(noted(d, "not supported by evidence; using SELF_REPORTED"), d.reasons().toString());
    }

    @Test
    void postureEditedAfterSigningIsRejected() {
        // Agent signed "AV unhealthy"; attacker flips it to healthy in transit.
        DevicePosture measured = new DevicePosture(true, true, false, AssuranceLevel.AGENT_SIGNED);
        SignatureProof honest = Fixtures.signPosture(Fixtures.DEVICE_AGENT, Fixtures.DEVICE_KEY_ID, "laptop-alice",
                measured, Fixtures.T0);
        AccessRequest base = financeOnLedger().unsignedPosture().build();
        AccessRequest forged = base.withDevice(base.device())
                .withDevice(new dev.dwarpal.domain.Device("laptop-alice", true, HEALTHY));
        forged = withPostureProof(forged, honest);
        Decision d = decide(engine(), forged);
        assertEquals(Outcome.DENY, d.outcome());
        assertTrue(noted(d, "signature does not verify"), d.reasons().toString());
    }

    @Test
    void oneDevicesAgentKeyCannotVouchForAnotherDevice() {
        // A malware-controlled laptop-alice signs a report for laptop-mallory.
        Decision d = decide(engine(), financeOnLedger().device("laptop-mallory").build());
        assertEquals(Outcome.DENY, d.outcome());
        assertTrue(noted(d, "belongs to laptop-alice, not laptop-mallory"), d.reasons().toString());
    }

    @Test
    void identityProviderKeyCannotSignDevicePosture() {
        AccessRequest base = financeOnLedger().unsignedPosture().build();
        SignatureProof idpSigned = Fixtures.signPosture(Fixtures.IDP, Fixtures.IDP_KEY_ID, "laptop-alice", HEALTHY, Fixtures.T0);
        Decision d = decide(engine(), withPostureProof(base, idpSigned));
        assertEquals(Outcome.DENY, d.outcome());
        assertTrue(noted(d, "is a IDENTITY_PROVIDER key, not DEVICE_AGENT"), d.reasons().toString());
    }

    @Test
    void stalePostureReportIsNotBelieved() {
        AccessRequest base = financeOnLedger().unsignedPosture().build();
        SignatureProof old = Fixtures.signPosture(Fixtures.DEVICE_AGENT, Fixtures.DEVICE_KEY_ID, "laptop-alice", HEALTHY,
                Fixtures.T0.minus(Duration.ofDays(2)));
        Decision d = decide(engine(), withPostureProof(base, old));
        assertEquals(Outcome.DENY, d.outcome());
        assertTrue(noted(d, "older than"), d.reasons().toString());
    }

    @Test
    void hardwareAttestationCannotBeClaimedWithAnAgentSignature() {
        AccessRequest r = financeOnLedger()
                .posture(new DevicePosture(true, true, true, AssuranceLevel.HARDWARE_ATTESTED)).build();
        Decision d = decide(engine(), r);
        assertTrue(noted(d, "HARDWARE_ATTESTED not supported by evidence; using AGENT_SIGNED"), d.reasons().toString());
    }

    @Test
    void managedStatusComesFromInventoryNotTheRequest() {
        AccessRequest claimsManaged = Fixtures.request()
                .resource("crm", ResourceKind.SAAS_DATA, DataClassification.INTERNAL).build();
        // Inventory does not list the laptop: the claim "managed=true" is overridden.
        Decision d = engine().withDirectory(new dev.dwarpal.pip.InMemoryDirectory(
                java.util.List.of(claimsManaged.subject()), java.util.List.of(claimsManaged.resource())))
                .decide(claimsManaged, dev.dwarpal.risk.SignalSnapshot.empty());
        assertEquals(Outcome.ALLOW_LIMITED, d.outcome());
        assertTrue(noted(d, "inventory says false"), d.reasons().toString());
    }

    // ---- authentication & step-up --------------------------------------------------------------

    @Test
    void freshWebAuthnSatisfiesAPolicyStepUp() {
        AccessRequest r = Fixtures.request().action(Action.ADMIN).authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(3)).build();
        Decision d = decide(engine(), r);
        assertEquals(Outcome.ALLOW, d.outcome(), d.analystReport());
        assertTrue(noted(d, "step-up satisfied"));
    }

    @Test
    void weakAuthenticatorUnderSuspicionNeedsSomethingStronger() {
        // New ASN (LR 10) -> P(attack) ~ 0.0099. Push (beta 0.30) leaves ~0.003: still above the step-up line.
        AccessRequest push = Fixtures.request().authenticated(AuthMethod.PUSH, Duration.ofMinutes(1)).build();
        Decision d = decide(engine(fixed("new-asn", 10)), push);
        assertEquals(Outcome.STEP_UP, d.outcome());
        assertTrue(noted(d, "stronger authenticator than PUSH"), d.reasons().toString());

        AccessRequest webauthn = Fixtures.request().authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)).build();
        assertEquals(Outcome.ALLOW, decide(engine(fixed("new-asn", 10)), webauthn).outcome());
    }

    @Test
    void staleUnsignedPasswordOnlyOrFutureAuthenticationsDoNotCount() {
        PolicyEngine e = engine();
        Fixtures.RequestBuilder admin = Fixtures.request().action(Action.ADMIN);
        assertEquals(Outcome.STEP_UP, decide(e, Fixtures.request().action(Action.ADMIN)
                .authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(20)).build()).outcome(), "stale");
        assertEquals(Outcome.STEP_UP, decide(e, Fixtures.request().action(Action.ADMIN)
                .authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)).unsignedAuthentication().build()).outcome(), "unsigned");
        assertEquals(Outcome.STEP_UP, decide(e, Fixtures.request().action(Action.ADMIN)
                .authenticated(AuthMethod.PASSWORD, Duration.ofMinutes(1)).build()).outcome(), "password only");
        Decision future = decide(e, Fixtures.request().action(Action.ADMIN)
                .authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(-1)).build());
        assertEquals(Outcome.STEP_UP, future.outcome(), "future-dated authentication");
        assertTrue(admin.build().evidence().authentication().isEmpty());
    }

    @Test
    void anotherUsersAuthenticationProofIsRejected() {
        // Bob's genuine IdP proof replayed on Alice's request.
        AuthenticationContext bobAuth = new AuthenticationContext(AuthMethod.WEBAUTHN, Fixtures.T0.minusSeconds(60));
        SignatureProof bobProof = Fixtures.signAuthentication(Fixtures.IDP, Fixtures.IDP_KEY_ID, "bob", "laptop-alice", bobAuth,
                bobAuth.authenticatedAt());
        AccessRequest base = Fixtures.request().action(Action.ADMIN).build();
        AccessRequest replayed = new AccessRequest(base.requestId(), base.timestamp(), base.subject(), base.device(),
                base.resource(), base.action(), base.network(), base.pepRegion(),
                base.evidence().withAuthentication(bobAuth, bobProof));
        Decision d = decide(engine(), replayed);
        assertEquals(Outcome.STEP_UP, d.outcome());
        assertTrue(noted(d, "authentication signature rejected"), d.reasons().toString());
    }

    @Test
    void stolenAuthenticationProofCannotBeReplayedFromAnotherDevice() {
        // Malware lifts Alice's genuine WebAuthn proof from her laptop; attacker replays it from their own machine.
        AuthenticationContext auth = new AuthenticationContext(AuthMethod.WEBAUTHN, Fixtures.T0.minusSeconds(60));
        SignatureProof stolen = Fixtures.signAuthentication(Fixtures.IDP, Fixtures.IDP_KEY_ID, "alice", "laptop-alice",
                auth, auth.authenticatedAt());
        AccessRequest base = Fixtures.request().device("attacker-box").unsignedPosture().action(Action.ADMIN).build();
        AccessRequest replayed = new AccessRequest(base.requestId(), base.timestamp(), base.subject(), base.device(),
                base.resource(), base.action(), base.network(), base.pepRegion(),
                base.evidence().withAuthentication(auth, stolen));
        Decision d = decide(engine(), replayed);
        assertEquals(Outcome.STEP_UP, d.outcome());
        assertTrue(noted(d, "authentication signature rejected"), d.reasons().toString());
    }

    @Test
    void stepUpNeverLiftsReadOnlyOrAllowsADownload() {
        Fixtures.RequestBuilder saas = Fixtures.request().unmanaged()
                .resource("crm", ResourceKind.SAAS_DATA, DataClassification.INTERNAL)
                .authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1));
        Decision read = decide(engine(fixed("new-asn", 10)), saas.build());
        assertEquals(Outcome.ALLOW_LIMITED, read.outcome());
        assertTrue(read.restricted());
        assertEquals(Outcome.DENY, decide(engine(fixed("new-asn", 10)), saas.action(Action.DOWNLOAD).build()).outcome());
    }

    @Test
    void customBetasChangeTheOutcome() {
        Map<AuthMethod, Double> betas = new EnumMap<>(AuthMethod.class);
        for (AuthMethod m : AuthMethod.values()) {
            betas.put(m, 0.9);   // an organisation that distrusts every second factor
        }
        AssuranceSettings distrustful = new AssuranceSettings(Duration.ofMinutes(15), Duration.ofHours(24), betas);
        PolicyEngine e = PolicyEngine.builder().policySet(PolicyEngineTest.POLICIES).directory(Fixtures.emptyDirectory())
                .keyRing(Fixtures.KEYRING).assurance(distrustful).scorer(fixed("new-asn", 10))
                .aggregator(new dev.dwarpal.risk.BayesianRiskAggregator(0.001, 7))
                .costModel(new dev.dwarpal.decision.CostModel(1000, 1, 20, 0.05)).build();
        AccessRequest r = Fixtures.request().authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)).build();
        assertEquals(Outcome.STEP_UP, decide(e, r).outcome());
    }

    @Test
    void assuranceSettingsAreValidated() {
        Map<AuthMethod, Double> partial = new EnumMap<>(AuthMethod.class);
        partial.put(AuthMethod.WEBAUTHN, 0.01);
        assertThrows(NullPointerException.class,
                () -> new AssuranceSettings(Duration.ofMinutes(1), Duration.ofHours(1), partial));
        assertThrows(IllegalArgumentException.class, () -> new AssuranceSettings(Duration.ZERO, Duration.ofHours(1),
                AssuranceSettings.defaults().bypassProbability()));
        Map<AuthMethod, Double> wrong = new EnumMap<>(AssuranceSettings.defaults().bypassProbability());
        wrong.put(AuthMethod.TOTP, 2.0);
        assertThrows(IllegalArgumentException.class, () -> new AssuranceSettings(Duration.ofMinutes(1), Duration.ofHours(1), wrong));
    }

    private static AccessRequest withPostureProof(AccessRequest r, SignatureProof proof) {
        return new AccessRequest(r.requestId(), r.timestamp(), r.subject(), r.device(), r.resource(), r.action(),
                r.network(), r.pepRegion(), r.evidence().withPostureProof(proof));
    }
}

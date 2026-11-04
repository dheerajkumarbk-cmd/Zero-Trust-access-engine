package dev.dwarpal.session;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.engine.DenyListGate;
import dev.dwarpal.engine.HoneytokenGate;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.engine.PolicyEngineTest;
import dev.dwarpal.pip.AttributeDirectory;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.runtime.DecisionPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static dev.dwarpal.session.SessionFixtures.count;
import static dev.dwarpal.session.SessionResult.Status.GRANTED;
import static dev.dwarpal.session.SessionResult.Status.OPENED;
import static dev.dwarpal.session.SessionResult.Status.REJECTED;
import static dev.dwarpal.session.SessionResult.Status.STEP_UP;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression tests for the second red-team pass on Layer 3 part A. Each test was first a working
 * exploit (R2 to R6 in the threat model).
 */
class SessionHardeningTest {

    private final SessionFixtures.MutableClock clock = new SessionFixtures.MutableClock();
    private final InMemoryAuditSink sink = new InMemoryAuditSink();
    private final KeyPair key = Ed25519.generateKeyPair();
    private volatile DataClassification wikiClass = DataClassification.INTERNAL;
    private PolicyAdministrator pa;
    private int ids;

    /** The directory of the shared fixtures, except that the wiki's classification can change. */
    private final AttributeDirectory directory = new AttributeDirectory() {
        @Override
        public Optional<Subject> subject(String id) {
            return SessionFixtures.DIRECTORY.subject(id);
        }

        @Override
        public Optional<Resource> resource(String id) {
            return id.equals("wiki") ? Optional.of(new Resource("wiki", ResourceKind.PRIVATE_APP, wikiClass))
                    : SessionFixtures.DIRECTORY.resource(id);
        }

        @Override
        public boolean isManagedDevice(String id) {
            return SessionFixtures.DIRECTORY.isManagedDevice(id);
        }
    };

    @BeforeEach
    void setUp() {
        AuditLog audit = SessionFixtures.auditLog(sink);
        PolicyEngine engine = PolicyEngine.builder().policySet(PolicyEngineTest.POLICIES).directory(directory)
                .keyRing(Fixtures.KEYRING).gate(new HoneytokenGate()).gate(new DenyListGate()).scorers(List.of())
                .aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                .costModel(new CostModel(1000, 1, 20, 0.05)).build();
        DecisionPoint pdp = DecisionPipeline.continuous(engine, audit, clock);
        pa = PolicyAdministrator.builder(audit).opening(pdp).continuous(pdp).directory(directory)
                .keyRing(Fixtures.KEYRING).clock(clock).allowLoginWithoutMfa().build();
    }

    private Fixtures.RequestBuilder alice() {
        return Fixtures.request().id("h-" + (++ids)).at(clock.now());
    }

    private SessionResult open(KeyPair k, AccessRequest r) {
        return pa.open(r, SignalSnapshot.empty(), k.getPublic(), SessionFixtures.bind(r, k, clock.now()));
    }

    private SessionResult use(SessionGrant g, AccessRequest r) {
        return pa.use(g.token(), SessionFixtures.prove(key, g.sessionId(), r, clock.now()), r, SignalSnapshot.empty());
    }

    @Test
    void r2_reclassifyingAResourceUpwardsShortensItsOpenSessions() {
        SessionGrant g = open(key, alice().build()).grant().orElseThrow();
        wikiClass = DataClassification.CONFIDENTIAL;
        for (int i = 0; i < 2; i++) {
            clock.advance(Duration.ofMinutes(20));
            assertEquals(GRANTED, use(g, alice().build()).status(), "Alice is in finance: P-02 still grants");
        }
        clock.advance(Duration.ofMinutes(20));
        assertEquals(STEP_UP, use(g, alice().build()).status(), "1 h for CONFIDENTIAL, not the 4 h of INTERNAL");
    }

    @Test
    void r3_requestsDatedAwayFromTheClockAreRefused() {
        SessionResult backdated = open(key, alice().at(clock.now().minus(Duration.ofHours(3))).build());
        assertEquals(REJECTED, backdated.status());
        assertTrue(backdated.decision().isEmpty(), "refused before the engine: not decided, not learned");
        SessionGrant g = open(key, alice().build()).grant().orElseThrow();
        assertEquals(REJECTED, use(g, alice().at(clock.now().plus(Duration.ofMinutes(5))).build()).status());
        assertEquals(GRANTED, use(g, alice().at(clock.now().plus(Duration.ofSeconds(90))).build()).status(),
                "within the 2 min allowance");
    }

    @Test
    void r4_aCapturedMfaProofCannotBeReplayedWithAnotherKey() {
        KeyPair victim = Ed25519.generateKeyPair();
        KeyPair attacker = Ed25519.generateKeyPair();
        // Phone without an agent: no posture, so no device binding. The MFA proof is the only evidence.
        AccessRequest captured = alice().device("phone-alice").unmanaged().unsignedPosture()
                .authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(2)).boundTo(victim.getPublic()).build();
        SessionResult replay = pa.open(captured, SignalSnapshot.empty(), attacker.getPublic());
        assertEquals(REJECTED, replay.status());
        assertTrue(replay.decision().isEmpty(), "refused before the engine");
        assertEquals(1, count(sink, "SESSION_MFA_NOT_BOUND"));

        AccessRequest unbound = alice().device("phone-alice").unmanaged().unsignedPosture()
                .authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(2)).build();
        assertEquals(REJECTED, pa.open(unbound, SignalSnapshot.empty(), attacker.getPublic()).status(),
                "an MFA proof bound to no key is not accepted by the Policy Administrator");

        assertEquals(OPENED, pa.open(captured, SignalSnapshot.empty(), victim.getPublic()).status(),
                "the real client, holding the key the proof names, gets in");
    }

    @Test
    void r4_insideASessionAnMfaProofForAnotherKeyIsRefused() {
        SessionGrant g = open(key, alice().build()).grant().orElseThrow();
        KeyPair other = Ed25519.generateKeyPair();
        SessionResult r = use(g, alice().authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1))
                .boundTo(other.getPublic()).build());
        assertEquals(REJECTED, r.status());
        assertEquals(GRANTED, use(g, alice().build()).status(), "the session itself is unaffected");
    }

    @Test
    void r5_noStandingAdminEvenWithStrongMfa() {
        // Alice is an engineer with finance rights, but not an administrator.
        AccessRequest admin = alice().action(Action.ADMIN).authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1))
                .boundTo(key.getPublic()).build();
        SessionResult r = open(key, admin);
        assertEquals(SessionResult.Status.DENIED, r.status(), r.reason());
    }

    @Test
    void r6_deadSessionsDoNotCountTowardsTheLimitAndAreReportedAsExpired() {
        for (int i = 0; i < 5; i++) {
            assertEquals(OPENED, open(key, alice().build()).status());
        }
        clock.advance(Duration.ofHours(1));
        assertEquals(OPENED, open(key, alice().build()).status());
        assertEquals(1, pa.activeSessions());
        assertEquals(5, count(sink, "SESSION_EXPIRED"));
        assertTrue(sink.snapshot().stream().noneMatch(x -> x.payloadJson().contains("per-subject")));
    }

    @Test
    void purgingRemovesAbandonedSessionsAndAuditsThem() {
        open(key, alice().build());
        open(key, alice().subject("carol").device("laptop-carol").unsignedPosture().build());
        clock.advance(Duration.ofMinutes(31));
        assertEquals(2, pa.purgeExpired());
        assertEquals(0, pa.activeSessions());
        assertEquals(2, count(sink, "SESSION_EXPIRED"));
    }

    @Test
    void aFloodOfRefusalsCannotFloodTheAuditTrail() {
        SessionGrant g = open(key, alice().build()).grant().orElseThrow();
        KeyPair thief = Ed25519.generateKeyPair();
        for (int i = 0; i < 50; i++) {
            AccessRequest r = alice().build();
            pa.use(g.token(), SessionFixtures.prove(thief, g.sessionId(), r, clock.now()), r, SignalSnapshot.empty());
        }
        assertEquals(20, count(sink, "SESSION_PROOF_FAILED"), "20 per minute per type and subject");
        assertEquals(30, pa.suppressedAuditEvents());
        clock.advance(Duration.ofMinutes(1));
        AccessRequest r = alice().build();
        pa.use(g.token(), SessionFixtures.prove(thief, g.sessionId(), r, clock.now()), r, SignalSnapshot.empty());
        assertEquals(21, count(sink, "SESSION_PROOF_FAILED"), "a new minute, a new allowance");
    }
}

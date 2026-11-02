package dev.dwarpal.session;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.policy.SafePolicyLoader;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.runtime.DecisionPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static dev.dwarpal.session.SessionFixtures.count;
import static dev.dwarpal.session.SessionFixtures.prove;
import static dev.dwarpal.session.SessionResult.Status.DENIED;
import static dev.dwarpal.session.SessionResult.Status.GRANTED;
import static dev.dwarpal.session.SessionResult.Status.GRANTED_LIMITED;
import static dev.dwarpal.session.SessionResult.Status.OPENED;
import static dev.dwarpal.session.SessionResult.Status.REJECTED;
import static dev.dwarpal.session.SessionResult.Status.STEP_UP;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyAdministratorTest {

    private final SessionFixtures.MutableClock clock = new SessionFixtures.MutableClock();
    private final InMemoryAuditSink sink = new InMemoryAuditSink();
    private final KeyPair key = Ed25519.generateKeyPair();
    private PolicyAdministrator pa;
    private int ids;

    @BeforeEach
    void setUp() {
        pa = administrator(SessionFixtures.engine(), SessionLimits.defaults());
    }

    private PolicyAdministrator administrator(PolicyEngine engine, SessionLimits limits) {
        AuditLog audit = SessionFixtures.auditLog(sink);
        DecisionPoint pdp = DecisionPipeline.continuous(engine, audit, clock);
        return PolicyAdministrator.builder(audit).opening(pdp).continuous(pdp).directory(SessionFixtures.DIRECTORY)
                .keyRing(Fixtures.KEYRING).limits(limits).clock(clock).build();
    }

    /** Alice on her laptop, reading the wiki, now. */
    private Fixtures.RequestBuilder alice() {
        return Fixtures.request().id("r-" + (++ids)).at(clock.now());
    }

    private SessionGrant open(KeyPair k, Fixtures.RequestBuilder r) {
        SessionResult res = openRaw(k, r.build());
        assertEquals(OPENED, res.status(), res.reason());
        return res.grant().orElseThrow();
    }

    /** What a client with an endpoint agent sends: the login, its session public key, the agent's binding. */
    private SessionResult openRaw(KeyPair k, AccessRequest req) {
        return pa.open(req, SignalSnapshot.empty(), k.getPublic(), SessionFixtures.bind(req, k, clock.now()));
    }

    private SessionResult use(SessionGrant g, Fixtures.RequestBuilder r) {
        AccessRequest req = r.build();
        return pa.use(g.token(), prove(key, g.sessionId(), req, clock.now()), req, SignalSnapshot.empty());
    }

    private static SessionLimits limits(Duration idle, Duration absolute, Duration reauth, int perSubject, int max) {
        Map<DataClassification, Duration> m = new EnumMap<>(DataClassification.class);
        for (DataClassification c : DataClassification.values()) {
            m.put(c, reauth);
        }
        return new SessionLimits(idle, absolute, m, perSubject, max, Duration.ofMinutes(2), 0.05);
    }

    @Test
    void anAllowedLoginOpensASessionThatCanBeUsed() {
        SessionGrant g = open(key, alice());
        assertEquals(43, g.token().length());
        assertFalse(g.toString().contains(g.token()), "the token must never appear in toString");
        assertFalse(g.restricted());
        assertEquals(SessionFixtures.T.plus(Duration.ofHours(4)), g.reauthDue(), "INTERNAL: 4 h");

        assertEquals(GRANTED, use(g, alice()).status());
        assertEquals(1, pa.activeSessions());
        assertEquals(1, count(sink, "SESSION_OPENED"));
        for (AuditRecord r : sink.snapshot()) {
            assertFalse(r.payloadJson().contains(g.token()), "the audit trail must never hold a token");
        }
    }

    @Test
    void aReplayedLoginCannotOpenASessionForAnotherKey() {
        // Red-team finding: a captured login carries a posture report the agent signed (valid 24 h).
        // Replayed with a new request id and the attacker's own session key, it used to open a session
        // that the engine counted as coming from Alice's verified laptop.
        AccessRequest captured = alice().build();
        KeyPair attacker = Ed25519.generateKeyPair();
        AccessRequest replay = new AccessRequest("attacker-1", captured.timestamp(), captured.subject(),
                captured.device(), captured.resource(), captured.action(), captured.network(), captured.pepRegion(),
                captured.evidence());
        int recordsBefore = sink.snapshot().size();
        SessionResult r = pa.open(replay, SignalSnapshot.empty(), attacker.getPublic());
        assertEquals(REJECTED, r.status());
        assertTrue(r.decision().isEmpty(), "refused before the engine: nothing decided, nothing learned");
        assertEquals(recordsBefore + 1, sink.snapshot().size());
        assertEquals(1, count(sink, "SESSION_BINDING_FAILED"));

        // The victim's own binding names the victim's session key, so it cannot be reused for the attacker's.
        KeyPair victimKey = Ed25519.generateKeyPair();
        SignatureProof victimBinding = SessionFixtures.bind(captured, victimKey, clock.now());
        assertEquals(REJECTED, pa.open(captured, SignalSnapshot.empty(), attacker.getPublic(), victimBinding).status());
        assertEquals(OPENED, pa.open(captured, SignalSnapshot.empty(), victimKey.getPublic(), victimBinding).status());
        assertEquals(REJECTED, pa.open(captured, SignalSnapshot.empty(), victimKey.getPublic(), victimBinding).status(),
                "a binding opens one session only");
    }

    @Test
    void aBindingMustBeFreshAndFromThisDevicesAgent() {
        AccessRequest login = alice().build();
        SignatureProof stale = SessionFixtures.bind(login, key, clock.now().minus(Duration.ofMinutes(3)));
        assertEquals(REJECTED, pa.open(login, SignalSnapshot.empty(), key.getPublic(), stale).status());
        SignatureProof byIdp = new SignatureProof(Fixtures.IDP_KEY_ID, clock.now(), Ed25519.sign(Fixtures.IDP.getPrivate(),
                dev.dwarpal.crypto.SignedMessages.sessionBinding(login.device().id(), login.requestId(),
                        dev.dwarpal.crypto.Digests.thumbprint(key.getPublic()), clock.now())));
        assertEquals(REJECTED, pa.open(login, SignalSnapshot.empty(), key.getPublic(), byIdp).status(),
                "only a DEVICE_AGENT key bound to this device may bind");
        // A device without an agent sends no posture proof: no binding needed, and no device credit given.
        SessionResult agentless = pa.open(alice().unsignedPosture().build(), SignalSnapshot.empty(), key.getPublic());
        assertEquals(OPENED, agentless.status());
        assertFalse(agentless.decision().orElseThrow().deviceVerified());
    }

    @Test
    void aStolenTokenIsUselessWithoutTheSessionKey() {
        SessionGrant g = open(key, alice());
        KeyPair thief = Ed25519.generateKeyPair();
        AccessRequest req = alice().build();
        SessionResult r = pa.use(g.token(), prove(thief, g.sessionId(), req, clock.now()), req, SignalSnapshot.empty());
        assertEquals(REJECTED, r.status());
        assertTrue(r.reason().contains("proof of possession failed"), r.reason());
        assertEquals(1, count(sink, "SESSION_PROOF_FAILED"));

        AccessRequest bare = alice().build();
        assertEquals(REJECTED, pa.use(g.token(), null, bare, SignalSnapshot.empty()).status(), "no proof at all");
        assertEquals(GRANTED, use(g, alice()).status(), "the real client is unaffected");
    }

    @Test
    void aCapturedRequestCannotBeReplayed() {
        SessionGrant g = open(key, alice());
        AccessRequest req = alice().build();
        SignatureProof proof = prove(key, g.sessionId(), req, clock.now());
        assertEquals(GRANTED, pa.use(g.token(), proof, req, SignalSnapshot.empty()).status());
        clock.advance(Duration.ofSeconds(30));
        SessionResult again = pa.use(g.token(), proof, req, SignalSnapshot.empty());
        assertEquals(REJECTED, again.status());
        assertTrue(again.reason().contains("replay"), again.reason());
        assertEquals(1, count(sink, "SESSION_REPLAY_REFUSED"));
    }

    @Test
    void aProofCannotBeMovedToADifferentRequest() {
        SessionGrant g = open(key, alice());
        AccessRequest read = alice().build();
        SignatureProof proofForRead = prove(key, g.sessionId(), read, clock.now());
        AccessRequest write = alice().id(read.requestId()).action(Action.WRITE).build();
        assertEquals(REJECTED, pa.use(g.token(), proofForRead, write, SignalSnapshot.empty()).status());
    }

    @Test
    void staleFutureAndMislabelledProofsAreRejected() {
        SessionGrant g = open(key, alice());
        AccessRequest r1 = alice().build();
        assertEquals(REJECTED, pa.use(g.token(), prove(key, g.sessionId(), r1, clock.now().minus(Duration.ofMinutes(3))),
                r1, SignalSnapshot.empty()).status(), "older than 2 minutes");
        AccessRequest r2 = alice().build();
        assertEquals(REJECTED, pa.use(g.token(), prove(key, g.sessionId(), r2, clock.now().plus(Duration.ofMinutes(5))),
                r2, SignalSnapshot.empty()).status(), "dated in the future");
        AccessRequest r3 = alice().build();
        assertEquals(REJECTED, pa.use(g.token(), prove(key, "s-other", r3, clock.now()), r3,
                SignalSnapshot.empty()).status(), "proof names another session");
        assertEquals(GRANTED, use(g, alice()).status());
    }

    @Test
    void aTokenPresentedFromAnotherDeviceEndsTheSession() {
        SessionGrant g = open(key, alice());
        SessionResult r = use(g, alice().device("laptop-mallory"));
        assertEquals(REJECTED, r.status());
        assertTrue(r.sessionEnded());
        assertEquals(1, count(sink, "SESSION_REVOKED"));
        assertEquals(REJECTED, use(g, alice()).status(), "the session is gone");
        assertEquals(0, pa.activeSessions());
    }

    @Test
    void aTokenForAnotherResourceIsRefusedButTheSessionSurvives() {
        SessionGrant g = open(key, alice());
        SessionResult r = use(g, alice().resource("drive", ResourceKind.SAAS_DATA, DataClassification.INTERNAL));
        assertEquals(REJECTED, r.status());
        assertFalse(r.sessionEnded());
        assertEquals(GRANTED, use(g, alice()).status());
    }

    @Test
    void anIdleSessionEnds() {
        SessionGrant g = open(key, alice());
        clock.advance(Duration.ofMinutes(29));
        assertEquals(GRANTED, use(g, alice()).status(), "29 min idle is fine");
        clock.advance(Duration.ofMinutes(30));
        SessionResult r = use(g, alice());
        assertEquals(REJECTED, r.status());
        assertTrue(r.sessionEnded());
        assertEquals(1, count(sink, "SESSION_EXPIRED"));
    }

    @Test
    void noSessionOutlivesItsAbsoluteLifetime() {
        pa = administrator(SessionFixtures.engine(),
                limits(Duration.ofMinutes(30), Duration.ofHours(1), Duration.ofHours(8), 5, 100));
        SessionGrant g = open(key, alice());
        for (int i = 0; i < 2; i++) {
            clock.advance(Duration.ofMinutes(20));
            assertEquals(GRANTED, use(g, alice()).status());
        }
        clock.advance(Duration.ofMinutes(20));
        SessionResult r = use(g, alice());
        assertEquals(REJECTED, r.status(), "busy, but 1 h is the limit");
        assertTrue(r.reason().contains("absolute lifetime"), r.reason());
    }

    @Test
    void afterTheReauthIntervalOnlyAFreshVerifiedMfaContinuesTheSession() {
        SessionGrant g = open(key, alice());
        for (int i = 0; i < 11; i++) {
            clock.advance(Duration.ofMinutes(20));
            assertEquals(GRANTED, use(g, alice()).status(), "3 h 40 min in");
        }
        clock.advance(Duration.ofMinutes(20));
        assertEquals(STEP_UP, use(g, alice()).status(), "4 h: re-authentication due");
        assertEquals(STEP_UP, use(g, alice().authenticated(AuthMethod.PASSWORD, Duration.ofMinutes(1)).boundTo(key.getPublic())).status(),
                "a password is not a step-up");
        assertEquals(STEP_UP, use(g, alice().authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(20)).boundTo(key.getPublic())).status(),
                "20 min old MFA is stale");
        assertEquals(STEP_UP, use(g, alice().authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)).boundTo(key.getPublic())
                .unsignedAuthentication()).status(), "unsigned MFA claim");

        assertEquals(GRANTED, use(g, alice().authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)).boundTo(key.getPublic())).status());
        clock.advance(Duration.ofMinutes(20));
        assertEquals(GRANTED, use(g, alice()).status(), "the re-authentication restarted the 4 h clock");
    }

    @Test
    void mfaProvedOnAnotherDeviceDoesNotReauthenticateThisSession() {
        SessionGrant g = open(key, alice());
        for (int i = 0; i < 12; i++) {
            clock.advance(Duration.ofMinutes(20));
            use(g, alice());
        }
        // The proof is bound to laptop-mallory; the request comes from laptop-alice.
        AccessRequest req = alice().authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)).boundTo(key.getPublic()).build();
        AccessRequest elsewhere = alice().device("laptop-mallory").authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)).boundTo(key.getPublic()).build();
        AccessRequest forged = new AccessRequest(req.requestId(), req.timestamp(), req.subject(), req.device(),
                req.resource(), req.action(), req.network(), req.pepRegion(), elsewhere.evidence()
                .withPostureProof(req.evidence().postureProof().orElseThrow()));
        SessionResult r = pa.use(g.token(), prove(key, g.sessionId(), forged, clock.now()), forged, SignalSnapshot.empty());
        assertEquals(STEP_UP, r.status());
    }

    @Test
    void aReadOnlySessionMayReadButNotDownloadAndSurvivesTheAttempt() {
        Fixtures.RequestBuilder phone = alice().device("phone-alice").unmanaged().unsignedPosture()
                .resource("drive", ResourceKind.SAAS_DATA, DataClassification.INTERNAL);
        SessionGrant g = open(key, phone);
        assertTrue(g.restricted());

        assertEquals(GRANTED_LIMITED, use(g, alice().device("phone-alice").unmanaged().unsignedPosture()
                .resource("drive", ResourceKind.SAAS_DATA, DataClassification.INTERNAL)).status());
        SessionResult download = use(g, alice().device("phone-alice").unmanaged().unsignedPosture()
                .resource("drive", ResourceKind.SAAS_DATA, DataClassification.INTERNAL).action(Action.DOWNLOAD));
        assertEquals(DENIED, download.status());
        assertFalse(download.sessionEnded());
        assertEquals(GRANTED_LIMITED, use(g, alice().device("phone-alice").unmanaged().unsignedPosture()
                .resource("drive", ResourceKind.SAAS_DATA, DataClassification.INTERNAL)).status());
    }

    @Test
    void continuousEvaluationRevokesTheMomentADeviceIsDenyListed() {
        SessionGrant g = open(key, alice());
        AccessRequest req = alice().build();
        SignalSnapshot incident = new SignalSnapshot(Set.of(), Set.of(), Set.of("laptop-alice"), Set.of());
        SessionResult r = pa.use(g.token(), prove(key, g.sessionId(), req, clock.now()), req, incident);
        assertEquals(DENIED, r.status());
        assertTrue(r.sessionEnded());
        assertEquals(REJECTED, use(g, alice()).status());
        assertEquals(1, count(sink, "SESSION_REVOKED"));
    }

    @Test
    void anActionSpecificPolicyDenialDoesNotEndTheSession() {
        String yaml = String.join(System.lineSeparator(),
                "version: \"t-1\"",
                "algorithm: DENY_OVERRIDES",
                "default: DENY",
                "policies:",
                "  - id: P-01",
                "    description: Humans read internal apps.",
                "    when:",
                "      all:",
                "        - subjectType: HUMAN",
                "        - classificationAtMost: INTERNAL",
                "    effect: PERMIT",
                "  - id: P-50",
                "    description: Nobody edits the wiki.",
                "    when:",
                "      actionIn: [WRITE]",
                "    effect: DENY");
        pa = administrator(SessionFixtures.engine(new SafePolicyLoader().load(yaml)), SessionLimits.defaults());
        SessionGrant g = open(key, alice());
        SessionResult write = use(g, alice().action(Action.WRITE));
        assertEquals(DENIED, write.status());
        assertFalse(write.sessionEnded(), "low-risk denial of one action keeps the session");
        assertEquals(GRANTED, use(g, alice()).status());
    }

    @Test
    void revocationBySessionSubjectOrDeviceIsImmediateAndAudited() {
        SessionGrant a1 = open(key, alice());
        SessionGrant a2 = open(key, alice());
        SessionGrant c1 = open(key, alice().subject("carol").device("laptop-carol").unsignedPosture());

        assertEquals(1, pa.revokeSession(a1.sessionId(), "soc-analyst", "suspicious activity"));
        assertEquals(REJECTED, use(a1, alice()).status());
        assertEquals(GRANTED, use(a2, alice()).status());

        assertEquals(1, pa.revokeSubject("alice", "hr-system", "account disabled"));
        assertEquals(REJECTED, use(a2, alice()).status());

        assertEquals(1, pa.revokeDevice("laptop-carol", "soc-analyst", "device reported stolen"));
        assertEquals(0, pa.revokeDevice("laptop-carol", "soc-analyst", "again"));
        assertEquals(REJECTED, use(c1, alice().subject("carol").device("laptop-carol").unsignedPosture()).status());
        assertEquals(3, count(sink, "SESSION_REVOKED"));
        assertEquals(0, pa.activeSessions());
    }

    @Test
    void openingOneSessionTooManyClosesTheOldest() {
        pa = administrator(SessionFixtures.engine(),
                limits(Duration.ofMinutes(30), Duration.ofHours(10), Duration.ofHours(4), 2, 100));
        SessionGrant first = open(key, alice());
        SessionGrant second = open(key, alice());
        SessionGrant third = open(key, alice());
        assertEquals(REJECTED, use(first, alice()).status());
        assertEquals(GRANTED, use(second, alice()).status());
        assertEquals(GRANTED, use(third, alice()).status());
        assertTrue(sink.snapshot().stream().anyMatch(r -> r.payloadJson().contains("per-subject session limit")));
    }

    @Test
    void aFullStoreRefusesNewSessionsUntilOldOnesExpire() {
        pa = administrator(SessionFixtures.engine(),
                limits(Duration.ofMinutes(30), Duration.ofHours(10), Duration.ofHours(4), 5, 1));
        open(key, alice());
        SessionResult carol = pa.open(alice().subject("carol").device("laptop-carol").unsignedPosture().build(),
                SignalSnapshot.empty(), key.getPublic());
        assertEquals(DENIED, carol.status());
        assertTrue(carol.reason().contains("capacity"), carol.reason());
        clock.advance(Duration.ofMinutes(31));
        open(key, alice().subject("carol").device("laptop-carol").unsignedPosture());
    }

    @Test
    void noAuditNoSession() {
        AuditLog broken = new AuditLog(SessionFixtures.auditKey(), record -> {
            throw new IllegalStateException("disk full");
        });
        PolicyEngine engine = SessionFixtures.engine();
        pa = PolicyAdministrator.builder(broken).opening(engine).continuous(engine).directory(SessionFixtures.DIRECTORY)
                .keyRing(Fixtures.KEYRING).clock(clock).build();
        SessionResult r = openRaw(key, alice().build());
        assertEquals(DENIED, r.status());
        assertTrue(r.reason().contains("no audit, no session"), r.reason());
        assertEquals(0, pa.activeSessions());
    }

    @Test
    void restrictedDataNeedsMfaToOpenAndThenEveryFifteenMinutes() {
        Fixtures.RequestBuilder vault = alice().resource("vault", ResourceKind.PRIVATE_APP, DataClassification.RESTRICTED);
        SessionResult first = openRaw(key, vault.build());
        assertEquals(STEP_UP, first.status());
        assertEquals(0, pa.activeSessions());

        SessionGrant g = open(key, alice().resource("vault", ResourceKind.PRIVATE_APP, DataClassification.RESTRICTED)
                .authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(2)).boundTo(key.getPublic()));
        assertEquals(clock.now().minus(Duration.ofMinutes(2)).plus(Duration.ofMinutes(15)), g.reauthDue());
        clock.advance(Duration.ofMinutes(10));
        // Session re-authentication is not due yet (T+13), but policy P-04 wants proof on every request.
        SessionResult bare = use(g, alice().resource("vault", ResourceKind.PRIVATE_APP, DataClassification.RESTRICTED));
        assertEquals(STEP_UP, bare.status());
        assertTrue(bare.decision().isPresent(), "this STEP_UP came from the engine (continuous evaluation)");
        assertEquals(GRANTED, use(g, alice().resource("vault", ResourceKind.PRIVATE_APP, DataClassification.RESTRICTED)
                .authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)).boundTo(key.getPublic())).status());
        clock.advance(Duration.ofMinutes(16));
        SessionResult due = use(g, alice().resource("vault", ResourceKind.PRIVATE_APP, DataClassification.RESTRICTED));
        assertEquals(STEP_UP, due.status());
        assertTrue(due.decision().isEmpty(), "this STEP_UP came from the session's 15 min re-authentication");
    }

    @Test
    void aDeniedLoginOpensNothing() {
        SessionResult r = openRaw(key, alice().subject("mallory").build());
        assertEquals(DENIED, r.status());
        assertTrue(r.grant().isEmpty());
        assertEquals(0, pa.activeSessions());
    }

    @Test
    void onlyEd25519SessionKeysAreAccepted() throws Exception {
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(256);
        SessionResult r = pa.open(alice().build(), SignalSnapshot.empty(), ec.generateKeyPair().getPublic());
        assertEquals(REJECTED, r.status());
    }

    @Test
    void garbageTokensAreRefusedWithoutErrors() {
        SessionGrant g = open(key, alice());
        Random rnd = new Random(7);
        String alphabet = "ABCxyz019-_+/=. :\"'<>";
        for (int i = 0; i < 2000; i++) {
            StringBuilder sb = new StringBuilder();
            int len = rnd.nextInt(3) == 0 ? 43 : rnd.nextInt(100);
            for (int j = 0; j < len; j++) {
                sb.append(alphabet.charAt(rnd.nextInt(alphabet.length())));
            }
            AccessRequest req = alice().build();
            SessionResult r = pa.use(sb.toString(), prove(key, g.sessionId(), req, clock.now()), req,
                    SignalSnapshot.empty());
            assertEquals(REJECTED, r.status());
        }
        assertEquals(REJECTED, pa.use(null, null, alice().build(), SignalSnapshot.empty()).status());
        assertTrue(pa.malformedTokens() + pa.unknownTokens() >= 2001);
        assertEquals(GRANTED, use(g, alice()).status());
    }

    @Test
    void parallelUsesAreAllServedAndAParallelReplayWinsOnlyOnce() throws Exception {
        SessionGrant g = open(key, alice());
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Callable<SessionResult>> distinct = new java.util.ArrayList<>();
            for (int i = 0; i < 200; i++) {
                AccessRequest req = alice().build();
                SignatureProof p = prove(key, g.sessionId(), req, clock.now());
                distinct.add(() -> pa.use(g.token(), p, req, SignalSnapshot.empty()));
            }
            for (Future<SessionResult> f : pool.invokeAll(distinct)) {
                assertEquals(GRANTED, f.get().status());
            }

            AccessRequest req = alice().build();
            SignatureProof p = prove(key, g.sessionId(), req, clock.now());
            List<Callable<SessionResult>> same = java.util.Collections.nCopies(50,
                    () -> pa.use(g.token(), p, req, SignalSnapshot.empty()));
            int granted = 0;
            for (Future<SessionResult> f : pool.invokeAll(same)) {
                if (f.get().status() == GRANTED) {
                    granted++;
                }
            }
            assertEquals(1, granted, "one request id, one use");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void theStolenUnlockedLaptopIsCutOffAtTheNextReauthentication() {
        // Alice logs in at 09:30 and leaves her laptop unlocked at 10:00. Someone else sits down and keeps
        // the session busy. Layers 1-2 cannot tell them apart: same laptop, network, hours.
        SessionGrant g = open(key, alice());
        clock.advance(Duration.ofMinutes(20));
        assertEquals(GRANTED, use(g, alice()).status(), "Alice working at 09:50");
        clock.advance(Duration.ofMinutes(10));
        int attackerUses = 0;
        SessionResult last;
        do {
            clock.advance(Duration.ofMinutes(10));
            last = use(g, alice());
            if (last.status() == GRANTED) {
                attackerUses++;
            }
        } while (last.status() == GRANTED && attackerUses < 100);
        assertEquals(STEP_UP, last.status());
        Instant cutOff = clock.now();
        assertEquals(SessionFixtures.T.plus(Duration.ofHours(4)), cutOff, "window ends at the 4 h re-authentication");
        // Without Alice's authenticator the session cannot continue; a password is not enough.
        assertEquals(STEP_UP, use(g, alice().authenticated(AuthMethod.PASSWORD, Duration.ofMinutes(1)).boundTo(key.getPublic())).status());
        // The window is bounded by the classification: 1 h for CONFIDENTIAL, 15 min for RESTRICTED.
        assertTrue(Duration.between(SessionFixtures.T, cutOff).compareTo(Duration.ofHours(4)) <= 0);
    }

    @Test
    void aSessionUseMeetsTheTwentyMillisecondTarget() {
        SessionGrant g = open(key, alice());
        int n = 2000;
        AccessRequest[] reqs = new AccessRequest[n];
        SignatureProof[] proofs = new SignatureProof[n];
        for (int i = 0; i < n; i++) {
            reqs[i] = alice().build();
            proofs[i] = prove(key, g.sessionId(), reqs[i], clock.now());
        }
        long[] nanos = new long[n];
        for (int i = 0; i < n; i++) {
            long t0 = System.nanoTime();
            SessionResult r = pa.use(g.token(), proofs[i], reqs[i], SignalSnapshot.empty());
            nanos[i] = System.nanoTime() - t0;
            assertEquals(GRANTED, r.status());
        }
        java.util.Arrays.sort(nanos);
        double p50 = nanos[n / 2] / 1e6;
        double p99 = nanos[(int) (n * 0.99)] / 1e6;
        System.out.printf(java.util.Locale.ROOT,
                "LATENCY session use (token, possession proof, replay check, engine, audit): p50=%.3f ms p99=%.3f ms%n",
                p50, p99);
        assertTrue(p99 < 20, "p99 " + p99 + " ms");
    }

    @Test
    void aLaptopLeftAloneForHalfAnHourHasNoSessionLeftToSteal() {
        SessionGrant g = open(key, alice());
        clock.advance(Duration.ofMinutes(40));
        SessionResult r = use(g, alice());
        assertEquals(REJECTED, r.status());
        assertTrue(r.reason().contains("idle"), r.reason());
    }
}

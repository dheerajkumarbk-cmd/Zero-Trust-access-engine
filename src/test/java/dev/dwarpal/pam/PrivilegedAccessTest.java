package dev.dwarpal.pam;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.crypto.TrustedKey;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.domain.SubjectType;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.engine.PolicyEngineTest;
import dev.dwarpal.pip.InMemoryDirectory;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 3 part B: no standing admin, just-in-time elevation, break-glass, rate limits. */
class PrivilegedAccessTest {

    private static final Instant T = Fixtures.T0;
    private static final KeyPair BOB = Ed25519.generateKeyPair();
    private static final KeyPair ALICE_APPROVER = Ed25519.generateKeyPair();
    private static final KeyPair POLICY_SIGNER = Ed25519.generateKeyPair();
    private static final KeyPair SEALED = Ed25519.generateKeyPair();

    private static final KeyRing KEYS = new KeyRing(List.of(
            key(Fixtures.IDP_KEY_ID, KeyPurpose.IDENTITY_PROVIDER, "corp-idp", Fixtures.IDP),
            key(Fixtures.DEVICE_KEY_ID, KeyPurpose.DEVICE_AGENT, "laptop-alice", Fixtures.DEVICE_AGENT),
            key("bob-approver", KeyPurpose.ELEVATION_APPROVER, "bob", BOB),
            key("alice-approver", KeyPurpose.ELEVATION_APPROVER, "alice", ALICE_APPROVER),
            key("bob-policy", KeyPurpose.POLICY_SIGNER, "bob", POLICY_SIGNER),
            key("bg-1-sealed", KeyPurpose.BREAK_GLASS, "bg-admin-1", SEALED)));

    private static final InMemoryDirectory BASE = new InMemoryDirectory(
            List.of(new Subject("alice", SubjectType.HUMAN, Set.of("engineer"), "engineering"),
                    new Subject("bob", SubjectType.HUMAN, Set.of("engineer"), "engineering"),
                    new Subject("bg-admin-1", SubjectType.HUMAN, Set.of(), "security")),
            List.of(new Resource("wiki", ResourceKind.PRIVATE_APP, DataClassification.INTERNAL)),
            List.of("laptop-alice"));

    private static final class MutableClock extends Clock {
        private volatile Instant now = T;

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private final MutableClock clock = new MutableClock();
    private final InMemoryAuditSink sink = new InMemoryAuditSink();
    private final List<String> alerts = new ArrayList<>();
    private PrivilegedAccessManager pam;
    private PolicyEngine engine;

    private static TrustedKey key(String id, KeyPurpose purpose, String owner, KeyPair kp) {
        return new TrustedKey(id, purpose, owner, kp.getPublic(), T.minus(Duration.ofDays(90)), T.plus(Duration.ofDays(90)));
    }

    @BeforeEach
    void setUp() throws Exception {
        AuditLog audit = new AuditLog(KeyGenerator.getInstance("HmacSHA256").generateKey(), sink);
        pam = new PrivilegedAccessManager(KEYS, Map.of("alice", Set.of("admin")),
                Map.of("bg-admin-1", Set.of("admin")), PamSettings.defaults(), audit, clock, alerts::add);
        engine = PolicyEngine.builder().policySet(PolicyEngineTest.POLICIES)
                .directory(new ElevatedDirectory(BASE, pam, clock)).keyRing(KEYS).scorers(List.of())
                .aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                .costModel(new CostModel(1000, 1, 20, 0.05)).build();
    }

    // ---- helpers: what the identity provider, approvers and sealed credential sign -------------------

    private AuthenticationContext mfa(AuthMethod m, Duration ago) {
        return new AuthenticationContext(m, clock.instant().minus(ago));
    }

    private static SignatureProof idpSigns(String subject, String device, AuthenticationContext a) {
        return Fixtures.signAuthentication(Fixtures.IDP, Fixtures.IDP_KEY_ID, subject, device, a, a.authenticatedAt());
    }

    private PrivilegedAccessManager.Result requestAdmin(String subject, Duration d, AuthenticationContext a) {
        return pam.request(subject, "laptop-alice", "admin", d, "INC-4211: rotate the wiki signing key",
                a, idpSigns(subject, "laptop-alice", a));
    }

    private SignatureProof approval(KeyPair k, String keyId, String requestId, String subject, String role, Duration d,
                                    Instant at) {
        return new SignatureProof(keyId, at, Ed25519.sign(k.getPrivate(),
                SignedMessages.elevationApproval(requestId, subject, role, d.toSeconds(), at)));
    }

    private SignatureProof bobApproves(String requestId, Duration d) {
        return approval(BOB, "bob-approver", requestId, "alice", "admin", d, clock.instant());
    }

    private SignatureProof sealed(String account, String role, String justification) {
        Instant at = clock.instant();
        return new SignatureProof("bg-1-sealed", at, Ed25519.sign(SEALED.getPrivate(),
                SignedMessages.breakGlass(account, role, justification, at)));
    }

    private SignatureProof review(KeyPair k, String keyId, String grantId, String verdict) {
        Instant at = clock.instant();
        return new SignatureProof(keyId, at, Ed25519.sign(k.getPrivate(), SignedMessages.breakGlassReview(grantId, verdict, at)));
    }

    /** An ADMIN action on the wiki with fresh WebAuthn (P-05 always asks for it). */
    private Outcome adminAction(String subject) {
        AccessRequest r = Fixtures.request().subject(subject).at(clock.instant()).action(Action.ADMIN)
                .authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)).build();
        return engine.decide(r, SignalSnapshot.empty()).outcome();
    }

    private long audited(String type) {
        return sink.snapshot().stream().map(AuditRecord::type).filter(type::equals).count();
    }

    // ---- just-in-time elevation -------------------------------------------------------------------------

    @Test
    void justInTimeAdminExistsOnlyInsideTheApprovedWindow() {
        assertEquals(Outcome.DENY, adminAction("alice"), "no standing admin");

        PrivilegedAccessManager.Result req = requestAdmin("alice", Duration.ofMinutes(60), mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)));
        assertTrue(req.ok(), req.reason());
        String id = req.id().orElseThrow();
        assertEquals(Outcome.DENY, adminAction("alice"), "requested is not granted");

        PrivilegedAccessManager.Result ok = pam.approve(id, "bob", bobApproves(id, Duration.ofMinutes(60)));
        assertTrue(ok.ok(), ok.reason());
        assertEquals(Outcome.ALLOW, adminAction("alice"), "inside the window, with fresh MFA");

        clock.now = clock.now.plus(Duration.ofMinutes(59));
        assertEquals(Outcome.ALLOW, adminAction("alice"));
        clock.now = clock.now.plus(Duration.ofMinutes(1));
        assertEquals(Outcome.DENY, adminAction("alice"), "the role is gone the moment the window ends");
        assertEquals(1, pam.purgeExpired());
        assertEquals(1, audited("ELEVATION_REQUESTED"));
        assertEquals(1, audited("ELEVATION_GRANTED"));
        assertEquals(1, audited("ELEVATION_EXPIRED"));
    }

    @Test
    void onlyEligibleRolesForALimitedTimeWithAReason() {
        AuthenticationContext a = mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1));
        assertFalse(pam.request("bob", "laptop-alice", "admin", Duration.ofMinutes(30), "INC-1: needed for the fix",
                a, idpSigns("bob", "laptop-alice", a)).ok(), "bob is not eligible");
        assertFalse(requestAdmin("alice", Duration.ofMinutes(61), mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1))).ok(),
                "longer than 1 h");
        AuthenticationContext b = mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1));
        assertFalse(pam.request("alice", "laptop-alice", "admin", Duration.ofMinutes(30), "because",
                b, idpSigns("alice", "laptop-alice", b)).ok(), "a one-word reason is not a justification");
        AuthenticationContext c = mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1));
        assertFalse(pam.request("alice", "laptop-alice", "superuser", Duration.ofMinutes(30), "INC-1: needed for the fix",
                c, idpSigns("alice", "laptop-alice", c)).ok(), "not eligible for that role");
    }

    @Test
    void requestingPrivilegeNeedsFreshPhishingResistantMfaUsedOnce() {
        assertFalse(requestAdmin("alice", Duration.ofMinutes(30), mfa(AuthMethod.PUSH_NUMBER_MATCH, Duration.ofMinutes(1))).ok(),
                "push can be phished or fatigued");
        assertFalse(requestAdmin("alice", Duration.ofMinutes(30), mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(6))).ok(),
                "older than 5 minutes");
        AuthenticationContext a = mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1));
        assertFalse(pam.request("alice", "laptop-alice", "admin", Duration.ofMinutes(30), "INC-4211: rotate the key",
                a, idpSigns("bob", "laptop-alice", a)).ok(), "a proof for someone else");
        assertFalse(pam.request("alice", "laptop-alice", "admin", Duration.ofMinutes(30), "INC-4211: rotate the key",
                a, null).ok(), "unsigned");
    }

    @Test
    void oneMfaCeremonyServesOneRequest() {
        AuthenticationContext once = mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1));
        SignatureProof proof = idpSigns("alice", "laptop-alice", once);
        assertTrue(pam.request("alice", "laptop-alice", "admin", Duration.ofMinutes(30), "INC-4211: rotate the key",
                once, proof).ok());
        PrivilegedAccessManager.Result again = pam.request("alice", "laptop-alice", "admin", Duration.ofMinutes(30),
                "INC-4211: rotate the key", once, proof);
        assertFalse(again.ok(), "one MFA ceremony, one request");
        assertTrue(again.reason().contains("already used"), again.reason());
    }

    @Test
    void nobodyApprovesTheirOwnElevation() {
        String id = requestAdmin("alice", Duration.ofMinutes(30), mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1))).id().orElseThrow();
        PrivilegedAccessManager.Result self = pam.approve(id, "alice",
                approval(ALICE_APPROVER, "alice-approver", id, "alice", "admin", Duration.ofMinutes(30), clock.instant()));
        assertFalse(self.ok());
        assertTrue(self.reason().contains("own"), self.reason());
        assertEquals(Outcome.DENY, adminAction("alice"));
    }

    @Test
    void anApprovalCoversExactlyWhatWasAskedAndNothingElse() {
        String id = requestAdmin("alice", Duration.ofMinutes(30), mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1))).id().orElseThrow();
        Instant now = clock.instant();
        assertFalse(pam.approve(id, "bob", approval(BOB, "bob-approver", id, "alice", "admin", Duration.ofHours(8), now)).ok(),
                "signed for a longer duration than requested");
        assertFalse(pam.approve(id, "bob", approval(BOB, "bob-approver", id, "alice", "superuser", Duration.ofMinutes(30), now)).ok(),
                "signed for another role");
        assertFalse(pam.approve(id, "bob", approval(BOB, "bob-approver", "e-other", "alice", "admin", Duration.ofMinutes(30), now)).ok(),
                "signed for another request");
        assertFalse(pam.approve(id, "bob", approval(POLICY_SIGNER, "bob-policy", id, "alice", "admin", Duration.ofMinutes(30), now)).ok(),
                "a policy-signing key cannot approve elevation");
        assertFalse(pam.approve(id, "bob", approval(BOB, "bob-approver", id, "alice", "admin", Duration.ofMinutes(30),
                now.minus(Duration.ofMinutes(6)))).ok(), "a stale approval");
        assertFalse(pam.approve(id, "carol", bobApproves(id, Duration.ofMinutes(30))).ok(), "bob's key claimed by carol");
        assertTrue(pam.approve(id, "bob", bobApproves(id, Duration.ofMinutes(30))).ok());
        assertFalse(pam.approve(id, "bob", bobApproves(id, Duration.ofMinutes(30))).ok(), "an approval is used once");
    }

    @Test
    void anUnapprovedRequestLapses() {
        String id = requestAdmin("alice", Duration.ofMinutes(30), mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1))).id().orElseThrow();
        clock.now = clock.now.plus(Duration.ofMinutes(31));
        assertFalse(pam.approve(id, "bob", bobApproves(id, Duration.ofMinutes(30))).ok());
        assertTrue(pam.pendingRequests().isEmpty());
    }

    @Test
    void revokingElevationTakesEffectOnTheNextDecision() {
        String id = requestAdmin("alice", Duration.ofMinutes(60), mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1))).id().orElseThrow();
        pam.approve(id, "bob", bobApproves(id, Duration.ofMinutes(60)));
        assertEquals(Outcome.ALLOW, adminAction("alice"));
        assertEquals(1, pam.revokeSubject("alice", "soc-analyst", "suspicious change pattern"));
        assertEquals(Outcome.DENY, adminAction("alice"));
        assertEquals(1, audited("ELEVATION_REVOKED"));
    }

    @Test
    void noAuditNoElevation() throws Exception {
        PrivilegedAccessManager broken = new PrivilegedAccessManager(KEYS, Map.of("alice", Set.of("admin")), Map.of(),
                PamSettings.defaults(), new AuditLog(KeyGenerator.getInstance("HmacSHA256").generateKey(), r -> {
                    throw new IllegalStateException("disk full");
                }), clock, alerts::add);
        AuthenticationContext a = mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1));
        assertFalse(broken.request("alice", "laptop-alice", "admin", Duration.ofMinutes(30), "INC-4211: rotate the key",
                a, idpSigns("alice", "laptop-alice", a)).ok());
        assertTrue(broken.pendingRequests().isEmpty());
    }

    // ---- break-glass ------------------------------------------------------------------------------------

    @Test
    void breakGlassWorksAlertsAtOnceAndMustBeReviewed() {
        String why = "SEV-1: IdP admin console unreachable, approvers offline";
        PrivilegedAccessManager.Result r = pam.breakGlass("bg-admin-1", "admin", why, sealed("bg-admin-1", "admin", why));
        assertTrue(r.ok(), r.reason());
        assertEquals(1, alerts.size());
        assertTrue(alerts.get(0).startsWith("break-glass: bg-admin-1 holds admin"));
        assertTrue(sink.snapshot().stream().anyMatch(x -> x.type().equals("BREAK_GLASS_USED")
                && x.payloadJson().contains("CRITICAL")));
        assertEquals(Outcome.ALLOW, adminAction("bg-admin-1"));

        clock.now = clock.now.plus(Duration.ofMinutes(30));
        assertEquals(Outcome.DENY, adminAction("bg-admin-1"), "30 minutes, then gone");
        assertEquals(1, pam.pendingReviews().size(), "still awaiting review after it ended");

        String grant = r.id().orElseThrow();
        assertFalse(pam.review(grant, "bob", "fine", review(BOB, "bob-approver", grant, "fine")).ok(), "verdicts are fixed");
        assertTrue(pam.review(grant, "bob", "justified", review(BOB, "bob-approver", grant, "justified")).ok());
        assertTrue(pam.pendingReviews().isEmpty());
        assertEquals(1, audited("BREAK_GLASS_REVIEWED"));
    }

    @Test
    void misuseFoundInReviewEndsTheGrantAtOnce() {
        String why = "SEV-1: production outage, need admin now";
        String grant = pam.breakGlass("bg-admin-1", "admin", why, sealed("bg-admin-1", "admin", why)).id().orElseThrow();
        assertEquals(Outcome.ALLOW, adminAction("bg-admin-1"));
        assertTrue(pam.review(grant, "bob", "misuse", review(BOB, "bob-approver", grant, "misuse")).ok());
        assertEquals(Outcome.DENY, adminAction("bg-admin-1"));
        assertEquals(2, alerts.size());
        assertTrue(alerts.get(1).contains("misuse"));
    }

    @Test
    void breakGlassCannotBeForgedReplayedOrSelfReviewed() {
        String why = "SEV-1: production outage, need admin now";
        assertFalse(pam.breakGlass("alice", "admin", why, sealed("alice", "admin", why)).ok(), "not a break-glass account");
        assertFalse(pam.breakGlass("bg-admin-1", "superuser", why, sealed("bg-admin-1", "superuser", why)).ok(),
                "a role its credential does not open");
        assertFalse(pam.breakGlass("bg-admin-1", "admin", why, sealed("bg-admin-1", "admin", "something else entirely")).ok(),
                "the justification is signed");
        SignatureProof s = sealed("bg-admin-1", "admin", why);
        PrivilegedAccessManager.Result first = pam.breakGlass("bg-admin-1", "admin", why, s);
        assertTrue(first.ok());
        assertFalse(pam.breakGlass("bg-admin-1", "admin", why, s).ok(), "a sealed signature opens the glass once");
        String grant = first.id().orElseThrow();
        assertFalse(pam.review(grant, "bg-admin-1", "justified", review(BOB, "bob-approver", grant, "justified")).ok(),
                "nobody reviews their own break-glass use");
        assertTrue(alerts.size() >= 4, "every failed or replayed attempt pages the SOC: " + alerts);
    }

    @Test
    void breakGlassIsLimitedToThreeUsesADay() {
        for (int i = 0; i < 3; i++) {
            String why = "SEV-1: outage number " + i + ", need admin";
            clock.now = clock.now.plusSeconds(1);
            assertTrue(pam.breakGlass("bg-admin-1", "admin", why, sealed("bg-admin-1", "admin", why)).ok());
        }
        String why = "SEV-1: outage number 4, need admin";
        assertFalse(pam.breakGlass("bg-admin-1", "admin", why, sealed("bg-admin-1", "admin", why)).ok());
    }

    // ---- rate limits and settings ------------------------------------------------------------------------

    @Test
    void elevationRequestsAndApprovalsAreRateLimited() {
        int ok = 0;
        for (int i = 0; i < 8; i++) {
            if (requestAdmin("alice", Duration.ofMinutes(30), mfa(AuthMethod.WEBAUTHN, Duration.ofSeconds(60 + i))).ok()) {
                ok++;
            }
        }
        assertEquals(5, ok, "5 requests per subject per hour");
        String id = pam.pendingRequests().get(0).requestId();
        int refused = 0;
        for (int i = 0; i < 25; i++) {
            if (!pam.approve(id, "bob", approval(BOB, "bob-approver", id, "alice", "admin", Duration.ofMinutes(1),
                    clock.instant())).ok()) {
                refused++;
            }
        }
        assertEquals(25, refused, "every bad approval is refused");
        assertTrue(sink.snapshot().size() < 60, "refusals are audited, but throttled");
    }

    @Test
    void settingsRefuseStandingPrivilegeInDisguise() {
        assertThrows(IllegalArgumentException.class, () -> new PamSettings(Duration.ofHours(9), Duration.ofMinutes(30),
                Duration.ofMinutes(5), Duration.ofMinutes(5), EnumSet.of(AuthMethod.WEBAUTHN), Duration.ofMinutes(30),
                5, 20, 3, 10, 10));
        assertThrows(IllegalArgumentException.class, () -> new PamSettings(Duration.ofHours(1), Duration.ofMinutes(30),
                Duration.ofMinutes(5), Duration.ofMinutes(5), EnumSet.of(AuthMethod.PASSWORD), Duration.ofMinutes(30),
                5, 20, 3, 10, 10));
        assertThrows(IllegalArgumentException.class, () -> new ElevationGrant("g-1", "alice", "admin", T, T.plusSeconds(60),
                java.util.Optional.empty(), false, "x"), "only break-glass grants lack an approver");
    }

    @Test
    void anElevatedRoleNeverLeaksToAnotherSubject() {
        String id = requestAdmin("alice", Duration.ofMinutes(60), mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1))).id().orElseThrow();
        pam.approve(id, "bob", bobApproves(id, Duration.ofMinutes(60)));
        ElevatedDirectory dir = new ElevatedDirectory(BASE, pam, clock);
        assertTrue(dir.subject("alice").orElseThrow().roles().contains("admin"));
        assertFalse(dir.subject("bob").orElseThrow().roles().contains("admin"));
        assertEquals(Set.of("engineer"), BASE.subject("alice").orElseThrow().roles(), "the identity store is untouched");
        assertEquals(1, pam.grants().size());
        assertTrue(dir.resource("wiki").isPresent());
        assertTrue(dir.isManagedDevice("laptop-alice"));
    }

    @Test
    void oneGrantCanBeRevokedAndStoresStayBounded() throws Exception {
        String id = requestAdmin("alice", Duration.ofMinutes(60), mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1))).id().orElseThrow();
        pam.approve(id, "bob", bobApproves(id, Duration.ofMinutes(60)));
        assertEquals(0, pam.revokeGrant("g-unknown", "soc-analyst", "no such grant"));
        assertEquals(1, pam.revokeGrant(id, "soc-analyst", "change window cancelled"));
        assertEquals(Outcome.DENY, adminAction("alice"));
        assertFalse(pam.review(id, "bob", "justified", review(BOB, "bob-approver", id, "justified")).ok(),
                "only break-glass uses are reviewed");

        PamSettings tiny = new PamSettings(Duration.ofHours(1), Duration.ofMinutes(30), Duration.ofMinutes(5),
                Duration.ofMinutes(5), EnumSet.of(AuthMethod.WEBAUTHN), Duration.ofMinutes(30), 5, 20, 3, 1, 1);
        pam = new PrivilegedAccessManager(KEYS, Map.of("alice", Set.of("admin")), Map.of("bg-admin-1", Set.of("admin")),
                tiny, new AuditLog(KeyGenerator.getInstance("HmacSHA256").generateKey(), sink), clock, alerts::add);
        String first = requestAdmin("alice", Duration.ofMinutes(30), mfa(AuthMethod.WEBAUTHN, Duration.ofSeconds(61)))
                .id().orElseThrow();
        assertFalse(requestAdmin("alice", Duration.ofMinutes(30), mfa(AuthMethod.WEBAUTHN, Duration.ofSeconds(62))).ok(),
                "one open request at most");
        assertTrue(pam.approve(first, "bob", bobApproves(first, Duration.ofMinutes(30))).ok());
        String why = "SEV-1: outage while the grant table is full";
        assertFalse(pam.breakGlass("bg-admin-1", "admin", why, sealed("bg-admin-1", "admin", why)).ok(),
                "one active grant at most: refuse rather than grow without bound");
    }

    @Test
    void withoutAnAuditTrailThereIsNoApprovalAndNoBreakGlass() throws Exception {
        String id = requestAdmin("alice", Duration.ofMinutes(30), mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1))).id().orElseThrow();
        boolean[] down = {false};
        AuditLog flaky = new AuditLog(KeyGenerator.getInstance("HmacSHA256").generateKey(), r -> {
            if (down[0]) {
                throw new IllegalStateException("disk full");
            }
        });
        PrivilegedAccessManager p = new PrivilegedAccessManager(KEYS, Map.of("alice", Set.of("admin")),
                Map.of("bg-admin-1", Set.of("admin")), PamSettings.defaults(), flaky, clock, alerts::add);
        AuthenticationContext a = mfa(AuthMethod.WEBAUTHN, Duration.ofSeconds(90));
        String pid = p.request("alice", "laptop-alice", "admin", Duration.ofMinutes(30), "INC-4211: rotate the key",
                a, idpSigns("alice", "laptop-alice", a)).id().orElseThrow();
        down[0] = true;
        assertFalse(p.approve(pid, "bob", bobApproves(pid, Duration.ofMinutes(30))).ok());
        assertTrue(p.activeRoles("alice", clock.instant()).isEmpty());
        String why = "SEV-1: outage and the audit disk is full";
        assertFalse(p.breakGlass("bg-admin-1", "admin", why, sealed("bg-admin-1", "admin", why)).ok());
        assertTrue(p.activeRoles("bg-admin-1", clock.instant()).isEmpty());
        assertTrue(id.startsWith("e-"));
    }

    @Test
    void r7_junkSentInSomeonesNameCannotUseUpTheirQuota() {
        // Red-team finding: rate limits counted attempts before checking who was asking, so 10 junk
        // requests in Alice's name locked her out of elevation for an hour.
        for (int i = 0; i < 10; i++) {
            assertFalse(pam.request("alice", "laptop-alice", "admin", Duration.ofMinutes(30), "junk junk junk junk",
                    null, null).ok());
        }
        PrivilegedAccessManager.Result legit = requestAdmin("alice", Duration.ofMinutes(30),
                mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)));
        assertTrue(legit.ok(), legit.reason());
        String id = legit.id().orElseThrow();
        for (int i = 0; i < 25; i++) {
            assertFalse(pam.approve(id, "bob", approval(ALICE_APPROVER, "alice-approver", id, "alice", "admin",
                    Duration.ofMinutes(30), clock.instant())).ok(), "forged in bob's name");
        }
        assertTrue(pam.approve(id, "bob", bobApproves(id, Duration.ofMinutes(30))).ok(), "bob's real approval still works");
        for (int i = 0; i < 20; i++) {
            pam.breakGlass("bg-admin-1", "admin", "SEV-1: junk junk junk",
                    new SignatureProof("bg-1-sealed", clock.instant(), "AAAA"));
        }
        String why = "SEV-1: real outage, approvers asleep";
        assertTrue(pam.breakGlass("bg-admin-1", "admin", why, sealed("bg-admin-1", "admin", why)).ok(),
                "20 forged break-glass attempts did not use up the emergency quota");
        assertTrue(alerts.size() <= 6, "failed attempts page at most 5 times an hour, plus the real use: " + alerts.size());
    }

    @Test
    void genuineApprovalsAreLimitedPerApprover() throws Exception {
        PamSettings two = new PamSettings(Duration.ofHours(1), Duration.ofMinutes(30), Duration.ofMinutes(5),
                Duration.ofMinutes(5), EnumSet.of(AuthMethod.WEBAUTHN), Duration.ofMinutes(30), 5, 2, 3, 100, 100);
        pam = new PrivilegedAccessManager(KEYS, Map.of("alice", Set.of("admin")), Map.of(), two,
                new AuditLog(KeyGenerator.getInstance("HmacSHA256").generateKey(), sink), clock, alerts::add);
        List<String> ids = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            ids.add(requestAdmin("alice", Duration.ofMinutes(30), mfa(AuthMethod.WEBAUTHN, Duration.ofSeconds(60 + i)))
                    .id().orElseThrow());
        }
        assertTrue(pam.approve(ids.get(0), "bob", bobApproves(ids.get(0), Duration.ofMinutes(30))).ok());
        assertTrue(pam.approve(ids.get(1), "bob", bobApproves(ids.get(1), Duration.ofMinutes(30))).ok());
        PrivilegedAccessManager.Result third = pam.approve(ids.get(2), "bob", bobApproves(ids.get(2), Duration.ofMinutes(30)));
        assertFalse(third.ok(), "a stolen approver key cannot hand out elevation in bulk");
        assertTrue(third.reason().contains("too many approvals"), third.reason());
    }
}

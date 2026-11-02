package dev.dwarpal.session;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.crypto.TrustedKey;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.engine.PolicyEngineTest;
import dev.dwarpal.pam.ElevatedDirectory;
import dev.dwarpal.pam.PamSettings;
import dev.dwarpal.pam.PrivilegedAccessManager;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.runtime.DecisionPipeline;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static dev.dwarpal.session.SessionResult.Status.DENIED;
import static dev.dwarpal.session.SessionResult.Status.GRANTED;
import static dev.dwarpal.session.SessionResult.Status.OPENED;
import static dev.dwarpal.session.SessionResult.Status.STEP_UP;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Both halves of Layer 3 together: Alice works in a session; she is granted admin just in time; her
 * admin actions in the same session work only inside the window, each with fresh MFA bound to the
 * session key; when the window ends, admin stops but her ordinary session carries on.
 */
class JustInTimeAdminSessionTest {

    private static final KeyPair BOB = Ed25519.generateKeyPair();

    @Test
    void adminInsideASessionLivesExactlyAsLongAsTheGrant() throws Exception {
        SessionFixtures.MutableClock clock = new SessionFixtures.MutableClock();
        InMemoryAuditSink sink = new InMemoryAuditSink();
        AuditLog audit = SessionFixtures.auditLog(sink);
        KeyRing keys = new KeyRing(List.of(
                new TrustedKey(Fixtures.IDP_KEY_ID, KeyPurpose.IDENTITY_PROVIDER, "corp-idp", Fixtures.IDP.getPublic(),
                        SessionFixtures.T.minus(Duration.ofDays(1)), SessionFixtures.T.plus(Duration.ofDays(1))),
                new TrustedKey(Fixtures.DEVICE_KEY_ID, KeyPurpose.DEVICE_AGENT, "laptop-alice",
                        Fixtures.DEVICE_AGENT.getPublic(), SessionFixtures.T.minus(Duration.ofDays(1)),
                        SessionFixtures.T.plus(Duration.ofDays(1))),
                new TrustedKey("bob-approver", KeyPurpose.ELEVATION_APPROVER, "bob", BOB.getPublic(),
                        SessionFixtures.T.minus(Duration.ofDays(1)), SessionFixtures.T.plus(Duration.ofDays(1)))));
        PrivilegedAccessManager pam = new PrivilegedAccessManager(keys, Map.of("alice", Set.of("admin")), Map.of(),
                PamSettings.defaults(), audit, clock, message -> { });
        ElevatedDirectory directory = new ElevatedDirectory(SessionFixtures.DIRECTORY, pam, clock);
        PolicyEngine engine = PolicyEngine.builder().policySet(PolicyEngineTest.POLICIES).directory(directory)
                .keyRing(keys).scorers(List.of()).aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                .costModel(new CostModel(1000, 1, 20, 0.05)).build();
        DecisionPoint pdp = DecisionPipeline.continuous(engine, audit, clock);
        PolicyAdministrator pa = PolicyAdministrator.builder(audit).opening(pdp).continuous(pdp).directory(directory)
                .keyRing(keys).clock(clock).build();

        KeyPair session = Ed25519.generateKeyPair();
        int[] n = {0};
        java.util.function.Supplier<Fixtures.RequestBuilder> alice =
                () -> Fixtures.request().id("j-" + (++n[0])).at(clock.now());
        AccessRequest login = alice.get().build();
        SessionResult opened = pa.open(login, SignalSnapshot.empty(), session.getPublic(),
                SessionFixtures.bind(login, session, clock.now()));
        assertEquals(OPENED, opened.status());
        SessionGrant g = opened.grant().orElseThrow();
        java.util.function.Function<AccessRequest, SessionResult> use = r ->
                pa.use(g.token(), SessionFixtures.prove(session, g.sessionId(), r, clock.now()), r, SignalSnapshot.empty());
        java.util.function.Supplier<AccessRequest> adminWithMfa = () -> alice.get().action(Action.ADMIN)
                .authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)).boundTo(session.getPublic()).build();

        SessionResult before = use.apply(adminWithMfa.get());
        assertEquals(DENIED, before.status(), "no standing admin");
        assertFalse(before.sessionEnded(), "a refused admin action does not end her working session");

        AuthenticationContext mfa = new AuthenticationContext(AuthMethod.WEBAUTHN, clock.now().minusSeconds(30));
        String id = pam.request("alice", "laptop-alice", "admin", Duration.ofMinutes(30), "CHG-88: rotate wiki keys",
                mfa, Fixtures.signAuthentication(Fixtures.IDP, Fixtures.IDP_KEY_ID, "alice", "laptop-alice", mfa,
                        mfa.authenticatedAt())).id().orElseThrow();
        SignatureProof approval = new SignatureProof("bob-approver", clock.now(), Ed25519.sign(BOB.getPrivate(),
                SignedMessages.elevationApproval(id, "alice", "admin", Duration.ofMinutes(30).toSeconds(), clock.now())));
        assertTrue(pam.approve(id, "bob", approval).ok());

        assertEquals(STEP_UP, use.apply(alice.get().action(Action.ADMIN).build()).status(),
                "elevated, but every admin action still needs fresh MFA (P-05)");
        assertEquals(GRANTED, use.apply(adminWithMfa.get()).status());

        clock.advance(Duration.ofMinutes(20));
        assertEquals(GRANTED, use.apply(alice.get().build()).status(), "she keeps working (no idle timeout)");
        clock.advance(Duration.ofMinutes(10));
        SessionResult after = use.apply(adminWithMfa.get());
        assertEquals(DENIED, after.status(), "the grant ended, so admin ended");
        assertFalse(after.sessionEnded());
        assertEquals(GRANTED, use.apply(alice.get().build()).status(), "her ordinary work goes on");
    }
}

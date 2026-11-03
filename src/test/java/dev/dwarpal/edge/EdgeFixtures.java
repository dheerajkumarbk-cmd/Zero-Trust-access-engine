package dev.dwarpal.edge;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.TrustedKey;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.domain.SubjectType;
import dev.dwarpal.engine.AssuranceSettings;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.engine.DenyListGate;
import dev.dwarpal.engine.HoneytokenGate;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.engine.PolicyEngineTest;
import dev.dwarpal.pam.ElevatedDirectory;
import dev.dwarpal.pam.PamSettings;
import dev.dwarpal.pam.PrivilegedAccessManager;
import dev.dwarpal.pip.InMemoryDirectory;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.runtime.DecisionPipeline;
import dev.dwarpal.session.PolicyAdministrator;

import javax.crypto.KeyGenerator;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The shared test world for every Layer 4 part: the same people, devices, resources, keys and engine,
 * so the ZTNA gateway, the API and the web gateway are tested against one and the same Dwarpal.
 *
 * <pre>
 * people     alice (engineer, finance; eligible for admin), bob (engineer; approver), carol (engineer),
 *            bg-admin-1 (break-glass account for admin)
 * devices    laptop-alice (managed, has an endpoint agent key), laptop-carol (managed, no agent key),
 *            anything else is unmanaged
 * resources  wiki (private app, INTERNAL), vault (private app, RESTRICTED), drive (SaaS data, INTERNAL),
 *            web:general (web, PUBLIC), web:uncategorised (web, INTERNAL), web:malicious (web, RESTRICTED)
 * policy     the reference policy (no standing admin, read-only SaaS from unmanaged devices, ...)
 * </pre>
 *
 * Risk scorers are off, so every request sits at the prior and outcomes come from policy, gates and
 * evidence; parts that need risk can add scorers through {@link #world(java.util.List)}.
 */
public final class EdgeFixtures {

    public static final Instant T = Fixtures.T0;
    public static final KeyPair BOB_APPROVER = Ed25519.generateKeyPair();
    public static final KeyPair BREAK_GLASS = Ed25519.generateKeyPair();
    public static final String BOB_APPROVER_KEY_ID = "bob-approver";
    public static final String BREAK_GLASS_KEY_ID = "bg-admin-1-sealed";

    private EdgeFixtures() {
    }

    public static KeyRing keyRing() {
        return new KeyRing(List.of(
                key(Fixtures.IDP_KEY_ID, KeyPurpose.IDENTITY_PROVIDER, "corp-idp", Fixtures.IDP),
                key(Fixtures.DEVICE_KEY_ID, KeyPurpose.DEVICE_AGENT, "laptop-alice", Fixtures.DEVICE_AGENT),
                key(BOB_APPROVER_KEY_ID, KeyPurpose.ELEVATION_APPROVER, "bob", BOB_APPROVER),
                key(BREAK_GLASS_KEY_ID, KeyPurpose.BREAK_GLASS, "bg-admin-1", BREAK_GLASS)));
    }

    public static InMemoryDirectory directory() {
        return new InMemoryDirectory(
                List.of(new Subject("alice", SubjectType.HUMAN, Set.of("engineer", "finance"), "engineering"),
                        new Subject("bob", SubjectType.HUMAN, Set.of("engineer"), "engineering"),
                        new Subject("carol", SubjectType.HUMAN, Set.of("engineer"), "engineering"),
                        new Subject("bg-admin-1", SubjectType.HUMAN, Set.of(), "security")),
                List.of(new Resource("wiki", ResourceKind.PRIVATE_APP, DataClassification.INTERNAL),
                        new Resource("vault", ResourceKind.PRIVATE_APP, DataClassification.RESTRICTED),
                        new Resource("drive", ResourceKind.SAAS_DATA, DataClassification.INTERNAL),
                        new Resource("web:general", ResourceKind.WEB, DataClassification.PUBLIC),
                        new Resource("web:uncategorised", ResourceKind.WEB, DataClassification.INTERNAL),
                        new Resource("web:malicious", ResourceKind.WEB, DataClassification.RESTRICTED)),
                List.of("laptop-alice", "laptop-carol"));
    }

    /** A clock the test moves by hand. */
    public static final class TestClock extends Clock {
        private volatile Instant now = T;

        public Instant now() {
            return now;
        }

        public void advance(Duration d) {
            now = now.plus(d);
        }

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

    /** Everything wired together, as it will run in production (minus the network). */
    public static final class World {
        public final TestClock clock = new TestClock();
        public final InMemoryAuditSink sink = new InMemoryAuditSink();
        public final AuditLog audit;
        public final PrivilegedAccessManager pam;
        public final ElevatedDirectory directory;
        public final PolicyEngine engine;
        public final PolicyAdministrator administrator;
        public final LocalSessionAuthority authority;
        /** The engine-side threat signals; tests set deny-lists here, never in requests. */
        public final AtomicReference<SignalSnapshot> signals = new AtomicReference<>(SignalSnapshot.empty());
        public final List<String> alerts = new ArrayList<>();
        private int ids;

        World(List<dev.dwarpal.risk.RiskScorer> scorers) {
            try {
                audit = new AuditLog(KeyGenerator.getInstance("HmacSHA256").generateKey(), sink);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
            KeyRing keys = keyRing();
            pam = new PrivilegedAccessManager(keys, Map.of("alice", Set.of("admin")), Map.of("bg-admin-1", Set.of("admin")),
                    PamSettings.defaults(), audit, clock, alerts::add);
            directory = new ElevatedDirectory(directory(), pam, clock);
            engine = PolicyEngine.builder().policySet(PolicyEngineTest.POLICIES).directory(directory).keyRing(keys)
                    .gate(new HoneytokenGate()).gate(new DenyListGate()).scorers(scorers)
                    .aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                    .costModel(new CostModel(1000, 1, 20, 0.05)).build();
            DecisionPoint pdp = DecisionPipeline.continuous(engine, audit, clock);
            administrator = PolicyAdministrator.builder(audit).opening(pdp).continuous(pdp).directory(directory)
                    .keyRing(keys).clock(clock).build();
            authority = new LocalSessionAuthority(administrator, pdp, directory, signals::get,
                    AssuranceSettings.defaults().challengeMethod(), clock);
        }

        /** A request from Alice on her laptop to the wiki, now, with a fresh id and agent-signed posture. */
        public RequestBuilder request() {
            return new RequestBuilder(this, "e-" + (++ids));
        }

        /** Logs in with {@code sessionKey}; adds the agent's device binding when the request carries signed posture. */
        public EdgeResult open(KeyPair sessionKey, EdgeRequest login) {
            Optional<SignatureProof> binding = login.evidence().postureProof().isPresent()
                    ? Optional.of(ClientProofs.bindDevice(Fixtures.DEVICE_AGENT.getPrivate(), Fixtures.DEVICE_KEY_ID,
                    login, sessionKey.getPublic(), clock.now()))
                    : Optional.empty();
            return authority.open(login, sessionKey.getPublic(), binding);
        }

        /** One request on a session, signed with the session key now. */
        public EdgeResult use(KeyPair sessionKey, EdgeGrant grant, EdgeRequest request) {
            return authority.use(grant.token(),
                    ClientProofs.sign(sessionKey.getPrivate(), grant.sessionId(), request, clock.now()), request);
        }

        public long audited(String type) {
            return sink.snapshot().stream().map(AuditRecord::type).filter(type::equals).count();
        }
    }

    public static World world() {
        return new World(List.of());
    }

    public static World world(List<dev.dwarpal.risk.RiskScorer> scorers) {
        return new World(scorers);
    }

    /** Builds an {@link EdgeRequest} the way an enforcement point would. */
    public static final class RequestBuilder {
        private final World world;
        private String requestId;
        private Instant at;
        private String subject = "alice";
        private String device = "laptop-alice";
        private boolean signPosture = true;
        private DevicePosture posture = new DevicePosture(true, true, true, AssuranceLevel.SELF_REPORTED);
        private String resource = "wiki";
        private Action action = Action.READ;
        private NetworkContext network = new NetworkContext("203.0.113.10", "AS64500", "IN", 19.07, 72.88, 25);
        private AuthenticationContext auth;
        private boolean signAuth = true;

        RequestBuilder(World world, String requestId) {
            this.world = world;
            this.requestId = requestId;
            this.at = world.clock.now();
        }

        public RequestBuilder id(String v) { requestId = v; return this; }
        public RequestBuilder at(Instant v) { at = v; return this; }
        public RequestBuilder subject(String v) { subject = v; return this; }
        /** Another device; its posture is unsigned (only laptop-alice has an agent key in the fixtures). */
        public RequestBuilder device(String v) { device = v; signPosture = false; return this; }
        public RequestBuilder unsignedPosture() { signPosture = false; return this; }
        public RequestBuilder posture(boolean patched, boolean encrypted, boolean av) {
            posture = new DevicePosture(patched, encrypted, av, AssuranceLevel.SELF_REPORTED); return this;
        }
        public RequestBuilder resource(String v) { resource = v; return this; }
        public RequestBuilder action(Action v) { action = v; return this; }
        public RequestBuilder network(NetworkContext v) { network = v; return this; }
        /** The user passed {@code method} {@code ago} before now; the IdP binds the proof to {@code sessionKey}. */
        public RequestBuilder mfa(AuthMethod method, Duration ago, KeyPair sessionKey) {
            auth = new AuthenticationContext(method, world.clock.now().minus(ago),
                    Optional.of(Digests.thumbprint(sessionKey.getPublic())));
            return this;
        }
        public RequestBuilder unsignedMfa() { signAuth = false; return this; }

        public EdgeRequest build() {
            Optional<SignatureProof> postureProof = signPosture
                    ? Optional.of(Fixtures.signPosture(Fixtures.DEVICE_AGENT, Fixtures.DEVICE_KEY_ID, device, posture, at))
                    : Optional.empty();
            Optional<AuthenticationContext> a = Optional.ofNullable(auth);
            Optional<SignatureProof> authProof = auth != null && signAuth
                    ? Optional.of(Fixtures.signAuthentication(Fixtures.IDP, Fixtures.IDP_KEY_ID, subject, device, auth,
                    auth.authenticatedAt()))
                    : Optional.empty();
            return new EdgeRequest(requestId, at, subject, device, posture, resource, action, network, "mumbai",
                    new Evidence(a, authProof, postureProof));
        }
    }

    private static TrustedKey key(String id, KeyPurpose purpose, String owner, KeyPair kp) {
        return new TrustedKey(id, purpose, owner, kp.getPublic(), T.minus(Duration.ofDays(365)), T.plus(Duration.ofDays(365)));
    }
}

package dev.dwarpal;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.crypto.TrustedKey;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Device;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.FailMode;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.domain.SubjectType;
import dev.dwarpal.pip.InMemoryDirectory;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Test-data builder: a sensible legitimate request that each test tweaks.
 *
 * <p>Keys are generated fresh for every test run and never written anywhere, so the repository
 * contains no private keys (which the gitleaks scan would flag anyway).
 */
public final class Fixtures {

    public static final Instant T0 = Instant.parse("2026-11-01T09:30:00Z");

    public static final KeyPair DEVICE_AGENT = Ed25519.generateKeyPair();
    public static final KeyPair IDP = Ed25519.generateKeyPair();
    public static final String DEVICE_KEY_ID = "agent-laptop-alice";
    public static final String IDP_KEY_ID = "idp-main";

    public static final KeyRing KEYRING = new KeyRing(List.of(
            new TrustedKey(DEVICE_KEY_ID, KeyPurpose.DEVICE_AGENT, "laptop-alice", DEVICE_AGENT.getPublic(),
                    T0.minus(Duration.ofDays(365)), T0.plus(Duration.ofDays(365))),
            new TrustedKey(IDP_KEY_ID, KeyPurpose.IDENTITY_PROVIDER, "corp-idp", IDP.getPublic(),
                    T0.minus(Duration.ofDays(365)), T0.plus(Duration.ofDays(365)))));

    private Fixtures() {
    }

    public static RequestBuilder request() {
        return new RequestBuilder();
    }

    /** A directory whose records are exactly what the given requests claim (i.e. honest PEPs). */
    public static InMemoryDirectory directoryFor(AccessRequest... requests) {
        Map<String, Subject> subjects = new HashMap<>();
        Map<String, Resource> resources = new HashMap<>();
        List<String> managed = new ArrayList<>();
        for (AccessRequest r : requests) {
            subjects.put(r.subject().id(), r.subject());
            resources.put(r.resource().id(), r.resource());
            if (r.device().managed()) {
                managed.add(r.device().id());
            }
        }
        return new InMemoryDirectory(subjects.values(), resources.values(), managed);
    }

    public static InMemoryDirectory emptyDirectory() {
        return new InMemoryDirectory(List.of(), List.of());
    }

    public static String resource(String path) {
        try (InputStream in = Fixtures.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalArgumentException("missing test resource " + path);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** What the real endpoint agent does: sign the posture it measured. */
    public static SignatureProof signPosture(KeyPair keys, String keyId, String deviceId, DevicePosture p, Instant at) {
        return new SignatureProof(keyId, at, Ed25519.sign(keys.getPrivate(), SignedMessages.posture(deviceId, p, at)));
    }

    /** What the real identity provider does: sign "subject authenticated with method at time". */
    public static SignatureProof signAuthentication(KeyPair keys, String keyId, String subjectId, String deviceId,
                                                    AuthenticationContext a, Instant at) {
        return new SignatureProof(keyId, at, Ed25519.sign(keys.getPrivate(),
                SignedMessages.authentication(subjectId, deviceId, a, at)));
    }

    public static final class RequestBuilder {
        private String requestId = "req-1";
        private Instant timestamp = T0;
        private String subjectId = "alice";
        private SubjectType subjectType = SubjectType.HUMAN;
        private Set<String> roles = Set.of("engineer");
        private String department = "engineering";
        private String deviceId = "laptop-alice";
        private boolean managed = true;
        private DevicePosture posture = new DevicePosture(true, true, true, AssuranceLevel.AGENT_SIGNED);
        private boolean signPosture = true;
        private KeyPair postureKey = DEVICE_AGENT;
        private String postureKeyId = DEVICE_KEY_ID;
        private AuthenticationContext authentication;
        private boolean signAuthentication = true;
        private String resourceId = "wiki";
        private ResourceKind kind = ResourceKind.PRIVATE_APP;
        private DataClassification classification = DataClassification.INTERNAL;
        private FailMode failMode = FailMode.FAIL_CLOSED;
        private Action action = Action.READ;
        private String ip = "203.0.113.10";
        private String country = "IN";
        private String asn = "AS64500";
        private double lat = 19.07;
        private double lon = 72.88;

        public RequestBuilder id(String v) { requestId = v; return this; }
        public RequestBuilder at(Instant v) { timestamp = v; return this; }
        public RequestBuilder subject(String v) { subjectId = v; return this; }
        public RequestBuilder workload() { subjectType = SubjectType.WORKLOAD; return this; }
        public RequestBuilder roles(String... v) { roles = Set.of(v); return this; }
        public RequestBuilder device(String v) { deviceId = v; return this; }
        public RequestBuilder unmanaged() { managed = false; return this; }
        public RequestBuilder posture(DevicePosture v) { posture = v; return this; }
        public RequestBuilder unsignedPosture() { signPosture = false; return this; }
        /** Sign the posture with this device's own agent key (default: alice's laptop key). */
        public RequestBuilder postureSignedBy(KeyPair key, String keyId) { postureKey = key; postureKeyId = keyId; return this; }
        /** Subject passed {@code method} {@code ago} before the request; the IdP signs it. */
        public RequestBuilder authenticated(AuthMethod method, Duration ago) {
            authentication = new AuthenticationContext(method, timestamp.minus(ago));
            return this;
        }
        public RequestBuilder unsignedAuthentication() { signAuthentication = false; return this; }
        /** The IdP binds the authentication to this client session key (call after {@code authenticated}). */
        public RequestBuilder boundTo(java.security.PublicKey sessionKey) {
            authentication = new AuthenticationContext(authentication.method(), authentication.authenticatedAt(),
                    java.util.Optional.of(dev.dwarpal.crypto.Digests.thumbprint(sessionKey)));
            return this;
        }
        public RequestBuilder resource(String id, ResourceKind k, DataClassification c) {
            resourceId = id; kind = k; classification = c; return this;
        }
        public RequestBuilder failMode(FailMode v) { failMode = v; return this; }
        public RequestBuilder action(Action v) { action = v; return this; }
        public RequestBuilder ip(String v) { ip = v; return this; }
        public RequestBuilder country(String v) { country = v; return this; }
        /** Source network: IP, ISP (ASN), country and GeoIP coordinates (25 km accuracy). */
        public RequestBuilder network(String ip, String asn, String country, double lat, double lon) {
            this.ip = ip; this.asn = asn; this.country = country; this.lat = lat; this.lon = lon; return this;
        }

        public AccessRequest build() {
            Evidence evidence = Evidence.none();
            if (signPosture) {
                evidence = evidence.withPostureProof(signPosture(postureKey, postureKeyId, deviceId, posture, timestamp));
            }
            if (authentication != null) {
                SignatureProof proof = signAuthentication
                        ? Fixtures.signAuthentication(IDP, IDP_KEY_ID, subjectId, deviceId, authentication, authentication.authenticatedAt())
                        : null;
                evidence = evidence.withAuthentication(authentication, proof);
            }
            return new AccessRequest(requestId, timestamp,
                    new Subject(subjectId, subjectType, roles, department),
                    new Device(deviceId, managed, posture),
                    new Resource(resourceId, kind, classification, failMode),
                    action,
                    new NetworkContext(ip, asn, country, lat, lon, 25),
                    "mumbai",
                    evidence);
        }
    }
}

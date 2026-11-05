package dev.dwarpal.sim;

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
import dev.dwarpal.policy.PolicySet;
import dev.dwarpal.policy.SafePolicyLoader;

/**
 * Builds signed access requests for the simulated organisation (and for the lab). It is the production-side twin of
 * the test fixtures: a request carries a device posture signed by the device agent's key and an authentication
 * signed by the identity provider's key, as the real components would sign them.
 *
 * <p>The keys here are process-wide development keys. They stand for the simulated identity provider; a deployment
 * trusts the keys of its real components through the key ring instead.
 */
public final class SimRequests {

    public static final Instant T0 = Instant.parse("2026-11-01T09:30:00Z");

    public static final KeyPair DEVICE_AGENT = Ed25519.generateKeyPair();
    public static final KeyPair IDP = Ed25519.generateKeyPair();
    public static final String DEVICE_KEY_ID = "agent-laptop-alice";
    public static final String IDP_KEY_ID = "idp-main";

    private SimRequests() {
    }

    public static Builder request() {
        return new Builder();
    }

    /** The reference policy shipped in the jar, loaded through the hardened loader. */
    public static PolicySet defaultPolicies() {
        try (InputStream in = SimRequests.class.getResourceAsStream("/policies/default-policy.yaml")) {
            if (in == null) {
                throw new IllegalStateException("the reference policy is missing from the jar");
            }
            return new SafePolicyLoader().load(new String(in.readAllBytes(), StandardCharsets.UTF_8));
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

    public static final class Builder {
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

        public Builder id(String v) { requestId = v; return this; }
        public Builder at(Instant v) { timestamp = v; return this; }
        public Builder subject(String v) { subjectId = v; return this; }
        public Builder workload() { subjectType = SubjectType.WORKLOAD; return this; }
        public Builder roles(String... v) { roles = Set.of(v); return this; }
        public Builder device(String v) { deviceId = v; return this; }
        public Builder unmanaged() { managed = false; return this; }
        public Builder posture(DevicePosture v) { posture = v; return this; }
        public Builder unsignedPosture() { signPosture = false; return this; }
        /** Sign the posture with this device's own agent key (default: alice's laptop key). */
        public Builder postureSignedBy(KeyPair key, String keyId) { postureKey = key; postureKeyId = keyId; return this; }
        /** Subject passed {@code method} {@code ago} before the request; the IdP signs it. */
        public Builder authenticated(AuthMethod method, Duration ago) {
            authentication = new AuthenticationContext(method, timestamp.minus(ago));
            return this;
        }
        public Builder unsignedAuthentication() { signAuthentication = false; return this; }
        /** The IdP binds the authentication to this client session key (call after {@code authenticated}). */
        public Builder boundTo(java.security.PublicKey sessionKey) {
            authentication = new AuthenticationContext(authentication.method(), authentication.authenticatedAt(),
                    java.util.Optional.of(dev.dwarpal.crypto.Digests.thumbprint(sessionKey)));
            return this;
        }
        public Builder resource(String id, ResourceKind k, DataClassification c) {
            resourceId = id; kind = k; classification = c; return this;
        }
        public Builder failMode(FailMode v) { failMode = v; return this; }
        public Builder action(Action v) { action = v; return this; }
        public Builder ip(String v) { ip = v; return this; }
        public Builder country(String v) { country = v; return this; }
        /** Source network: IP, ISP (ASN), country and GeoIP coordinates (25 km accuracy). */
        public Builder network(String ip, String asn, String country, double lat, double lon) {
            this.ip = ip; this.asn = asn; this.country = country; this.lat = lat; this.lon = lon; return this;
        }

        public AccessRequest build() {
            Evidence evidence = Evidence.none();
            if (signPosture) {
                evidence = evidence.withPostureProof(signPosture(postureKey, postureKeyId, deviceId, posture, timestamp));
            }
            if (authentication != null) {
                SignatureProof proof = signAuthentication
                        ? signAuthentication(IDP, IDP_KEY_ID, subjectId, deviceId, authentication, authentication.authenticatedAt())
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

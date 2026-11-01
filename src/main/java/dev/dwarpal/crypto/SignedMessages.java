package dev.dwarpal.crypto;

import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.domain.DevicePosture;

import java.time.Instant;

/**
 * The exact bytes each kind of signer signs. Signers (endpoint agent, identity provider, policy
 * administrators) and the verifier both use these functions, so they cannot drift apart.
 * Each message type has its own domain tag (see {@link Canonical}).
 */
public final class SignedMessages {

    public static final String POSTURE_V1 = "dwarpal/device-posture/v1";
    public static final String AUTHENTICATION_V2 = "dwarpal/authentication/v2";
    public static final String POLICY_BUNDLE_V1 = "dwarpal/policy-bundle/v1";

    private SignedMessages() {
    }

    /** What the endpoint agent signs. The assurance level is not signed: the verifier decides it. */
    public static byte[] posture(String deviceId, DevicePosture p, Instant signedAt) {
        return Canonical.encode(POSTURE_V1, deviceId, Boolean.toString(p.osPatched()),
                Boolean.toString(p.diskEncrypted()), Boolean.toString(p.avHealthy()), signedAt.toString());
    }

    /**
     * What the identity provider signs. Binding the subject id stops one user's proof serving
     * another; binding the device id stops a stolen proof being replayed from the attacker's
     * machine (device-bound sessions, the idea behind token binding / DPoP).
     */
    public static byte[] authentication(String subjectId, String deviceId, AuthenticationContext a, Instant signedAt) {
        return Canonical.encode(AUTHENTICATION_V2, subjectId, deviceId, a.method().name(),
                a.authenticatedAt().toString(), signedAt.toString());
    }

    /** What each approving administrator signs: the sequence number and the hash of the exact policy text. */
    public static byte[] policyBundle(long sequence, String policyYaml, Instant signedAt) {
        return Canonical.encode(POLICY_BUNDLE_V1, Long.toString(sequence), Digests.sha256Hex(policyYaml),
                signedAt.toString());
    }
}

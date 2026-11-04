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
    /** v2 plus the thumbprint of the client key the authentication is bound to. */
    public static final String AUTHENTICATION_V3 = "dwarpal/authentication/v3";
    public static final String POLICY_BUNDLE_V1 = "dwarpal/policy-bundle/v1";
    public static final String SESSION_USE_V1 = "dwarpal/session-use/v1";
    public static final String SESSION_BINDING_V1 = "dwarpal/session-binding/v1";
    public static final String AUTHENTICATION_FAILURE_V1 = "dwarpal/authentication-failure/v1";
    public static final String ELEVATION_APPROVAL_V1 = "dwarpal/elevation-approval/v1";
    public static final String BREAK_GLASS_V1 = "dwarpal/break-glass/v1";
    public static final String BREAK_GLASS_REVIEW_V1 = "dwarpal/break-glass-review/v1";
    public static final String SOC_VERDICT_V1 = "dwarpal/soc-verdict/v1";

    /**
     * What an approver signs: this request, this person, this role, for this long. Changing any of
     * them (a longer duration, a stronger role) breaks the signature.
     */
    public static byte[] elevationApproval(String requestId, String subjectId, String role, long seconds,
                                           Instant signedAt) {
        return Canonical.encode(ELEVATION_APPROVAL_V1, requestId, subjectId, role, Long.toString(seconds),
                signedAt.toString());
    }

    /** What a break-glass account's sealed credential signs when it is opened in an emergency. */
    public static byte[] breakGlass(String accountId, String role, String justification, Instant signedAt) {
        return Canonical.encode(BREAK_GLASS_V1, accountId, role, Digests.sha256Hex(justification), signedAt.toString());
    }

    /** What a reviewer signs after examining one break-glass use. */
    public static byte[] breakGlassReview(String grantId, String verdict, Instant signedAt) {
        return Canonical.encode(BREAK_GLASS_REVIEW_V1, grantId, verdict, signedAt.toString());
    }

    /** An analyst's verdict on one alert: which alert, who decided, what, and when (Layer 5). */
    public static byte[] socVerdict(String alertId, String analystId, String outcome, Instant signedAt) {
        return Canonical.encode(SOC_VERDICT_V1, alertId, analystId, outcome, signedAt.toString());
    }

    private SignedMessages() {
    }

    /**
     * What the client signs with its session key on every use of a session (proof of possession,
     * the idea behind DPoP, RFC 9449). The request id doubles as the single-use nonce, and the
     * subject, device, resource and action are bound so a proof cannot be moved to another request.
     */
    public static byte[] sessionUse(String sessionId, String requestId, String subjectId, String deviceId,
                                    String resourceId, String action, Instant signedAt) {
        return Canonical.encode(SESSION_USE_V1, sessionId, requestId, subjectId, deviceId, resourceId, action,
                signedAt.toString());
    }

    /**
     * What the endpoint agent signs when its device opens a session: "this session key is mine, for
     * this login, now". A posture report alone can be replayed for hours; this binding cannot, so a
     * session can claim a verified device only if that device's own agent took part.
     */
    public static byte[] sessionBinding(String deviceId, String requestId, String sessionKeyThumbprint,
                                        Instant signedAt) {
        return Canonical.encode(SESSION_BINDING_V1, deviceId, requestId, sessionKeyThumbprint, signedAt.toString());
    }

    /** What the identity provider signs when a login fails, so nobody else can feed the failure log. */
    public static byte[] authenticationFailure(String reportId, String subjectId, String ip, Instant failedAt,
                                               Instant signedAt) {
        return Canonical.encode(AUTHENTICATION_FAILURE_V1, reportId, subjectId, ip, failedAt.toString(),
                signedAt.toString());
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
        if (a.keyThumbprint().isPresent()) {
            return Canonical.encode(AUTHENTICATION_V3, subjectId, deviceId, a.method().name(),
                    a.authenticatedAt().toString(), a.keyThumbprint().get(), signedAt.toString());
        }
        return Canonical.encode(AUTHENTICATION_V2, subjectId, deviceId, a.method().name(),
                a.authenticatedAt().toString(), signedAt.toString());
    }

    /** What each approving administrator signs: the sequence number and the hash of the exact policy text. */
    public static byte[] policyBundle(long sequence, String policyYaml, Instant signedAt) {
        return Canonical.encode(POLICY_BUNDLE_V1, Long.toString(sequence), Digests.sha256Hex(policyYaml),
                signedAt.toString());
    }
}

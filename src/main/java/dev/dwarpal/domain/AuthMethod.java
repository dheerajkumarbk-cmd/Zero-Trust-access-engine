package dev.dwarpal.domain;

/**
 * How a subject proved who they are, with the assumed probability that an attacker who has the
 * victim's password gets past this method ({@code beta} in cost model M2).
 *
 * <p>These defaults are documented <em>assumptions</em>, not measurements (no peer-reviewed
 * per-method bypass rates exist; see the research notes). The ordering follows NIST SP 800-63B:
 * SMS is a "restricted" authenticator, push approval is open to MFA fatigue (MITRE ATT&CK
 * T1621), number matching blunts fatigue, and WebAuthn/FIDO2 is phishing-resistant.
 * Deployments override them in {@code AssuranceSettings}; the evaluation runs a sensitivity
 * analysis over them.
 */
public enum AuthMethod {
    PASSWORD(1.0),
    SMS_OTP(0.20),
    PUSH(0.30),
    TOTP(0.10),
    PUSH_NUMBER_MATCH(0.05),
    WEBAUTHN(0.01);

    private final double defaultBypassProbability;

    AuthMethod(double defaultBypassProbability) {
        this.defaultBypassProbability = defaultBypassProbability;
    }

    public double defaultBypassProbability() {
        return defaultBypassProbability;
    }

    /** A password alone is the thing a step-up is meant to go beyond. */
    public boolean satisfiesStepUp() {
        return this != PASSWORD;
    }
}

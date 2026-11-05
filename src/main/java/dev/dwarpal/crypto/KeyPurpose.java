package dev.dwarpal.crypto;

/**
 * What a key may sign. One key, one purpose (key separation, NIST SP 800-57): a stolen device
 * agent key must not be able to approve a policy, and an identity-provider key must not be able
 * to vouch for a laptop's disk encryption.
 */
public enum KeyPurpose {
    /** Endpoint agent: signs device-posture reports and endpoint telemetry batches (separate message domains). Bound to exactly one device id. */
    DEVICE_AGENT,
    /** Identity provider: signs "subject X authenticated with method M at time T". */
    IDENTITY_PROVIDER,
    /** Policy administrator: approves policy bundles. Bound to the administrator's identity. */
    POLICY_SIGNER,
    /** Privileged-access approver: approves just-in-time elevations and reviews break-glass use. Bound to the approver. */
    ELEVATION_APPROVER,
    /** Sealed emergency credential of one break-glass account. Bound to that account. */
    BREAK_GLASS,
    /** SOC analyst: signs verdicts on alerts, which can trigger response playbooks. Bound to the analyst. */
    SOC_ANALYST
}

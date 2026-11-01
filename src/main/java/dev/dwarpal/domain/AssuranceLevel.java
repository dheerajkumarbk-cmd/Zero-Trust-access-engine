package dev.dwarpal.domain;

/**
 * How much a device-posture claim can be believed (fix for stress-test weakness W5:
 * "zero trust that trusts the client"). A compromised laptop will happily self-report
 * "patched"; only higher assurance levels are evidence.
 */
public enum AssuranceLevel {
    /** The device said so. Treat as a hint, not as evidence. */
    SELF_REPORTED,
    /** Reported by an endpoint agent and signed with the agent's key. */
    AGENT_SIGNED,
    /** Backed by hardware attestation (TPM / MDM). */
    HARDWARE_ATTESTED;

    public boolean atLeast(AssuranceLevel required) {
        return compareTo(required) >= 0;
    }
}

package dev.dwarpal.domain;

/**
 * What to do when a signal source (risk scorer) is unavailable while deciding on a resource
 * (stress-test weakness W8). There is deliberately no "ignore and allow" option: a missing
 * signal never silently becomes an ALLOW.
 */
public enum FailMode {
    /** Deny. Default for anything sensitive. */
    FAIL_CLOSED,
    /** Keep working in degraded mode, but require step-up authentication. */
    FAIL_STEP_UP
}

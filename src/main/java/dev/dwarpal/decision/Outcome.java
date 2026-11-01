package dev.dwarpal.decision;

/**
 * Possible answers of the Policy Engine, ordered from least to most restrictive. When several
 * stages disagree, the most restrictive answer wins (deny-overrides).
 *
 * <p>Session revocation is not an outcome of a single decision: it is carried out by the
 * Policy Administrator on live sessions, so it lives in the PA layer.
 */
public enum Outcome {
    ALLOW,
    /** Allowed with restrictions, e.g. read-only or no download (CASB/DLP-style control). */
    ALLOW_LIMITED,
    /** Allowed only after a fresh, stronger authentication. */
    STEP_UP,
    DENY;

    public static Outcome mostRestrictive(Outcome a, Outcome b) {
        return a.compareTo(b) >= 0 ? a : b;
    }
}

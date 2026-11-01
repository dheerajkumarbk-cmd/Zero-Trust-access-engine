package dev.dwarpal.policy;

/** How to resolve several matching policies (from XACML / NIST SP 800-162). */
public enum CombiningAlgorithm {
    /** The most restrictive effect among all matching policies wins. */
    DENY_OVERRIDES,
    /** The first matching policy in file order wins. */
    FIRST_APPLICABLE
}

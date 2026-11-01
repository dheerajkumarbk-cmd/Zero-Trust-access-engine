package dev.dwarpal.domain;

/**
 * What kind of thing is being accessed. Each kind corresponds to a SASE/SSE service, all
 * decided by the same engine: that single-policy property is the SASE idea Dwarpal implements.
 */
public enum ResourceKind {
    /** Internal application reached through ZTNA. */
    PRIVATE_APP,
    /** Outbound internet destination, decided like a Secure Web Gateway (SWG). */
    WEB,
    /** Data held in a SaaS service, decided like a CASB / DLP control. */
    SAAS_DATA
}

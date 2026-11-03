package dev.dwarpal.api;

/**
 * What a caller of the engine API is, decided only by its client certificate. Each endpoint lists the
 * roles it serves; a caller in no listed role gets 403.
 */
public enum CallerRole {
    /** An enforcement point: ZTNA gateway, web gateway, CASB. Opens and uses sessions, asks for decisions. */
    PEP,
    /** The administration console: privileged access and revocation. */
    ADMIN_CONSOLE,
    /** The security operations centre: revocation (the kill switch). */
    SOC
}

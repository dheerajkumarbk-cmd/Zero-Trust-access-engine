package dev.dwarpal.swg;

/** Why the web gateway refused a request. Kept for counters and the operator, never shown to the user. */
public enum BlockReason {
    /** The request itself is malformed (request line, headers, target). */
    BAD_REQUEST,
    /** The destination is not a valid host name or IP literal. */
    BAD_HOST,
    /** The destination port is not allowed for this kind of request. */
    PORT_NOT_ALLOWED,
    /** A raw IP address that is not on the allow-list. */
    RAW_IP,
    /** The host or one of its parent domains is on a blocklist. */
    BLOCKLISTED,
    /** The host name imitates another by mixing writing systems (an IDN homograph). */
    LOOKALIKE,
    /** The host resolves to a loopback, private, link-local or otherwise internal address. */
    INTERNAL_ADDRESS,
    /** The engine refused the destination. */
    DENIED,
    /** The engine wants step-up authentication, which a forward proxy cannot run. */
    STEP_UP_REQUIRED,
    /** Read-only access, but the request could write (a tunnel, or a method other than GET or HEAD). */
    READ_ONLY,
    /** The connection does not belong to a known client. */
    UNKNOWN_CLIENT,
    /** The client took too long to send its request. */
    REQUEST_TIMEOUT,
    /** The HTTP method is not one the gateway forwards. */
    METHOD_NOT_ALLOWED,
    /** The request body is too large or uses a transfer coding the gateway does not accept. */
    BODY_NOT_ACCEPTED,
    /** The destination could not be reached. */
    UPSTREAM_FAILED,
    /** Too many connections at once. */
    BUSY
}

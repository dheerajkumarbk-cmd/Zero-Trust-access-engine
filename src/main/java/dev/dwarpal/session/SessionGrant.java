package dev.dwarpal.session;

import java.time.Instant;
import java.util.Objects;

/**
 * What the client receives when a session opens. The bearer token is a secret: it is returned
 * here exactly once, and {@link #toString()} never prints it, so it cannot leak into a log line by
 * accident (CWE-532).
 */
public final class SessionGrant {

    private final String sessionId;
    private final String token;
    private final Instant expiresAt;
    private final Instant reauthDue;
    private final boolean restricted;

    SessionGrant(String sessionId, String token, Instant expiresAt, Instant reauthDue, boolean restricted) {
        this.sessionId = Objects.requireNonNull(sessionId, "sessionId");
        this.token = Objects.requireNonNull(token, "token");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
        this.reauthDue = Objects.requireNonNull(reauthDue, "reauthDue");
        this.restricted = restricted;
    }

    public String sessionId() {
        return sessionId;
    }

    /** The bearer token. Send it only to the enforcement point, never log it. */
    public String token() {
        return token;
    }

    public Instant expiresAt() {
        return expiresAt;
    }

    public Instant reauthDue() {
        return reauthDue;
    }

    public boolean restricted() {
        return restricted;
    }

    @Override
    public String toString() {
        return "SessionGrant[sessionId=" + sessionId + ", token=<redacted>, expiresAt=" + expiresAt
                + ", reauthDue=" + reauthDue + ", restricted=" + restricted + "]";
    }
}

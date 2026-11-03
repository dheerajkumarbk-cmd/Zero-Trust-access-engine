package dev.dwarpal.edge;

import dev.dwarpal.domain.Validate;

import java.time.Instant;
import java.util.Objects;

/**
 * A newly opened session, as handed to an enforcement point to pass on to the client. The token is a
 * secret: {@link #toString()} never prints it, so it cannot end up in a log line by accident (CWE-532).
 */
public final class EdgeGrant {

    private final String sessionId;
    private final String token;
    private final Instant expiresAt;
    private final Instant reauthDue;
    private final boolean restricted;

    public EdgeGrant(String sessionId, String token, Instant expiresAt, Instant reauthDue, boolean restricted) {
        this.sessionId = Validate.id(sessionId, "grant.sessionId");
        if (!EdgeHttp.wellFormedToken(token)) {
            throw new IllegalArgumentException("grant.token is not a well-formed session token");
        }
        this.token = token;
        this.expiresAt = Objects.requireNonNull(expiresAt, "grant.expiresAt");
        this.reauthDue = Objects.requireNonNull(reauthDue, "grant.reauthDue");
        this.restricted = restricted;
    }

    public String sessionId() {
        return sessionId;
    }

    /** The bearer token: give it to the client only; never log it. */
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
    public boolean equals(Object o) {
        return o instanceof EdgeGrant g && sessionId.equals(g.sessionId) && token.equals(g.token)
                && expiresAt.equals(g.expiresAt) && reauthDue.equals(g.reauthDue) && restricted == g.restricted;
    }

    @Override
    public int hashCode() {
        return Objects.hash(sessionId, expiresAt, reauthDue, restricted);
    }

    @Override
    public String toString() {
        return "EdgeGrant[sessionId=" + sessionId + ", token=<redacted>, expiresAt=" + expiresAt
                + ", reauthDue=" + reauthDue + ", restricted=" + restricted + "]";
    }
}

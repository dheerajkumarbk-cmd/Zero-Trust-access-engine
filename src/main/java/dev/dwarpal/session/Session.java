package dev.dwarpal.session;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.domain.Validate;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * One established session, as the Policy Administrator stores it. Immutable: every change
 * (a use, a re-authentication, a downgrade to read-only) replaces the whole record atomically.
 *
 * <p>The bearer token itself is never stored, only its SHA-256 hash, so a dump of the session
 * store gives an attacker nothing to present.
 *
 * @param sessionId           public identifier, safe to log and audit
 * @param tokenHash           SHA-256 (hex) of the bearer token
 * @param proofKey            the client's session public key; every use must be signed with it
 * @param lastAuthenticatedAt when the subject last proved themselves (verified MFA, or the login itself)
 * @param reauthInterval      how long that proof lasts for this resource's classification
 */
public record Session(String sessionId, String tokenHash, String subjectId, String deviceId, String resourceId,
                      boolean restricted, PublicKey proofKey, Instant openedAt, Instant lastUsedAt,
                      Instant lastAuthenticatedAt, Instant expiresAt, Duration reauthInterval) {

    public Session {
        Validate.id(sessionId, "session.id");
        Validate.id(tokenHash, "session.tokenHash");
        Validate.id(subjectId, "session.subjectId");
        Validate.id(deviceId, "session.deviceId");
        Validate.id(resourceId, "session.resourceId");
        Objects.requireNonNull(proofKey, "session.proofKey");
        if (!Ed25519.isEd25519(proofKey)) {
            throw new IllegalArgumentException("session proof key must be Ed25519");
        }
        Objects.requireNonNull(openedAt, "session.openedAt");
        Objects.requireNonNull(lastUsedAt, "session.lastUsedAt");
        Objects.requireNonNull(lastAuthenticatedAt, "session.lastAuthenticatedAt");
        Objects.requireNonNull(expiresAt, "session.expiresAt");
        Objects.requireNonNull(reauthInterval, "session.reauthInterval");
    }

    public Instant reauthDue() {
        return lastAuthenticatedAt.plus(reauthInterval);
    }

    Session used(Instant at) {
        return new Session(sessionId, tokenHash, subjectId, deviceId, resourceId, restricted, proofKey, openedAt,
                at, lastAuthenticatedAt, expiresAt, reauthInterval);
    }

    Session reauthenticated(Instant at) {
        return new Session(sessionId, tokenHash, subjectId, deviceId, resourceId, restricted, proofKey, openedAt,
                lastUsedAt, at, expiresAt, reauthInterval);
    }

    /** Read-only from now on: a downgrade is permanent for the life of the session. */
    Session downgraded() {
        return new Session(sessionId, tokenHash, subjectId, deviceId, resourceId, true, proofKey, openedAt,
                lastUsedAt, lastAuthenticatedAt, expiresAt, reauthInterval);
    }
}

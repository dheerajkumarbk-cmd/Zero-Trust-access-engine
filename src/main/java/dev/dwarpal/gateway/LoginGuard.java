package dev.dwarpal.gateway;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.guard.NonceCache;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * What a login must prove before the gateway asks Dwarpal to open a session (red-team findings B1 and
 * B7). The Policy Administrator treats authentication as evidence that lowers risk, not as a
 * requirement, so without this check a login carrying no MFA, or an MFA claim nobody signed, opened a
 * session for anyone whose subject id was known.
 *
 * <p>A login is accepted only with an MFA proof that is step-up grade, signed by a trusted identity
 * provider over this subject and device, bound to this login's session key, at most
 * {@code maxAge} old, and never seen before (a captured login cannot be replayed to open more
 * sessions and push the victim's real one past the per-user limit).
 */
final class LoginGuard {

    private final KeyRing identityProviders;
    private final Duration maxAge;
    private final NonceCache used;

    LoginGuard(KeyRing identityProviders, Duration maxAge, int capacity) {
        this.identityProviders = identityProviders;
        this.maxAge = maxAge;
        this.used = new NonceCache(maxAge.plus(KeyRing.MAX_CLOCK_SKEW), capacity);
    }

    /** Empty when the login may go to Dwarpal; otherwise the reason (for counters, never for the client). */
    Optional<String> check(EdgeRequest login, PublicKey sessionKey, Instant now) {
        Optional<AuthenticationContext> auth = login.evidence().authentication();
        Optional<SignatureProof> proof = login.evidence().authenticationProof();
        if (auth.isEmpty() || proof.isEmpty()) {
            return Optional.of("no authentication");
        }
        AuthenticationContext a = auth.get();
        if (!a.method().satisfiesStepUp()) {
            return Optional.of("authentication is not multi-factor");
        }
        if (!a.boundTo(Digests.thumbprint(sessionKey))) {
            return Optional.of("authentication not bound to the session key");
        }
        if (a.authenticatedAt().isAfter(now.plus(KeyRing.MAX_CLOCK_SKEW))
                || Duration.between(a.authenticatedAt(), now).compareTo(maxAge) > 0) {
            return Optional.of("authentication too old or in the future");
        }
        KeyRing.Result r = identityProviders.verify(KeyPurpose.IDENTITY_PROVIDER, null, proof.get(),
                SignedMessages.authentication(login.subjectId(), login.deviceId(), a, proof.get().signedAt()), now, maxAge);
        if (!r.valid()) {
            return Optional.of("authentication signature rejected");
        }
        // Counted last, so junk cannot use up anybody's proof.
        if (!used.firstUse(proof.get().signature(), now)) {
            return Optional.of("authentication already used for a login");
        }
        return Optional.empty();
    }
}

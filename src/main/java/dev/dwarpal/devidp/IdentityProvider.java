package dev.dwarpal.devidp;

import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.Validate;

import java.util.Objects;
import java.util.Optional;

/**
 * What a client needs from an identity provider: a WebAuthn challenge bound to its session key, and,
 * for the answer plus the password, a signed key-bound MFA proof. Implemented in-process by
 * {@link DevIdentityProvider#forClient} and over HTTP by the client agent. Never throws for a failed
 * login: the answer is simply empty, with no reason (no account enumeration).
 */
public interface IdentityProvider {

    /** One login attempt. Holds a password, so {@link #toString()} redacts it. */
    record Attempt(String challengeId, String subjectId, String password, WebAuthn.Assertion assertion) {
        public Attempt {
            Validate.id(challengeId, "challengeId");
            Validate.id(subjectId, "subjectId");
            Objects.requireNonNull(password, "password");
            Objects.requireNonNull(assertion, "assertion");
        }

        @Override
        public String toString() {
            return "Attempt[challengeId=" + challengeId + ", subjectId=" + subjectId + ", password=<redacted>]";
        }
    }

    /** The identity provider's statement "this subject passed WebAuthn with this session key", signed. */
    record MfaProof(AuthenticationContext authentication, SignatureProof proof) {
        public MfaProof {
            Objects.requireNonNull(authentication, "authentication");
            Objects.requireNonNull(proof, "proof");
            if (authentication.keyThumbprint().isEmpty()) {
                throw new IllegalArgumentException("MFA proofs from this identity provider are always key-bound");
            }
        }

        public Evidence addTo(Evidence e) {
            return e.withAuthentication(authentication, proof);
        }
    }

    /**
     * @param keyThumbprint {@code Digests.thumbprint} of the session public key the proof will be bound to
     */
    Optional<WebAuthn.Challenge> challenge(String subjectId, String deviceId, String keyThumbprint);

    Optional<MfaProof> authenticate(Attempt attempt);
}

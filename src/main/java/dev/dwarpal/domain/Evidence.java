package dev.dwarpal.domain;

import dev.dwarpal.crypto.SignatureProof;

import java.util.Objects;
import java.util.Optional;

/**
 * Signed claims that travel with a request. Unsigned or invalid claims are not errors; they are
 * simply not believed (posture drops to SELF_REPORTED, authentication is ignored).
 *
 * @param authentication      what the identity provider says about the current login
 * @param authenticationProof identity provider's signature over {@code authentication}
 * @param postureProof        endpoint agent's signature over the device posture
 */
public record Evidence(Optional<AuthenticationContext> authentication,
                       Optional<SignatureProof> authenticationProof,
                       Optional<SignatureProof> postureProof) {

    public Evidence {
        Objects.requireNonNull(authentication, "evidence.authentication");
        Objects.requireNonNull(authenticationProof, "evidence.authenticationProof");
        Objects.requireNonNull(postureProof, "evidence.postureProof");
    }

    public static Evidence none() {
        return new Evidence(Optional.empty(), Optional.empty(), Optional.empty());
    }

    public Evidence withAuthentication(AuthenticationContext auth, SignatureProof proof) {
        return new Evidence(Optional.of(auth), Optional.ofNullable(proof), postureProof);
    }

    public Evidence withPostureProof(SignatureProof proof) {
        return new Evidence(authentication, authenticationProof, Optional.of(proof));
    }
}

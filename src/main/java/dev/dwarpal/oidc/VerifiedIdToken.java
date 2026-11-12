package dev.dwarpal.oidc;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * What a caller may rely on after {@link IdTokenVerifier} has accepted a token: the signature, issuer,
 * audience, nonce and times were all checked. There is deliberately no map of raw claims, so nothing
 * unchecked can be read from here.
 *
 * @param subject   the {@code sub} claim (1 to 255 printable ASCII characters)
 * @param issuer    the {@code iss} claim (equal to the configured issuer)
 * @param acr       the authentication context class, or the empty string when the token had none
 * @param amr       authentication methods (at most 16), possibly empty; unmodifiable
 * @param authTime  when the person authenticated, if the token says
 * @param issuedAt  the {@code iat} claim
 * @param expiresAt the {@code exp} claim
 * @param keyId     the {@code kid} of the key that verified the token, or the empty string if that key has none
 * @param algorithm the JWS algorithm that was used (RS256, ES256 or EdDSA)
 */
public record VerifiedIdToken(String subject, String issuer, String acr, List<String> amr,
                              Optional<Instant> authTime, Instant issuedAt, Instant expiresAt, String keyId,
                              String algorithm) {

    public VerifiedIdToken {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(acr, "acr");
        amr = List.copyOf(amr);
        Objects.requireNonNull(authTime, "authTime");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(algorithm, "algorithm");
    }
}

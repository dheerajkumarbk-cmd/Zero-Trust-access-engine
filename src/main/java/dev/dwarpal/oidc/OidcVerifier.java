package dev.dwarpal.oidc;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/**
 * The convenient way to verify ID tokens from one provider: {@link IdTokenVerifier} with the keys
 * of a {@link JwksSource} and the current time from a clock. If a token names a key the held set
 * does not have (the provider may have rotated), the key source is asked once more and the token is
 * tried once more; the source limits how often that reaches the network (once per 30 seconds), so a
 * flood of tokens with invented key ids cannot make the application hammer the provider.
 */
public final class OidcVerifier {

    private final IdTokenVerifier verifier;
    private final JwksSource keys;
    private final Clock clock;

    public OidcVerifier(OidcPolicy policy, JwksSource keys, Clock clock) {
        this.verifier = new IdTokenVerifier(policy);
        this.keys = Objects.requireNonNull(keys, "keys");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Fetches the provider's metadata over https and builds a verifier for it.
     *
     * @throws OidcException if the metadata cannot be fetched or is not acceptable
     */
    public static OidcVerifier discover(OidcPolicy policy, Clock clock) {
        OidcDiscovery discovery = OidcDiscovery.fetch(policy.issuer());
        return new OidcVerifier(policy, new JwksSource(discovery, clock), clock);
    }

    /** Verifies a token with no limit on how long ago the person authenticated. */
    public VerifiedIdToken verify(String token, String expectedNonce) {
        return verify(token, expectedNonce, null);
    }

    /**
     * Verifies a token.
     *
     * @param maxAuthAge if not null, the token must carry {@code auth_time} and it must be at most this old
     * @throws IllegalArgumentException if {@code expectedNonce} is null or blank
     * @throws OidcException            if the token is refused or no keys are available
     */
    public VerifiedIdToken verify(String token, String expectedNonce, Duration maxAuthAge) {
        if (expectedNonce == null || expectedNonce.isBlank()) {
            throw new IllegalArgumentException("an expected nonce is required");
        }
        try {
            return verifier.verify(token, keys.current(), expectedNonce, clock.instant(), maxAuthAge);
        } catch (OidcException e) {
            if (e.reason() != OidcException.Reason.KEY_NOT_FOUND) {
                throw e;
            }
        }
        return verifier.verify(token, keys.refreshForUnknownKey(), expectedNonce, clock.instant(), maxAuthAge);
    }
}

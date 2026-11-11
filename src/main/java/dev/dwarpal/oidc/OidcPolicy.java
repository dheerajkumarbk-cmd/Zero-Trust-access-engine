package dev.dwarpal.oidc;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/**
 * What an ID token must satisfy to be accepted for one identity provider and one client.
 *
 * <p>Only RS256, ES256 and EdDSA can be listed. A list that names HS256 (or any other value)
 * is refused when the policy is built: a shared-secret algorithm has no place in a flow where the
 * public keys are the only keys the verifier holds (RFC 8725, section 3.1).
 *
 * @param issuer      exact value the {@code iss} claim must have
 * @param clientId    this application's client id; the {@code aud} claim must contain it
 * @param algorithms  accepted values of the {@code alg} header
 * @param skew        clock difference tolerated in either direction (at most 5 minutes)
 * @param maxTokenAge longest time since {@code iat} (between 1 minute and 24 hours)
 */
public record OidcPolicy(String issuer, String clientId, Set<String> algorithms, Duration skew,
                         Duration maxTokenAge) {

    public static final String RS256 = "RS256";
    public static final String ES256 = "ES256";
    public static final String EDDSA = "EdDSA";

    private static final Set<String> SUPPORTED = Set.of(RS256, ES256, EDDSA);
    private static final int MAX_ISSUER_CHARS = 200;
    private static final int MAX_CLIENT_ID_CHARS = 255;
    private static final Duration MAX_SKEW = Duration.ofMinutes(5);
    private static final Duration MIN_AGE = Duration.ofMinutes(1);
    private static final Duration MAX_AGE = Duration.ofHours(24);

    public OidcPolicy {
        if (issuer == null || issuer.isBlank() || issuer.length() > MAX_ISSUER_CHARS) {
            throw new IllegalArgumentException("issuer must be 1 to " + MAX_ISSUER_CHARS + " characters");
        }
        if (clientId == null || clientId.isBlank() || clientId.length() > MAX_CLIENT_ID_CHARS) {
            throw new IllegalArgumentException("client id must be 1 to " + MAX_CLIENT_ID_CHARS + " characters");
        }
        Objects.requireNonNull(algorithms, "algorithms");
        algorithms = Set.copyOf(algorithms);
        if (algorithms.isEmpty() || !SUPPORTED.containsAll(algorithms)) {
            throw new IllegalArgumentException("algorithms must be a non-empty subset of RS256, ES256, EdDSA");
        }
        Objects.requireNonNull(skew, "skew");
        if (skew.isNegative() || skew.compareTo(MAX_SKEW) > 0) {
            throw new IllegalArgumentException("skew must be between zero and 5 minutes");
        }
        Objects.requireNonNull(maxTokenAge, "maxTokenAge");
        if (maxTokenAge.compareTo(MIN_AGE) < 0 || maxTokenAge.compareTo(MAX_AGE) > 0) {
            throw new IllegalArgumentException("maxTokenAge must be between 1 minute and 24 hours");
        }
    }

    /** The default policy: RS256, ES256 and EdDSA, skew of 2 minutes, tokens up to 10 minutes old. */
    public static OidcPolicy of(String issuer, String clientId) {
        return new OidcPolicy(issuer, clientId, SUPPORTED, Duration.ofMinutes(2), Duration.ofMinutes(10));
    }
}

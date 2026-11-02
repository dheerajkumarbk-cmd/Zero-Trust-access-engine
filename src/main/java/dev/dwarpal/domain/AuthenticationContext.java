package dev.dwarpal.domain;

import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

/**
 * "This subject authenticated with this method at this time", as asserted by the identity provider.
 *
 * @param keyThumbprint when present, the SHA-256 thumbprint (64 hex characters) of the client's session
 *                      public key that the identity provider saw during this authentication. The proof is
 *                      then bound to that key (as in DPoP), so it only counts for whoever holds the key:
 *                      a captured proof cannot be replayed with another key.
 */
public record AuthenticationContext(AuthMethod method, Instant authenticatedAt, Optional<String> keyThumbprint) {

    public AuthenticationContext {
        Objects.requireNonNull(method, "auth.method");
        Objects.requireNonNull(authenticatedAt, "auth.authenticatedAt");
        Objects.requireNonNull(keyThumbprint, "auth.keyThumbprint");
        keyThumbprint.ifPresent(t -> {
            if (t.length() != 64 || !HexFormat.isHexDigit(t.charAt(0)) || !t.chars().allMatch(HexFormat::isHexDigit)
                    || !t.equals(t.toLowerCase(java.util.Locale.ROOT))) {
                throw new IllegalArgumentException("auth.keyThumbprint must be 64 lower-case hex characters");
            }
        });
    }

    /** An authentication not bound to any client key (accepted by the engine; not by the Policy Administrator). */
    public AuthenticationContext(AuthMethod method, Instant authenticatedAt) {
        this(method, authenticatedAt, Optional.empty());
    }

    public boolean boundTo(String thumbprint) {
        return keyThumbprint.isPresent() && keyThumbprint.get().equals(thumbprint);
    }
}

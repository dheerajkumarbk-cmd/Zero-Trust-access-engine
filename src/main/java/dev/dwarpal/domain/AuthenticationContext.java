package dev.dwarpal.domain;

import java.time.Instant;
import java.util.Objects;

/** "This subject authenticated with this method at this time", as asserted by the identity provider. */
public record AuthenticationContext(AuthMethod method, Instant authenticatedAt) {

    public AuthenticationContext {
        Objects.requireNonNull(method, "auth.method");
        Objects.requireNonNull(authenticatedAt, "auth.authenticatedAt");
    }
}

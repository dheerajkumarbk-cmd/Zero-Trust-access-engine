package dev.dwarpal.api;

import dev.dwarpal.domain.Validate;
import dev.dwarpal.edge.TlsContexts;

import javax.security.auth.x500.X500Principal;
import java.util.Objects;

/**
 * One configured caller of the API: the exact certificate subject it must present, and its role.
 *
 * @param name    short name used in the audit trail and as the revocation actor (for example {@code gateway})
 * @param subject the whole certificate subject in RFC 2253 form, compared exactly and case-sensitively
 */
public record Caller(String name, String subject, CallerRole role) {

    public Caller {
        Validate.id(name, "caller.name");
        Objects.requireNonNull(subject, "caller.subject");
        Objects.requireNonNull(role, "caller.role");
        if (!new X500Principal(subject).getName(X500Principal.RFC2253).equals(subject)) {
            throw new IllegalArgumentException("caller.subject must be in RFC 2253 form");
        }
    }

    public static Caller of(String name, X500Principal principal, CallerRole role) {
        return new Caller(name, principal.getName(X500Principal.RFC2253), role);
    }

    /** A Dwarpal component certificate from the development CA: subject {@code CN=name}. */
    public static Caller component(String name, CallerRole role) {
        return of(name, TlsContexts.component(name), role);
    }
}

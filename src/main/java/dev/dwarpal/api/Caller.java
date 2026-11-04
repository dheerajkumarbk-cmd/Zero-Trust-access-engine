package dev.dwarpal.api;

import dev.dwarpal.domain.Validate;
import dev.dwarpal.edge.TlsContexts;

import javax.security.auth.x500.X500Principal;
import java.util.List;
import java.util.Objects;

/**
 * One configured caller of the API: the exact certificate subject it must present, its role and, for an
 * enforcement point, the resources it may ask about.
 *
 * @param name      short name used in the audit trail and as the revocation actor (for example {@code gateway})
 * @param subject   the whole certificate subject in RFC 2253 form, compared exactly and case-sensitively
 * @param resources for a {@link CallerRole#PEP}: required, the resource ids it fronts; an entry ending in
 *                  {@code *} is a prefix ({@code web:*}), {@code *} alone is every resource. Empty for the
 *                  other roles, which never ask about resources. A compromised web gateway therefore cannot
 *                  open or use sessions for the wiki (Layer 4 integration request R7)
 */
public record Caller(String name, String subject, CallerRole role, List<String> resources) {

    public static final int MAX_RESOURCES = 256;

    public Caller {
        Validate.id(name, "caller.name");
        Objects.requireNonNull(subject, "caller.subject");
        Objects.requireNonNull(role, "caller.role");
        if (!new X500Principal(subject).getName(X500Principal.RFC2253).equals(subject)) {
            throw new IllegalArgumentException("caller.subject must be in RFC 2253 form");
        }
        resources = List.copyOf(resources);
        if (role == CallerRole.PEP && resources.isEmpty()) {
            throw new IllegalArgumentException("an enforcement point must be scoped to the resources it fronts");
        }
        if (role != CallerRole.PEP && !resources.isEmpty()) {
            throw new IllegalArgumentException("only enforcement points ask about resources");
        }
        if (resources.size() > MAX_RESOURCES) {
            throw new IllegalArgumentException("too many resource entries");
        }
        for (String r : resources) {
            if (!r.equals("*")) {
                Validate.id(r.endsWith("*") ? r.substring(0, r.length() - 1) : r, "caller.resources");
            }
        }
    }

    /** A caller that does not ask about resources (administrative console, SOC). */
    public Caller(String name, String subject, CallerRole role) {
        this(name, subject, role, List.of());
    }

    public static Caller of(String name, X500Principal principal, CallerRole role) {
        return new Caller(name, principal.getName(X500Principal.RFC2253), role);
    }

    /** An enforcement point that may ask only about {@code resources}. */
    public static Caller pep(String name, X500Principal principal, String... resources) {
        return new Caller(name, principal.getName(X500Principal.RFC2253), CallerRole.PEP, List.of(resources));
    }

    /** A Dwarpal component certificate from the development CA: subject {@code CN=name}. */
    public static Caller component(String name, CallerRole role) {
        return of(name, TlsContexts.component(name), role);
    }

    /** An enforcement point with a development CA certificate {@code CN=name}, scoped to {@code resources}. */
    public static Caller pepComponent(String name, String... resources) {
        return pep(name, TlsContexts.component(name), resources);
    }

    /** Whether this caller may ask about {@code resourceId}. */
    public boolean mayAsk(String resourceId) {
        for (String r : resources) {
            if (r.equals("*") || (r.endsWith("*") ? resourceId.startsWith(r.substring(0, r.length() - 1))
                    : r.equals(resourceId))) {
                return true;
            }
        }
        return false;
    }
}

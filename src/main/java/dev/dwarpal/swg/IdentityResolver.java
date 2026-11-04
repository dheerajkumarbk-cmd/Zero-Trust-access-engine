package dev.dwarpal.swg;

import java.net.InetAddress;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Finds the identity behind a proxy connection. A connection with no identity is refused before any
 * destination is looked at: an anonymous user of a forward proxy is exactly what an SWG must not have.
 */
@FunctionalInterface
public interface IdentityResolver {

    Optional<WebIdentity> resolve(InetAddress client);

    /** Fixed identities per client address, as registered by the client agents. */
    static IdentityResolver fixed(Map<InetAddress, WebIdentity> identities) {
        Map<InetAddress, WebIdentity> copy = Map.copyOf(Objects.requireNonNull(identities, "identities"));
        return client -> client == null ? Optional.empty() : Optional.ofNullable(copy.get(client));
    }
}

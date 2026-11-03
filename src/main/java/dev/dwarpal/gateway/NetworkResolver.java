package dev.dwarpal.gateway;

import dev.dwarpal.domain.NetworkContext;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Map;
import java.util.Objects;

/**
 * Turns the client's real socket address into the network context the engine judges. Never fed from
 * request headers ({@code X-Forwarded-For} and friends are the client's word, not a fact).
 */
@FunctionalInterface
public interface NetworkResolver {

    NetworkContext resolve(InetAddress client);

    /** The address as an identifier: IPv6 scope ids ({@code %eth0}) are dropped. */
    static String ip(InetAddress client) {
        String s = client.getHostAddress();
        int scope = client instanceof Inet6Address ? s.indexOf('%') : -1;
        return scope >= 0 ? s.substring(0, scope) : s;
    }

    /**
     * A fixed table, standing in for a GeoIP database on a laptop: known addresses get their entry, the
     * rest get {@code unknown} (same place, ASN and accuracy as the template, the real IP).
     */
    static NetworkResolver fixed(Map<String, NetworkContext> known, NetworkContext unknown) {
        Map<String, NetworkContext> table = Map.copyOf(known);
        Objects.requireNonNull(unknown, "unknown");
        return client -> {
            String ip = ip(client);
            NetworkContext k = table.get(ip);
            return k != null ? k : new NetworkContext(ip, unknown.asn(), unknown.country(), unknown.latitude(),
                    unknown.longitude(), unknown.accuracyKm());
        };
    }
}

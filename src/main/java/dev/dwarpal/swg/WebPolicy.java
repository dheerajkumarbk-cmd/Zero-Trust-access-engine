package dev.dwarpal.swg;

import dev.dwarpal.domain.Validate;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * What the web filter does locally, before and alongside the engine: which category is which web
 * resource, which ports may be used, which raw IP addresses are allowed.
 *
 * <p>Categories map to resource ids, not to classifications: the classification of {@code web:general}
 * lives in the directory on the engine side, so this file cannot downgrade a destination.
 *
 * <p>Immutable. The policy answers questions instead of handing out its sets, so nothing outside can
 * hold a reference to them.
 */
public final class WebPolicy {

    public static final String UNCATEGORISED = "web:uncategorised";
    public static final String MALICIOUS = "web:malicious";

    private final Map<String, String> categoryResources;
    private final String uncategorisedResource;
    private final String maliciousResource;
    private final Set<Integer> tunnelPorts;
    private final Set<Integer> httpPorts;
    private final Set<String> rawIps;
    private final Set<String> internalAddresses;

    private WebPolicy(Builder b) {
        categoryResources = Map.copyOf(b.categories);
        categoryResources.values().forEach(v -> Validate.id(v, "categoryResources"));
        uncategorisedResource = Validate.id(b.uncategorised, "uncategorisedResource");
        maliciousResource = Validate.id(b.malicious, "maliciousResource");
        tunnelPorts = ports(b.tunnelPorts);
        httpPorts = ports(b.httpPorts);
        rawIps = canonicalIps(b.rawIps);
        internalAddresses = canonicalIps(b.internal);
    }

    /** No categories, tunnels to 443, plain HTTP to 80, no raw IPs, no internal destinations. */
    public static WebPolicy defaults() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** The web resource for a category; categories not listed (and hosts without one) are uncategorised. */
    public String resourceFor(Optional<String> category) {
        return category.map(categoryResources::get).orElse(uncategorisedResource);
    }

    public String uncategorisedResource() {
        return uncategorisedResource;
    }

    /** The resource blocklisted, look-alike and other locally blocked hosts are decided as. */
    public String maliciousResource() {
        return maliciousResource;
    }

    public boolean tunnelPortAllowed(int port) {
        return tunnelPorts.contains(port);
    }

    public boolean httpPortAllowed(int port) {
        return httpPorts.contains(port);
    }

    /** True if this IP address (canonical form, see {@link HostName}) may be used as a destination directly. */
    public boolean rawIpAllowed(String canonicalIp) {
        return rawIps.contains(canonicalIp);
    }

    /** True if destinations may resolve to this internal address (normally none may). */
    public boolean internalAddressAllowed(String canonicalIp) {
        return internalAddresses.contains(canonicalIp);
    }

    private static Set<Integer> ports(Set<Integer> ports) {
        Set<Integer> copy = Set.copyOf(ports);
        for (int p : copy) {
            if (p < 1 || p > 65535) {
                throw new IllegalArgumentException("port out of range");
            }
        }
        return copy;
    }

    private static Set<String> canonicalIps(Set<String> ips) {
        Set<String> out = new HashSet<>();
        for (String ip : ips) {
            String s = ip.indexOf(':') >= 0 && !ip.startsWith("[") ? "[" + ip + "]" : ip;
            HostName h = HostName.parse(s).filter(HostName::ipLiteral)
                    .orElseThrow(() -> new IllegalArgumentException("not an IP address literal"));
            out.add(h.value());
        }
        return Set.copyOf(out);
    }

    public static final class Builder {
        private final Map<String, String> categories = new HashMap<>();
        private String uncategorised = UNCATEGORISED;
        private String malicious = MALICIOUS;
        private Set<Integer> tunnelPorts = Set.of(443);
        private Set<Integer> httpPorts = Set.of(80);
        private Set<String> rawIps = Set.of();
        private Set<String> internal = Set.of();

        private Builder() {
        }

        public Builder category(String category, String resourceId) {
            categories.put(Objects.requireNonNull(category, "category"), resourceId);
            return this;
        }

        public Builder uncategorised(String resourceId) {
            uncategorised = resourceId;
            return this;
        }

        public Builder malicious(String resourceId) {
            malicious = resourceId;
            return this;
        }

        public Builder tunnelPorts(Set<Integer> v) {
            tunnelPorts = Set.copyOf(v);
            return this;
        }

        public Builder httpPorts(Set<Integer> v) {
            httpPorts = Set.copyOf(v);
            return this;
        }

        public Builder allowRawIps(Set<String> v) {
            rawIps = Set.copyOf(v);
            return this;
        }

        public Builder allowInternalAddresses(Set<String> v) {
            internal = Set.copyOf(v);
            return this;
        }

        public WebPolicy build() {
            return new WebPolicy(this);
        }
    }
}

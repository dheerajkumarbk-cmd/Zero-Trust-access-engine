package dev.dwarpal.swg;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * The local half of the web gateway's decision: parse and normalise the destination, then look it up in
 * the blocklist and the category file. Works on host names only (no TLS interception), so HTTPS needs no
 * certificate on the client.
 *
 * <p>The lists come through suppliers, so an operator can load new files and swap them in at once; a
 * request sees either the old list or the new one.
 */
public final class WebFilter {

    private final WebPolicy policy;
    private final Supplier<DomainList> blocklist;
    private final Supplier<CategoryMap> categories;

    public WebFilter(WebPolicy policy, Supplier<DomainList> blocklist, Supplier<CategoryMap> categories) {
        this.policy = Objects.requireNonNull(policy, "policy");
        this.blocklist = Objects.requireNonNull(blocklist, "blocklist");
        this.categories = Objects.requireNonNull(categories, "categories");
    }

    public WebPolicy policy() {
        return policy;
    }

    /**
     * Classifies an authority ({@code host}, {@code host:port}, {@code [v6]:port}) for a tunnel
     * ({@code CONNECT}) or a plain HTTP request. Empty if the authority is not a valid destination.
     */
    public Optional<Destination> classify(String authority, boolean tunnel) {
        Optional<Authority> a = Authority.parse(authority, tunnel ? 443 : 80);
        if (a.isEmpty()) {
            return Optional.empty();
        }
        HostName host = a.get().host();
        int port = a.get().port();
        if (!(tunnel ? policy.tunnelPortAllowed(port) : policy.httpPortAllowed(port))) {
            return Optional.of(blocked(host, port, BlockReason.PORT_NOT_ALLOWED, Optional.empty()));
        }
        if (Objects.requireNonNull(blocklist.get(), "blocklist").matches(host)) {
            return Optional.of(blocked(host, port, BlockReason.BLOCKLISTED, Optional.empty()));
        }
        if (host.mixedScript()) {
            return Optional.of(blocked(host, port, BlockReason.LOOKALIKE, Optional.empty()));
        }
        if (host.ipLiteral() && !policy.rawIpAllowed(host.value())) {
            return Optional.of(new Destination(host, port, policy.uncategorisedResource(), Optional.empty(),
                    Optional.of(BlockReason.RAW_IP)));
        }
        Optional<String> category = Objects.requireNonNull(categories.get(), "categories").category(host);
        return Optional.of(new Destination(host, port, policy.resourceFor(category), category, Optional.empty()));
    }

    private Destination blocked(HostName host, int port, BlockReason reason, Optional<String> category) {
        return new Destination(host, port, policy.maliciousResource(), category, Optional.of(reason));
    }

    /** {@code host[:port]} with no user information. */
    record Authority(HostName host, int port) {

        static Optional<Authority> parse(String s, int defaultPort) {
            if (s == null || s.isEmpty() || s.length() > 1100) {
                return Optional.empty();
            }
            String host;
            String port;
            if (s.charAt(0) == '[') {
                int close = s.indexOf(']');
                if (close < 0) {
                    return Optional.empty();
                }
                host = s.substring(0, close + 1);
                String rest = s.substring(close + 1);
                if (rest.isEmpty()) {
                    port = null;
                } else if (rest.charAt(0) == ':') {
                    port = rest.substring(1);
                } else {
                    return Optional.empty();
                }
            } else {
                int colon = s.lastIndexOf(':');
                host = colon >= 0 ? s.substring(0, colon) : s;
                port = colon >= 0 ? s.substring(colon + 1) : null;
            }
            int p = port == null ? defaultPort : port(port);
            if (p < 0) {
                return Optional.empty();
            }
            return HostName.parse(host).map(h -> new Authority(h, p));
        }

        private static int port(String s) {
            if (s.isEmpty() || s.length() > 5) {
                return -1;
            }
            int v = 0;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c < '0' || c > '9') {
                    return -1;
                }
                v = v * 10 + (c - '0');
            }
            return v >= 1 && v <= 65535 ? v : -1;
        }
    }
}

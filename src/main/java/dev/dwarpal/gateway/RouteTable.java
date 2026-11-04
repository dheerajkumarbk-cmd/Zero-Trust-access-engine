package dev.dwarpal.gateway;

import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.edge.EdgeHttp;

import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * Which path prefixes the gateway fronts, which resource each one is, where its application listens,
 * and which sub-paths are downloads or administration. The client agent holds the same table, so the
 * action it signs is the action the gateway checks.
 *
 * <p>Text form, one entry per line ({@code #} starts a comment):
 * <pre>
 *   route    /wiki  wiki  http://127.0.0.1:9000
 *   download /wiki/download
 *   admin    /wiki/admin
 * </pre>
 * {@code download} and {@code admin} lines belong to the route above them.
 */
public final class RouteTable {

    /** One fronted application. */
    public record Route(String prefix, String resourceId, URI upstream, List<String> downloads, List<String> admin) {
        public Route {
            prefix = checkedPrefix(prefix);
            if (prefix.equals("/") || RequestPath.under(prefix, ZtnaGateway.RESERVED_PREFIX)) {
                throw new IllegalArgumentException("route prefix must be a path below / outside the gateway's own");
            }
            Validate.id(resourceId, "route.resourceId");
            Objects.requireNonNull(upstream, "route.upstream");
            if (!"http".equals(upstream.getScheme()) && !"https".equals(upstream.getScheme())
                    || upstream.getHost() == null || upstream.getRawPath() != null && !upstream.getRawPath().isEmpty()
                    || upstream.getRawQuery() != null || upstream.getRawUserInfo() != null) {
                throw new IllegalArgumentException("route.upstream must be scheme://host:port only");
            }
            downloads = List.copyOf(downloads);
            admin = List.copyOf(admin);
            for (String p : downloads) {
                belowRoute(checkedPrefix(p), prefix);
            }
            for (String p : admin) {
                belowRoute(checkedPrefix(p), prefix);
            }
        }

        /** The action a request performs on this route, or empty for a method that has none. */
        public Optional<Action> action(String method, String path) {
            return EdgeHttp.action(method, matchesAny(path, downloads), matchesAny(path, admin));
        }

        /**
         * Compared case-insensitively (B3): many applications match paths that way, and a gateway that
         * reads {@code /wiki/Admin} as an ordinary write lets administration through. Erring towards the
         * stricter action is always safe.
         */
        private static boolean matchesAny(String path, List<String> prefixes) {
            String lower = path.toLowerCase(Locale.ROOT);
            for (String p : prefixes) {
                if (RequestPath.under(lower, p.toLowerCase(Locale.ROOT))) {
                    return true;
                }
            }
            return false;
        }

        private static void belowRoute(String sub, String prefix) {
            if (!RequestPath.under(sub, prefix)) {
                throw new IllegalArgumentException("download and admin paths must lie below their route");
            }
        }
    }

    private final List<Route> routes;

    public RouteTable(List<Route> routes) {
        List<Route> copy = new ArrayList<>(routes);
        for (int i = 0; i < copy.size(); i++) {
            for (int j = i + 1; j < copy.size(); j++) {
                Route a = copy.get(i);
                Route b = copy.get(j);
                if (RequestPath.under(a.prefix(), b.prefix()) || RequestPath.under(b.prefix(), a.prefix())) {
                    throw new IllegalArgumentException("route prefixes must not overlap");
                }
                if (a.resourceId().equals(b.resourceId())) {
                    throw new IllegalArgumentException("each resource has one route");
                }
            }
        }
        if (copy.isEmpty()) {
            throw new IllegalArgumentException("at least one route");
        }
        copy.sort(Comparator.comparing(Route::prefix));
        this.routes = List.copyOf(copy);
    }

    /** The route serving {@code path} (already checked by {@link RequestPath#path}), if any. */
    public Optional<Route> match(String path) {
        for (Route r : routes) {
            if (RequestPath.under(path, r.prefix())) {
                return Optional.of(r);
            }
        }
        return Optional.empty();
    }

    /** The route of a resource, if the gateway fronts it. */
    public Optional<Route> forResource(String resourceId) {
        return routes.stream().filter(r -> r.resourceId().equals(resourceId)).findFirst();
    }

    public List<Route> routes() {
        return routes;
    }

    /** Parses the text form; errors name the line, never echo its content. */
    public static RouteTable parse(String text) {
        Objects.requireNonNull(text, "text");
        if (text.length() > 64 * 1024) {
            throw new IllegalArgumentException("route table too large");
        }
        List<Route> out = new ArrayList<>();
        String prefix = null;
        String resource = null;
        URI upstream = null;
        List<String> downloads = new ArrayList<>();
        List<String> admin = new ArrayList<>();
        String[] lines = text.split("\n", -1);
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n].strip();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] f = line.split("\\s+");
            try {
                switch (f[0]) {
                    case "route" -> {
                        require(f.length == 4);
                        if (prefix != null) {
                            out.add(new Route(prefix, resource, upstream, downloads, admin));
                        }
                        prefix = f[1];
                        resource = f[2];
                        upstream = URI.create(f[3]);
                        downloads = new ArrayList<>();
                        admin = new ArrayList<>();
                    }
                    case "download", "admin" -> {
                        require(f.length == 2 && prefix != null);
                        (f[0].equals("download") ? downloads : admin).add(f[1]);
                    }
                    default -> throw new IllegalArgumentException("unknown keyword");
                }
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("route table line " + (n + 1) + " is invalid", e);
            }
        }
        if (prefix != null) {
            out.add(new Route(prefix, resource, upstream, downloads, admin));
        }
        return new RouteTable(out);
    }

    private static void require(boolean ok) {
        if (!ok) {
            throw new IllegalArgumentException("wrong number of fields");
        }
    }

    private static String checkedPrefix(String p) {
        Objects.requireNonNull(p, "prefix");
        if (p.length() > 1 && p.endsWith("/") || RequestPath.path(p).isEmpty()) {
            throw new IllegalArgumentException("prefix must be a plain path without a trailing slash");
        }
        return p;
    }
}

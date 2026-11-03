package dev.dwarpal.gateway;

import dev.dwarpal.edge.EdgeHttp;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Which headers cross the gateway, in each direction. Names are compared lower-case with underscores
 * read as dashes, because some servers fold one into the other ({@code X_Forwarded_For} becomes
 * {@code X-Forwarded-For} in CGI-style frameworks).
 */
final class HeaderPolicy {

    /** RFC 9110 section 7.6.1 hop-by-hop headers, plus the old proxy ones. */
    private static final Set<String> HOP_BY_HOP = Set.of("connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade");
    /** Set by the HTTP machinery itself on each hop; never copied. */
    private static final Set<String> FRAMING = Set.of("host", "content-length", "expect", "date");
    /** Client claims about where it is; the gateway knows the real address and sets its own. */
    private static final Set<String> CLIENT_LOCATION = Set.of("forwarded", "x-forwarded-for", "x-forwarded-host",
            "x-forwarded-proto", "x-forwarded-port", "x-real-ip", "x-client-ip", "true-client-ip");
    /** Headers and parameters with which frameworks let a request claim another method (B4). */
    private static final Set<String> METHOD_OVERRIDE = Set.of("x-http-method-override", "x-http-method",
            "x-method-override");
    private static final Pattern METHOD_PARAM = Pattern.compile("(?i)(^|&)(_method|%5fmethod)=");
    /** Response headers that may carry a URL of the application. */
    private static final Set<String> URL_HEADERS = Set.of("location", "content-location");
    private static final Set<String> LOOPBACK_NAMES = Set.of("localhost", "127.0.0.1", "[::1]", "localhost.");
    private static final Pattern TOKEN = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}");

    private HeaderPolicy() {
    }

    static String normal(String name) {
        return name.strip().toLowerCase(Locale.ROOT).replace('_', '-');
    }

    /** The names a {@code Connection} header lists are hop-by-hop for this message too. */
    static Set<String> connectionListed(Map<String, List<String>> headers) {
        Set<String> out = new HashSet<>();
        for (Map.Entry<String, List<String>> h : headers.entrySet()) {
            if (h.getKey() != null && normal(h.getKey()).equals("connection")) {
                for (String v : h.getValue()) {
                    for (String n : v.split(",")) {
                        out.add(normal(n));
                    }
                }
            }
        }
        return out;
    }

    /** May this client header go to the application? */
    static boolean forwardRequest(String name, Set<String> connectionListed) {
        if (name == null || !TOKEN.matcher(name).matches()) {
            return false;
        }
        String n = normal(name);
        return !EdgeHttp.clientOnly(name) && !HOP_BY_HOP.contains(n) && !FRAMING.contains(n)
                && !CLIENT_LOCATION.contains(n) && !connectionListed.contains(n);
    }

    static boolean overridesMethod(Set<String> names) {
        for (String n : names) {
            if (n != null && METHOD_OVERRIDE.contains(normal(n))) {
                return true;
            }
        }
        return false;
    }

    static boolean overridesMethodInQuery(String rawQuery) {
        return METHOD_PARAM.matcher(rawQuery).find();
    }

    /**
     * The value to send the client, or empty to drop it: no CR, LF or NUL; and a URL pointing at the
     * application's own address becomes a gateway-relative path, so the internal address never leaks
     * and the client is never invited to go around the gateway (B5).
     */
    static Optional<String> responseValue(String name, String value, URI upstream) {
        if (!EdgeHttp.safeHeaderValue(value)) {
            return Optional.empty();
        }
        if (!URL_HEADERS.contains(normal(name))) {
            return Optional.of(value);
        }
        URI u;
        try {
            u = new URI(value.strip());
        } catch (URISyntaxException e) {
            return Optional.empty();
        }
        if (!u.isAbsolute()) {
            return Optional.of(value);
        }
        boolean sameHost = u.getHost() != null && (upstream.getHost().equalsIgnoreCase(u.getHost())
                || LOOPBACK_NAMES.contains(u.getHost().toLowerCase(Locale.ROOT)) && loopback(upstream.getHost()));
        boolean internal = sameHost && port(upstream) == port(u);
        if (!internal) {
            return Optional.of(value);
        }
        String path = u.getRawPath() == null || u.getRawPath().isEmpty() ? "/" : u.getRawPath();
        return Optional.of(path + (u.getRawQuery() == null ? "" : "?" + u.getRawQuery()));
    }

    private static boolean loopback(String host) {
        return LOOPBACK_NAMES.contains(host.toLowerCase(Locale.ROOT)) || host.startsWith("127.");
    }

    private static int port(URI u) {
        return u.getPort() != -1 ? u.getPort() : "https".equalsIgnoreCase(u.getScheme()) ? 443 : 80;
    }

    /** May this application header go back to the client? */
    static boolean forwardResponse(String name, Set<String> connectionListed) {
        if (name == null || !TOKEN.matcher(name).matches()) {
            return false;
        }
        String n = normal(name);
        return !HOP_BY_HOP.contains(n) && !FRAMING.contains(n) && !connectionListed.contains(n)
                && !EdgeHttp.clientOnly(name) && !n.equals("www-authenticate");
    }
}

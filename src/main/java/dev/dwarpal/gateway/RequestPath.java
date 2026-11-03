package dev.dwarpal.gateway;

import java.util.Optional;

/**
 * Strict request-target checks, shared by the gateway and the client agent so both compute the same
 * route and action for a path.
 *
 * <p>The gateway decides on the path it sees, and the application acts on the path it sees. Any
 * difference between the two (a {@code ..} the application resolves, a {@code %2F} it decodes, a
 * {@code ;param} it strips) lets a request be authorised as one thing and executed as another. So
 * instead of trying to normalise every trick the way every possible application would, the gateway
 * accepts only paths that have exactly one reading: plain segments of unreserved characters, no
 * percent-encoding, no dot segments, no empty segments, no path parameters, no backslashes.
 */
public final class RequestPath {

    public static final int MAX_PATH = 2048;
    public static final int MAX_QUERY = 2048;

    /** RFC 3986 unreserved and sub-delimiters, minus ';' (path parameters) and '%' (encoding). */
    private static final String SEGMENT_PUNCTUATION = "._~!$&'()*+,=:@-";
    /** In a query also ';', '/' and '?' (percent-encoding is checked separately). */
    private static final String QUERY_PUNCTUATION = SEGMENT_PUNCTUATION + ";/?";

    private RequestPath() {
    }

    /** The path if it has exactly one reading; empty otherwise (answer 400). */
    public static Optional<String> path(String rawPath) {
        if (rawPath == null || rawPath.isEmpty() || rawPath.length() > MAX_PATH || rawPath.charAt(0) != '/') {
            return Optional.empty();
        }
        if (rawPath.equals("/")) {
            return Optional.of(rawPath);
        }
        String body = rawPath.substring(1);
        if (body.endsWith("/")) {
            body = body.substring(0, body.length() - 1);
        }
        for (String segment : body.split("/", -1)) {
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..") || !allowed(segment, SEGMENT_PUNCTUATION)) {
                return Optional.empty();
            }
        }
        return Optional.of(rawPath);
    }

    /**
     * The raw query, passed on unchanged (the gateway never routes on it); null means none. Only
     * well-formed percent-encoding and URI characters are accepted, so it cannot break the request line.
     */
    public static Optional<String> query(String rawQuery) {
        if (rawQuery == null) {
            return Optional.of("");
        }
        if (rawQuery.length() > MAX_QUERY) {
            return Optional.empty();
        }
        for (int i = 0; i < rawQuery.length(); i++) {
            char c = rawQuery.charAt(i);
            if (c == '%') {
                if (i + 2 >= rawQuery.length() || !hex(rawQuery.charAt(i + 1)) || !hex(rawQuery.charAt(i + 2))) {
                    return Optional.empty();
                }
                i += 2;
            } else if (!plain(c, QUERY_PUNCTUATION)) {
                return Optional.empty();
            }
        }
        return Optional.of(rawQuery);
    }

    /** Character checks by hand: no regular expression, so no backtracking on hostile input. */
    private static boolean allowed(String s, String punctuation) {
        for (int i = 0; i < s.length(); i++) {
            if (!plain(s.charAt(i), punctuation)) {
                return false;
            }
        }
        return true;
    }

    private static boolean plain(char c, String punctuation) {
        return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || punctuation.indexOf(c) >= 0;
    }

    private static boolean hex(char c) {
        return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F';
    }

    /** True when {@code path} is {@code prefix} or lies below it, on a segment boundary. */
    public static boolean under(String path, String prefix) {
        return path.equals(prefix) || path.startsWith(prefix + "/");
    }
}

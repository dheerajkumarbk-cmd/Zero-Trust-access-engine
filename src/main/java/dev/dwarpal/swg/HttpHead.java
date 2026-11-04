package dev.dwarpal.swg;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * A strictly parsed HTTP/1.x request head (request line and header fields), with hard limits. Anything
 * that two HTTP parsers might read differently is refused rather than interpreted: bare CR or LF,
 * folded header lines, white space before the colon, control characters, non-ASCII bytes, a second
 * request line. That removes the raw material of request smuggling and header injection.
 */
final class HttpHead {

    record Header(String name, String value) {
    }

    /** The head could not be read within the limits or is not well-formed HTTP. */
    static final class Malformed extends Exception {
        private static final long serialVersionUID = 1L;

        Malformed(String message) {
            super(message);
        }
    }

    final String method;
    final String target;
    final String version;
    final List<Header> headers;

    private HttpHead(String method, String target, String version, List<Header> headers) {
        this.method = method;
        this.target = target;
        this.version = version;
        this.headers = List.copyOf(headers);
    }

    /** All values of a header (names compared case-insensitively). */
    List<String> values(String name) {
        List<String> out = new ArrayList<>();
        for (Header h : headers) {
            if (h.name().equalsIgnoreCase(name)) {
                out.add(h.value());
            }
        }
        return out;
    }

    Optional<String> single(String name) throws Malformed {
        List<String> v = values(name);
        if (v.size() > 1) {
            throw new Malformed("repeated " + name.toLowerCase(Locale.ROOT));
        }
        return v.stream().findFirst();
    }

    /**
     * Reads one request head.
     *
     * @return empty if the connection closed before the first byte
     */
    static Optional<HttpHead> read(InputStream in, int maxBytes, int maxHeaders) throws IOException, Malformed {
        List<String> lines = new ArrayList<>();
        StringBuilder line = new StringBuilder();
        int total = 0;
        while (true) {
            int b = in.read();
            if (b == -1) {
                if (total == 0) {
                    return Optional.empty();
                }
                throw new Malformed("connection closed inside the request head");
            }
            if (++total > maxBytes) {
                throw new Malformed("request head too large");
            }
            if (b == '\r') {
                if (in.read() != '\n') {
                    throw new Malformed("bare CR");
                }
                total++;
                if (line.isEmpty()) {
                    if (lines.isEmpty()) {
                        throw new Malformed("empty request line");
                    }
                    return Optional.of(build(lines));
                }
                lines.add(line.toString());
                if (lines.size() > maxHeaders + 1) {
                    throw new Malformed("too many header fields");
                }
                line.setLength(0);
            } else if (b == '\n') {
                throw new Malformed("bare LF");
            } else if (b == '\t' || (b >= 0x20 && b < 0x7F)) {
                line.append((char) b);
            } else {
                throw new Malformed("control or non-ASCII byte in the request head");
            }
        }
    }

    private static HttpHead build(List<String> lines) throws Malformed {
        String[] rl = lines.get(0).split(" ", -1);
        if (rl.length != 3 || !token(rl[0]) || rl[1].isEmpty() || !(rl[2].equals("HTTP/1.1") || rl[2].equals("HTTP/1.0"))) {
            throw new Malformed("bad request line");
        }
        for (int i = 0; i < rl[1].length(); i++) {
            char c = rl[1].charAt(i);
            if (c <= 0x20 || c >= 0x7F) {
                throw new Malformed("bad request target");
            }
        }
        List<Header> headers = new ArrayList<>();
        for (String l : lines.subList(1, lines.size())) {
            if (l.charAt(0) == ' ' || l.charAt(0) == '\t') {
                throw new Malformed("folded header line");
            }
            int colon = l.indexOf(':');
            if (colon <= 0 || !token(l.substring(0, colon))) {
                throw new Malformed("bad header name");
            }
            headers.add(new Header(l.substring(0, colon), l.substring(colon + 1).strip()));
        }
        return new HttpHead(rl[0], rl[1], rl[2], headers);
    }

    /** An RFC 9110 token: letters, digits and {@code !#$%&'*+-.^_`|~}. */
    static boolean token(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || "!#$%&'*+-.^_`|~".indexOf(c) >= 0)) {
                return false;
            }
        }
        return true;
    }

    static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }
}

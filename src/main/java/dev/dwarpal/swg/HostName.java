package dev.dwarpal.swg;

import java.net.IDN;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * A destination host in one canonical form, so that every spelling of the same host matches the same
 * list entry: lower case (with {@link Locale#ROOT}), no trailing dot, internationalised names in their
 * ASCII (punycode) form, IP literals in their standard text form.
 *
 * <p>Anything that is not clearly a host name or an IP literal is refused: percent signs, slashes,
 * backslashes, {@code @}, spaces, control characters, empty or over-long labels. A filter that cannot
 * say what a name means must not guess.
 */
public record HostName(String value, Kind kind) {

    public enum Kind {
        NAME,
        IPV4,
        IPV6
    }

    public static final int MAX_LENGTH = 253;
    public static final int MAX_LABEL = 63;
    private static final int MAX_RAW = 1024;

    public HostName {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(kind, "kind");
    }

    /** True for IPv4 and IPv6 literals. */
    public boolean ipLiteral() {
        return kind != Kind.NAME;
    }

    /**
     * True if some label of an international name mixes letters of different writing systems
     * (a Cyrillic a followed by Latin pple): the classic homograph look-alike. A label in a
     * single script (including Latin with accents) is fine; so are the usual East Asian combinations
     * of Han with Hiragana and Katakana, with Bopomofo, or with Hangul. Names that are plain ASCII
     * cannot mix scripts.
     */
    public boolean mixedScript() {
        if (kind != Kind.NAME || !value.contains("xn--")) {
            return false;
        }
        for (String label : IDN.toUnicode(value).split("\\.")) {
            Set<Character.UnicodeScript> scripts = EnumSet.noneOf(Character.UnicodeScript.class);
            label.codePoints().filter(Character::isLetter).mapToObj(Character.UnicodeScript::of)
                    .filter(sc -> sc != Character.UnicodeScript.COMMON && sc != Character.UnicodeScript.INHERITED)
                    .forEach(scripts::add);
            if (scripts.size() > 1 && !EAST_ASIAN.stream().anyMatch(ok -> ok.containsAll(scripts))) {
                return true;
            }
        }
        return false;
    }

    private static final List<Set<Character.UnicodeScript>> EAST_ASIAN = List.of(
            EnumSet.of(Character.UnicodeScript.HAN, Character.UnicodeScript.HIRAGANA, Character.UnicodeScript.KATAKANA),
            EnumSet.of(Character.UnicodeScript.HAN, Character.UnicodeScript.BOPOMOFO),
            EnumSet.of(Character.UnicodeScript.HAN, Character.UnicodeScript.HANGUL));

    /** The parent domains from this name up, most specific first: {@code a.b.c}, {@code b.c}, {@code c}. */
    public List<String> suffixes() {
        if (kind != Kind.NAME) {
            return List.of(value);
        }
        List<String> out = new java.util.ArrayList<>();
        String s = value;
        while (true) {
            out.add(s);
            int dot = s.indexOf('.');
            if (dot < 0) {
                return out;
            }
            s = s.substring(dot + 1);
        }
    }

    /**
     * Parses a host as it appears in a request: a name, a dotted IPv4 address, or an IPv6 address in
     * brackets. No port, no user information.
     */
    public static Optional<HostName> parse(String raw) {
        if (raw == null || raw.isEmpty() || raw.length() > MAX_RAW) {
            return Optional.empty();
        }
        if (raw.charAt(0) == '[') {
            return raw.charAt(raw.length() - 1) == ']' ? ipv6(raw.substring(1, raw.length() - 1)) : Optional.empty();
        }
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c <= 0x20 || c == 0x7F || "%/\\@?#[]:,;\"'<>`{}|^".indexOf(c) >= 0) {
                return Optional.empty();
            }
        }
        String ascii;
        try {
            ascii = IDN.toASCII(raw, IDN.USE_STD3_ASCII_RULES);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        ascii = ascii.toLowerCase(Locale.ROOT);
        if (ascii.endsWith(".")) {
            ascii = ascii.substring(0, ascii.length() - 1);
        }
        if (ascii.isEmpty() || ascii.length() > MAX_LENGTH) {
            return Optional.empty();
        }
        Optional<String> v4 = dottedQuad(ascii);
        if (v4.isPresent()) {
            return Optional.of(new HostName(v4.get(), Kind.IPV4));
        }
        return validName(ascii) ? Optional.of(new HostName(ascii, Kind.NAME)) : Optional.empty();
    }

    /**
     * Letters, digits and hyphens in labels of 1 to 63 characters, not starting or ending with a hyphen,
     * and a last label that is not a number. Resolvers and browsers read {@code 2130706433},
     * {@code 0x7f000001}, {@code 127.1} and {@code 0177.0.0.1} as IPv4 addresses, so a filter that took
     * them for names would let a raw address through. No top-level domain is numeric, so such names
     * are refused outright instead of guessed at.
     */
    private static boolean validName(String s) {
        String last = s.substring(s.lastIndexOf('.') + 1);
        if (numeric(last)) {
            return false;
        }
        int labelStart = 0;
        for (int i = 0; i <= s.length(); i++) {
            if (i == s.length() || s.charAt(i) == '.') {
                int len = i - labelStart;
                if (len < 1 || len > MAX_LABEL || s.charAt(labelStart) == '-' || s.charAt(i - 1) == '-') {
                    return false;
                }
                labelStart = i + 1;
            } else {
                char c = s.charAt(i);
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
                    return false;
                }
            }
        }
        return true;
    }

    /** All digits, or {@code 0x} followed by hexadecimal digits (or nothing). */
    private static boolean numeric(String label) {
        boolean digits = true;
        for (int i = 0; i < label.length(); i++) {
            char c = label.charAt(i);
            digits &= c >= '0' && c <= '9';
        }
        if (digits) {
            return true;
        }
        if (!label.startsWith("0x")) {
            return false;
        }
        for (int i = 2; i < label.length(); i++) {
            char c = label.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    /** Four decimal parts of 0 to 255, no leading zeros. */
    private static Optional<String> dottedQuad(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            return Optional.empty();
        }
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3 || (p.length() > 1 && p.charAt(0) == '0')) {
                return Optional.empty();
            }
            for (int i = 0; i < p.length(); i++) {
                if (p.charAt(i) < '0' || p.charAt(i) > '9') {
                    return Optional.empty();
                }
            }
            if (Integer.parseInt(p) > 255) {
                return Optional.empty();
            }
        }
        return Optional.of(s);
    }

    private static Optional<HostName> ipv6(String inner) {
        if (inner.isEmpty() || inner.length() > 45) {
            return Optional.empty();
        }
        for (int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' || c == '.')) {
                return Optional.empty();
            }
        }
        try {
            InetAddress a = InetAddress.ofLiteral(inner);
            return Optional.of(of(a));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /** The canonical host for an address; IPv4-mapped IPv6 addresses become IPv4. */
    public static HostName of(InetAddress a) {
        Objects.requireNonNull(a, "address");
        byte[] b = a.getAddress();
        if (a instanceof Inet6Address && mappedV4(b)) {
            return new HostName((b[12] & 0xFF) + "." + (b[13] & 0xFF) + "." + (b[14] & 0xFF) + "." + (b[15] & 0xFF),
                    Kind.IPV4);
        }
        return new HostName(a.getHostAddress(), a instanceof Inet4Address ? Kind.IPV4 : Kind.IPV6);
    }

    private static boolean mappedV4(byte[] b) {
        for (int i = 0; i < 10; i++) {
            if (b[i] != 0) {
                return false;
            }
        }
        return (b[10] & 0xFF) == 0xFF && (b[11] & 0xFF) == 0xFF;
    }

    @Override
    public String toString() {
        return kind == Kind.IPV6 ? "[" + value + "]" : value;
    }
}

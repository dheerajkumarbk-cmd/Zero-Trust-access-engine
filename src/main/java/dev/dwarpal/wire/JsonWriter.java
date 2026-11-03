package dev.dwarpal.wire;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Compact JSON output. Strings are escaped so the output is safe to embed in logs and HTML-free
 * transports: quote, backslash and every control character are escaped, and so are the Unicode line
 * separators and bidirectional controls (log forging, Trojan Source). Characters are written by code,
 * so this source contains no escape sequences an editor could alter.
 */
public final class JsonWriter {

    private static final char QUOTE = 0x22;
    private static final char BACKSLASH = 0x5C;

    private JsonWriter() {
    }

    public static String write(JsonValue v) {
        StringBuilder sb = new StringBuilder(256);
        value(sb, v);
        return sb.toString();
    }

    public static byte[] bytes(JsonValue v) {
        return write(v).getBytes(StandardCharsets.UTF_8);
    }

    private static void value(StringBuilder sb, JsonValue v) {
        switch (v) {
            case JsonValue.JObject o -> {
                sb.append('{');
                boolean[] first = {true};
                o.forEach((k, member) -> {
                    if (!first[0]) {
                        sb.append(',');
                    }
                    first[0] = false;
                    string(sb, k);
                    sb.append(':');
                    value(sb, member);
                });
                sb.append('}');
            }
            case JsonValue.JArray a -> {
                sb.append('[');
                for (int i = 0; i < a.size(); i++) {
                    if (i > 0) {
                        sb.append(',');
                    }
                    value(sb, a.get(i));
                }
                sb.append(']');
            }
            case JsonValue.JString s -> string(sb, s.value());
            case JsonValue.JNumber n -> sb.append(n.text());
            case JsonValue.JBool b -> sb.append(b.value());
            case JsonValue.JNull n -> sb.append("null");
        }
    }

    static void string(StringBuilder sb, String s) {
        sb.append(QUOTE);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == QUOTE || c == BACKSLASH) {
                sb.append(BACKSLASH).append(c);
            } else if (c < 0x20 || c == 0x7F || c == 0x2028 || c == 0x2029 || (c >= 0x202A && c <= 0x202E)
                    || (c >= 0x2066 && c <= 0x2069) || c == 0xFEFF) {
                sb.append(BACKSLASH).append('u').append(String.format(Locale.ROOT, "%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        sb.append(QUOTE);
    }
}

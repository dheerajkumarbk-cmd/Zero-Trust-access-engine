package dev.dwarpal.audit;

import java.util.Map;

/**
 * Minimal JSON object writer for flat string maps (audit payloads), so records ship to a SIEM
 * (Wazuh, Elastic) without a JSON library on the decision path.
 *
 * <p>Escaping follows RFC 8259 section 7: quote, backslash and all control characters are
 * escaped. U+2028/U+2029 and bidi controls are escaped as well, so a payload cannot break a
 * JavaScript-based log viewer or visually reorder a line. Output is always valid JSON.
 */
public final class Json {

    private Json() {
    }

    public static String object(Map<String, String> fields) {
        StringBuilder sb = new StringBuilder(128).append('{');
        boolean first = true;
        for (Map.Entry<String, String> e : fields.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            string(sb, e.getKey());
            sb.append(':');
            string(sb, e.getValue());
        }
        return sb.append('}').toString();
    }

    static void string(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20 || c == 0x2028 || c == 0x2029 || (c >= 0x202A && c <= 0x202E)
                            || (c >= 0x2066 && c <= 0x2069)) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }
}

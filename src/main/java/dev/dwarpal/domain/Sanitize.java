package dev.dwarpal.domain;

import java.util.Objects;

/**
 * Neutralises free text before it reaches logs, explanations or error messages.
 *
 * <p>Identifiers are validated strictly by {@link Validate#id}; free text (risk evidence such as
 * a user-agent string, policy descriptions, parser complaints) cannot be, so it is escaped instead:
 * <ul>
 *   <li>control characters, including CR/LF, so a value cannot forge a new log line (CWE-117);</li>
 *   <li>Unicode line/paragraph separators (U+2028, U+2029), which some viewers render as newlines;</li>
 *   <li>bidirectional overrides (U+202A..U+202E, U+2066..U+2069), which can make a log line read
 *       differently from what it contains ("Trojan Source", CVE-2021-42574).</li>
 * </ul>
 * Output is truncated so one value cannot flood a log record.
 */
public final class Sanitize {

    private Sanitize() {
    }

    public static String text(String value, int maxLength) {
        Objects.requireNonNull(value, "text");
        StringBuilder sb = new StringBuilder(Math.min(value.length(), maxLength) + 16);
        for (int i = 0; i < value.length(); i++) {
            if (sb.length() >= maxLength) {
                sb.append("...[truncated]");
                break;
            }
            char c = value.charAt(i);
            if (Character.isISOControl(c) || isLineSeparator(c) || isBidiControl(c)) {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static boolean isLineSeparator(char c) {
        return c == 0x2028 || c == 0x2029;
    }

    private static boolean isBidiControl(char c) {
        return (c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069) || c == 0x200E || c == 0x200F;
    }
}

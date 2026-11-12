package dev.dwarpal.console;

/**
 * The identifier rule for anything the browser puts into a path or a parameter: the same plain identifiers the SOC
 * API accepts (letters, digits, {@code - _ . : @}, at most 128, no {@code ..}), checked before the identifier goes
 * anywhere near a URL, a log or an audit record.
 */
public final class ConsoleIds {

    private ConsoleIds() {
    }

    public static boolean isPlain(String s) {
        if (s == null || s.isEmpty() || s.length() > 128 || s.contains("..")) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
                    || c == '.' || c == ':' || c == '@';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    /** The identifier itself, or an {@link IllegalArgumentException} (which the server answers with 400). */
    public static String plain(String s) {
        if (!isPlain(s)) {
            throw new IllegalArgumentException("not a plain identifier");
        }
        return s;
    }
}

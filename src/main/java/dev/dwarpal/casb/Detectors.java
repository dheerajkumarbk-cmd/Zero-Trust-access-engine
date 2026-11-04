package dev.dwarpal.casb;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * Sensitive-data detectors that validate what they find instead of trusting a pattern: card numbers
 * must pass Luhn and start with a card industry digit, Aadhaar numbers must pass Verhoeff, a PAN must
 * name a real holder type. Each detector is a hand-written pass over the text (no regular
 * expressions, so no catastrophic backtracking): the work is linear in the input whatever it contains.
 *
 * <p>Digits may be written with any Unicode decimal digits (full-width, Arabic-Indic, ...), and groups
 * may be separated by one space, hyphen or other space character; zero-width and soft-hyphen characters
 * are ignored wherever they appear, because they are invisible to a reader and cost an evader nothing.
 *
 * <p>A {@link Finding} carries the type and position only, never the value.
 */
public final class Detectors {

    /**
     * Most findings kept per type. The cap is per type, not overall, so a flood of harmless findings
     * (thousands of e-mail addresses) can never push a secret out of the report.
     */
    public static final int MAX_PER_TYPE = 1_000;
    private static final String PAN_HOLDER_TYPES = "PCHFATBLJG";
    private static final int MAX_KEY_BLOCK = 64 * 1024;

    private Detectors() {
    }

    /**
     * The findings of one scan.
     *
     * @param truncated true if some type had more than {@link #MAX_PER_TYPE} findings, so the list is
     *                  not complete: anything that depends on every occurrence being found (redaction)
     *                  must fail closed
     */
    public record Scan(List<Finding> findings, boolean truncated) {
        public Scan {
            findings = List.copyOf(findings);
        }
    }

    /** All findings in {@code text}, ordered by position. */
    public static List<Finding> scan(CharSequence text) {
        return scanAll(text).findings();
    }

    public static Scan scanAll(CharSequence text) {
        Objects.requireNonNull(text, "text");
        Sink out = new Sink();
        digitRuns(text, out);
        words(text, out);
        emails(text, out);
        privateKeys(text, out);
        prefixed(text, "AKIA", FindingType.AWS_ACCESS_KEY, out);
        prefixed(text, "ASIA", FindingType.AWS_ACCESS_KEY, out);
        githubTokens(text, out);
        slackTokens(text, out);
        out.list.sort(Comparator.comparingInt(Finding::start).thenComparingInt(Finding::end));
        return new Scan(out.list, out.truncated);
    }

    /** Collects findings with the per-type cap. */
    private static final class Sink {
        final List<Finding> list = new ArrayList<>();
        final int[] counts = new int[FindingType.values().length];
        boolean truncated;

        void add(FindingType type, int start, int end) {
            if (counts[type.ordinal()] >= MAX_PER_TYPE) {
                truncated = true;
                return;
            }
            counts[type.ordinal()]++;
            list.add(new Finding(type, start, end));
        }
    }

    // ---- characters --------------------------------------------------------------------------------

    /** Value of a decimal digit in any script, or -1. */
    private static int digitValue(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        return c < 0x80 ? -1 : Character.digit(c, 10);
    }

    /** Characters a reader cannot see: soft hyphen, zero-width space, joiners, word joiner, byte order mark. */
    private static boolean invisible(char c) {
        return c == 0x00AD || (c >= 0x200B && c <= 0x200D) || c == 0x2060 || c == 0xFEFF;
    }

    /** What may stand between two groups of digits: one of these, never two. */
    private static boolean separator(char c) {
        return c == ' ' || c == '-' || c == 0x00A0 || (c >= 0x2000 && c <= 0x200A) || c == 0x202F || c == 0x205F
                || c == 0x3000;
    }

    private static boolean nextIsDigit(CharSequence s, int from) {
        int k = from;
        while (k < s.length() && invisible(s.charAt(k))) {
            k++;
        }
        return k < s.length() && digitValue(s.charAt(k)) >= 0;
    }

    // ---- numbers: cards and Aadhaar --------------------------------------------------------------

    private static void digitRuns(CharSequence s, Sink out) {
        int n = s.length();
        int i = 0;
        StringBuilder digits = new StringBuilder(24);
        while (i < n) {
            if (digitValue(s.charAt(i)) < 0) {
                i++;
                continue;
            }
            int start = i;
            int end = i;
            digits.setLength(0);
            boolean tooLong = false;
            int j = i;
            while (j < n) {
                char c = s.charAt(j);
                int v = digitValue(c);
                if (v >= 0) {
                    if (digits.length() < 20) {
                        digits.append((char) ('0' + v));
                    } else {
                        tooLong = true;
                    }
                    j++;
                    end = j;
                } else if (invisible(c) || (separator(c) && nextIsDigit(s, j + 1))) {
                    j++;
                } else {
                    break;
                }
            }
            if (!tooLong) {
                classifyNumber(digits, start, end, out);
            }
            i = end;
        }
    }

    private static void classifyNumber(CharSequence d, int start, int end, Sink out) {
        int len = d.length();
        if (len == 12 && d.charAt(0) >= '2' && Checksums.verhoeff(d)) {
            out.add(FindingType.AADHAAR, start, end);
        } else if (len >= 13 && len <= 19 && cardPrefix(d.charAt(0)) && !sameDigit(d) && Checksums.luhn(d)) {
            out.add(FindingType.CARD_NUMBER, start, end);
        }
    }

    /** Major industry identifiers of payment cards: 2 and 5 (Mastercard, RuPay), 3 (Amex, JCB, Diners), 4 (Visa), 6 (Discover, RuPay), 8 (RuPay). */
    private static boolean cardPrefix(char c) {
        return c == '2' || c == '3' || c == '4' || c == '5' || c == '6' || c == '8';
    }

    private static boolean sameDigit(CharSequence d) {
        for (int i = 1; i < d.length(); i++) {
            if (d.charAt(i) != d.charAt(0)) {
                return false;
            }
        }
        return true;
    }

    // ---- words: PAN and IFSC ---------------------------------------------------------------------

    private static boolean digit(char c) {
        return c >= '0' && c <= '9';
    }

    private static boolean letter(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    private static boolean alnum(char c) {
        return letter(c) || digit(c);
    }

    private static char upper(char c) {
        return c >= 'a' && c <= 'z' ? (char) (c - 32) : c;
    }

    /** Maximal runs of ASCII letters and digits (invisible characters ignored), checked as PAN (10) or IFSC (11). */
    private static void words(CharSequence s, Sink out) {
        int n = s.length();
        int i = 0;
        char[] word = new char[12];
        while (i < n) {
            if (!alnum(s.charAt(i))) {
                i++;
                continue;
            }
            int start = i;
            int end = i;
            int len = 0;
            while (i < n && (alnum(s.charAt(i)) || invisible(s.charAt(i)))) {
                if (!invisible(s.charAt(i))) {
                    if (len < word.length) {
                        word[len] = s.charAt(i);
                    }
                    len++;
                    end = i + 1;
                }
                i++;
            }
            if (len == 10 && pan(word)) {
                out.add(FindingType.PAN, start, end);
            } else if (len == 11 && ifsc(word)) {
                out.add(FindingType.IFSC, start, end);
            }
        }
    }

    private static boolean pan(char[] w) {
        for (int k = 0; k < 5; k++) {
            if (!letter(w[k])) {
                return false;
            }
        }
        for (int k = 5; k < 9; k++) {
            if (!digit(w[k])) {
                return false;
            }
        }
        return letter(w[9]) && PAN_HOLDER_TYPES.indexOf(upper(w[3])) >= 0;
    }

    private static boolean ifsc(char[] w) {
        for (int k = 0; k < 4; k++) {
            if (!letter(w[k])) {
                return false;
            }
        }
        if (w[4] != '0') {
            return false;
        }
        boolean hasDigit = false;
        for (int k = 5; k < 11; k++) {
            hasDigit |= digit(w[k]);
        }
        return hasDigit;
    }

    // ---- e-mail addresses ------------------------------------------------------------------------

    private static boolean localChar(char c) {
        return alnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-';
    }

    private static boolean domainChar(char c) {
        return alnum(c) || c == '.' || c == '-';
    }

    private static void emails(CharSequence s, Sink out) {
        int n = s.length();
        int lastEnd = 0;
        for (int at = 0; at < n; at++) {
            if (s.charAt(at) != '@') {
                continue;
            }
            int left = at;
            while (left > lastEnd && at - left < 64 && localChar(s.charAt(left - 1))) {
                left--;
            }
            while (left < at && s.charAt(left) == '.') {
                left++;
            }
            int right = at + 1;
            while (right < n && right - at <= 253 && domainChar(s.charAt(right))) {
                right++;
            }
            while (right > at + 1 && (s.charAt(right - 1) == '.' || s.charAt(right - 1) == '-')) {
                right--;
            }
            if (left < at && validDomain(s, at + 1, right)) {
                out.add(FindingType.EMAIL, left, right);
                lastEnd = right;
                at = right - 1;
            }
        }
    }

    /** At least two labels, none empty, the last one two or more letters. */
    private static boolean validDomain(CharSequence s, int from, int to) {
        if (to - from < 4) {
            return false;
        }
        int lastDot = -1;
        int labelStart = from;
        for (int i = from; i <= to; i++) {
            if (i == to || s.charAt(i) == '.') {
                if (i == labelStart) {
                    return false;
                }
                if (i < to) {
                    lastDot = i;
                }
                labelStart = i + 1;
            }
        }
        if (lastDot < 0 || to - lastDot - 1 < 2) {
            return false;
        }
        for (int i = lastDot + 1; i < to; i++) {
            if (!letter(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    // ---- secrets: the pre-commit hook's patterns ---------------------------------------------------

    private static final String[] KEY_KINDS = {"", "RSA ", "EC ", "OPENSSH ", "DSA ", "ENCRYPTED ", "PGP "};
    private static final String END_MARKER = "-----END ";

    /**
     * {@code BEGIN [kind ]PRIVATE KEY}, up to the matching END line when there is one nearby. The
     * position of the next END marker is remembered, so a text with thousands of BEGIN markers and
     * no END is scanned once, not once per marker.
     */
    private static void privateKeys(CharSequence s, Sink out) {
        String text = s.toString();
        int from = 0;
        int nextEnd = -2;
        while (true) {
            int begin = text.indexOf("BEGIN ", from);
            if (begin < 0) {
                return;
            }
            int after = begin + 6;
            int kindEnd = -1;
            for (String k : KEY_KINDS) {
                if (text.startsWith(k + "PRIVATE KEY", after)) {
                    kindEnd = after + k.length() + "PRIVATE KEY".length();
                    break;
                }
            }
            if (kindEnd < 0) {
                from = after;
                continue;
            }
            int start = begin >= 5 && text.startsWith("-----", begin - 5) ? begin - 5 : begin;
            if (nextEnd != -1 && nextEnd < kindEnd) {
                nextEnd = text.indexOf(END_MARKER, kindEnd);
            }
            int end = nextEnd >= 0 && nextEnd - start <= MAX_KEY_BLOCK ? endOfLine(text, nextEnd) : endOfLine(text, kindEnd);
            out.add(FindingType.PRIVATE_KEY, start, end);
            from = end;
        }
    }

    private static int endOfLine(String s, int from) {
        int nl = s.indexOf('\n', from);
        int end = nl < 0 ? s.length() : nl;
        return end > 0 && s.charAt(end - 1) == '\r' ? end - 1 : end;
    }

    private static boolean upperOrDigit(char c) {
        return (c >= 'A' && c <= 'Z') || digit(c);
    }

    /** {@code prefix} followed by 16 upper-case letters or digits (AWS access key ids). */
    private static void prefixed(CharSequence s, String prefix, FindingType type, Sink out) {
        String text = s.toString();
        int from = 0;
        while (true) {
            int at = text.indexOf(prefix, from);
            if (at < 0) {
                return;
            }
            int end = at + prefix.length() + 16;
            boolean ok = end <= text.length();
            for (int i = at + prefix.length(); ok && i < end; i++) {
                ok = upperOrDigit(text.charAt(i));
            }
            if (ok) {
                out.add(type, at, end);
                from = end;
            } else {
                from = at + 1;
            }
        }
    }

    /** {@code gh[pousr]_} and 36 letters or digits; {@code github_pat_} and 22 or more word characters. */
    private static void githubTokens(CharSequence s, Sink out) {
        String text = s.toString();
        int from = 0;
        while (true) {
            int at = text.indexOf("gh", from);
            if (at < 0) {
                break;
            }
            int end = at + 4 + 36;
            boolean ok = at + 3 < text.length() && "pousr".indexOf(text.charAt(at + 2)) >= 0
                    && text.charAt(at + 3) == '_' && end <= text.length();
            for (int i = at + 4; ok && i < end; i++) {
                ok = alnum(text.charAt(i));
            }
            if (ok) {
                out.add(FindingType.GITHUB_TOKEN, at, end);
                from = end;
            } else {
                from = at + 1;
            }
        }
        from = 0;
        while (true) {
            int at = text.indexOf("github_pat_", from);
            if (at < 0) {
                return;
            }
            int i = at + 11;
            while (i < text.length() && i - at < 255 && (alnum(text.charAt(i)) || text.charAt(i) == '_')) {
                i++;
            }
            if (i - at - 11 >= 22) {
                out.add(FindingType.GITHUB_TOKEN, at, i);
            }
            from = i;
        }
    }

    /** {@code xox[baprs]-} and 10 or more letters, digits or dashes. */
    private static void slackTokens(CharSequence s, Sink out) {
        String text = s.toString();
        int from = 0;
        while (true) {
            int at = text.indexOf("xox", from);
            if (at < 0) {
                return;
            }
            int i = at + 5;
            boolean ok = at + 4 < text.length() && "baprs".indexOf(text.charAt(at + 3)) >= 0 && text.charAt(at + 4) == '-';
            if (ok) {
                while (i < text.length() && i - at < 255 && (alnum(text.charAt(i)) || text.charAt(i) == '-')) {
                    i++;
                }
                ok = i - at - 5 >= 10;
            }
            if (ok) {
                out.add(FindingType.SLACK_TOKEN, at, i);
                from = i;
            } else {
                from = at + 1;
            }
        }
    }
}

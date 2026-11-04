package dev.dwarpal.casb;

/**
 * The check-digit algorithms that tell a real identifier from a random string of digits.
 *
 * <ul>
 *   <li><b>Luhn</b> (ISO/IEC 7812-1), used by payment cards: catches every single-digit error and most
 *       swaps of neighbours; a random number passes with probability 1/10.</li>
 *   <li><b>Verhoeff</b> (dihedral group D5), used by Aadhaar: catches every single-digit error and every
 *       swap of neighbours.</li>
 * </ul>
 * Both take ASCII digits only and refuse anything else.
 */
public final class Checksums {

    /** Multiplication table of the dihedral group D5. */
    private static final int[][] D = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
            {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
            {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
            {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
            {4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
            {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
            {6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
            {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
            {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
            {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}};

    /** Position permutation: P[i] = P[1] applied i times, P[1] = (1 5 8 9 4 2 7 0)(3 6). */
    private static final int[][] P = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
            {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
            {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
            {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
            {9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
            {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
            {2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
            {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}};

    /** Inverse in D5, for computing a check digit. */
    private static final int[] INV = {0, 4, 3, 2, 1, 5, 6, 7, 8, 9};

    private Checksums() {
    }

    public static boolean luhn(CharSequence digits) {
        if (!allDigits(digits)) {
            return false;
        }
        int sum = 0;
        boolean twice = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (twice) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            sum += d;
            twice = !twice;
        }
        return sum % 10 == 0;
    }

    public static boolean verhoeff(CharSequence digits) {
        if (!allDigits(digits)) {
            return false;
        }
        int c = 0;
        for (int i = 0; i < digits.length(); i++) {
            int d = digits.charAt(digits.length() - 1 - i) - '0';
            c = D[c][P[i % 8][d]];
        }
        return c == 0;
    }

    /** The digit that makes {@code digits + check} pass {@link #verhoeff}. */
    public static char verhoeffCheckDigit(CharSequence digits) {
        if (!allDigits(digits)) {
            throw new IllegalArgumentException("digits only");
        }
        int c = 0;
        for (int i = 0; i < digits.length(); i++) {
            int d = digits.charAt(digits.length() - 1 - i) - '0';
            c = D[c][P[(i + 1) % 8][d]];
        }
        return (char) ('0' + INV[c]);
    }

    /** The digit that makes {@code digits + check} pass {@link #luhn}. */
    public static char luhnCheckDigit(CharSequence digits) {
        if (!allDigits(digits)) {
            throw new IllegalArgumentException("digits only");
        }
        for (char c = '0'; c <= '9'; c++) {
            if (luhn(digits.toString() + c)) {
                return c;
            }
        }
        throw new IllegalStateException("unreachable");
    }

    private static boolean allDigits(CharSequence s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }
}

package dev.dwarpal.domain;

import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Input validation shared by all domain objects.
 *
 * <p>Secure-by-default: identifiers end up in audit logs and SIEM events, so anything outside a
 * strict ASCII character set is rejected at construction time. This blocks log injection
 * (CWE-117) and Unicode homoglyph look-alikes ("аdmin" with a Cyrillic а). Sequences of ".."
 * are rejected so an identifier can never become a path-traversal string if it is later used to
 * name a file.
 */
public final class Validate {

    private static final Pattern ID = Pattern.compile("[A-Za-z0-9._:@/-]{1,128}");

    /** Upper bound for any cost or count parameter: big enough for real use, far from overflow. */
    public static final double MAX_MAGNITUDE = 1e12;

    private Validate() {
    }

    public static String id(String value, String field) {
        Objects.requireNonNull(value, field + " must not be null");
        if (!ID.matcher(value).matches() || value.contains("..")) {
            throw new IllegalArgumentException(
                    field + " must match " + ID.pattern() + " without '..' (got a value of length "
                            + value.length() + ")");
        }
        return value;
    }

    /**
     * A case-insensitive label (role, department, region): validated, then lower-cased with
     * {@link Locale#ROOT}. Comparing labels case-sensitively lets "Contractor" slip past a deny
     * rule for "contractor"; using the default locale would turn "ADMIN" into "admın" on a
     * Turkish system. Both are classic authorisation bypasses.
     */
    public static String label(String value, String field) {
        return id(value, field).toLowerCase(Locale.ROOT);
    }

    /** ISO country code, canonicalised to upper case. */
    public static String country(String value, String field) {
        return id(value, field).toUpperCase(Locale.ROOT);
    }

    public static double probability(double value, String field) {
        if (!(value >= 0.0 && value <= 1.0)) {
            throw new IllegalArgumentException(field + " must be within [0,1], got " + value);
        }
        return value;
    }

    public static double positive(double value, String field) {
        if (!(value > 0.0 && value <= MAX_MAGNITUDE)) {
            throw new IllegalArgumentException(field + " must be in (0, " + MAX_MAGNITUDE + "], got " + value);
        }
        return value;
    }

    public static double finite(double value, String field) {
        if (!Double.isFinite(value)) {
            throw new IllegalArgumentException(field + " must be finite, got " + value);
        }
        return value;
    }
}

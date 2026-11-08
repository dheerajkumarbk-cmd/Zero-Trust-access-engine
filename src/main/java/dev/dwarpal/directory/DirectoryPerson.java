package dev.dwarpal.directory;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * One person in the directory: who they are, where they work, what their job is and which console roles they hold.
 * Every field is checked here, before it can reach a query: a name with a control character, a direction-switching
 * character or a stray surrogate is refused (it could forge a line in a log or on a page), and a role must be one of
 * the five the console knows. Quotes and semicolons are ordinary text, so {@code O'Brien} is fine; what protects the
 * database from them is that they only ever travel as query parameters.
 */
public record DirectoryPerson(String id, String displayName, String department, String businessRole, Status status,
                              Source source, Instant createdAt, Set<String> consoleRoles) {

    /** Whether the person may sign in. A leaver is disabled, never deleted, so history stays whole. */
    public enum Status { ACTIVE, DISABLED }

    /** Where the person came from: the lab's own starting set, or an HR joiner request. */
    public enum Source { SEED, HR }

    /** The console roles, spelled exactly as the database allows them. */
    public static final Set<String> ROLES = Set.of("ANALYST", "LEAD", "ADMIN", "USER", "HR");

    public static final int ID_MAX = 32;
    public static final int NAME_MAX = 100;
    public static final int LABEL_MAX = 60;

    private static final Pattern ID = Pattern.compile("[a-z][a-z0-9._-]{1,31}");

    public DirectoryPerson {
        Objects.requireNonNull(id, "id");
        if (!ID.matcher(id).matches() || id.contains("..")) {
            throw new IllegalArgumentException("a person id is 2 to " + ID_MAX + " lower-case letters, digits, . _ -");
        }
        displayName = text(displayName, "display name", NAME_MAX);
        department = text(department, "department", LABEL_MAX);
        businessRole = text(businessRole, "business role", LABEL_MAX);
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(consoleRoles, "consoleRoles");
        // a person who left, or a joiner whose items still wait for approval, holds no console role
        if (!ROLES.containsAll(consoleRoles)) {
            throw new IllegalArgumentException("console roles come from " + new TreeSet<>(ROLES));
        }
        consoleRoles = Set.copyOf(new TreeSet<>(consoleRoles));
    }

    /** True for a well-formed person id: used to answer "not found" to anything else without asking the database. */
    public static boolean validId(String candidate) {
        return candidate != null && ID.matcher(candidate).matches() && !candidate.contains("..");
    }

    /** Plain text of 1 to {@code max} characters, trimmed, with nothing that could forge a line or flip a direction. */
    static String text(String value, String field, int max) {
        Objects.requireNonNull(value, field);
        // the whole raw text is checked before trimming, so a trailing line break or tab is refused, not quietly removed
        for (int i = 0; i < value.length(); ) {
            int cp = value.codePointAt(i);
            i += Character.charCount(cp);
            boolean surrogate = cp >= 0xD800 && cp <= 0xDFFF;
            boolean bidi = cp == 0x200E || cp == 0x200F || (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069);
            if (Character.isISOControl(cp) || surrogate || bidi || cp == 0x2028 || cp == 0x2029 || cp == 0xFEFF
                    || cp == 0x200B || cp == 0x200C || cp == 0x200D || !Character.isDefined(cp)) {
                throw new IllegalArgumentException(field + " contains a character that is not allowed");
            }
        }
        String v = value.strip();
        if (v.isEmpty() || v.length() > max) {
            throw new IllegalArgumentException(field + " must be 1 to " + max + " characters");
        }
        return v;
    }
}

package dev.dwarpal.analytics;

import dev.dwarpal.domain.Sanitize;

import java.util.Locale;
import java.util.Objects;

/**
 * Where the numbers in a report came from. Every report carries one, and its {@link #statement()} is
 * printed first, so a number can never travel without its data and its caveat (Layer 5 rule: numbers
 * need their assumptions).
 *
 * @param kind        what sort of data it is
 * @param description free text (sanitised, at most 200 characters), for example "SimOrganisation"
 * @param seed        the generator seed, or -1 when the data was not generated
 * @param users       number of people in the data (0 if unknown)
 * @param days        days of traffic covered (0 if unknown)
 * @param requests    number of requests the numbers were computed from
 */
public record DataSource(Kind kind, String description, long seed, int users, int days, long requests) {

    public static final int MAX_DESCRIPTION = 200;

    public enum Kind {
        /** Traffic from the labelled simulated organisation (engine and generator written by one team). */
        SIMULATED,
        /** Synthetic numbers with known, planted parameters (tests of the estimators themselves). */
        SYNTHETIC,
        /** Requests kept by {@link RequestRecorder} from live traffic. */
        RECORDED,
        /** Decisions read back from the verified audit trail. */
        AUDIT_TRAIL
    }

    public DataSource {
        Objects.requireNonNull(kind, "kind");
        description = Sanitize.text(Objects.requireNonNull(description, "description"), MAX_DESCRIPTION);
        if (seed < -1 || users < 0 || days < 0 || requests < 0) {
            throw new IllegalArgumentException("seed, users, days and requests must not be negative");
        }
    }

    public static DataSource simulated(long seed, int users, int days, long requests) {
        if (seed < 0) {
            throw new IllegalArgumentException("a simulated source needs its seed");
        }
        return new DataSource(Kind.SIMULATED, "SimOrganisation", seed, users, days, requests);
    }

    /** The same source with another request count (an analysis that used a subset). */
    public DataSource withRequests(long n) {
        return new DataSource(kind, description, seed, users, days, n);
    }

    /** One sentence that says what the data was and what the numbers do not mean. */
    public String statement() {
        String what = switch (kind) {
            case SIMULATED -> String.format(Locale.ROOT,
                    "simulated organisation '%s' (seed %d, %d users, %d days, %d requests)",
                    description, seed, users, days, requests);
            case SYNTHETIC -> String.format(Locale.ROOT, "synthetic data '%s' (seed %d, %d samples)",
                    description, seed, requests);
            case RECORDED -> String.format(Locale.ROOT, "recorded requests '%s' (%d requests, %d users, %d days)",
                    description, requests, users, days);
            case AUDIT_TRAIL -> String.format(Locale.ROOT, "audit trail '%s' (%d decisions)", description, requests);
        };
        String caveat = switch (kind) {
            case SIMULATED -> "the engine and the generator were written by the same team, so these numbers measure"
                    + " consistency with the threat model, not real-world accuracy";
            case SYNTHETIC -> "these numbers test the estimators on planted parameters, not the engine";
            case RECORDED, AUDIT_TRAIL -> "these numbers describe this traffic only; without ground-truth labels"
                    + " they are not a measure of accuracy";
        };
        return "Data: " + what + ". Caveat: " + caveat + ".";
    }
}

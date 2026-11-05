package dev.dwarpal.socapi;

import java.time.Instant;
import java.util.Optional;

/**
 * Where the SOC API gets its reports (part E's daily SOC report and others). Names are identifiers; a report is
 * text that states its own data source.
 */
@FunctionalInterface
public interface ReportSource {

    int MAX_CHARS = 60_000;

    /** The report with this name as of {@code now}, if there is one; may throw (answered as unavailable). */
    Optional<String> report(String name, Instant now);

    static ReportSource none() {
        return (name, now) -> Optional.empty();
    }
}

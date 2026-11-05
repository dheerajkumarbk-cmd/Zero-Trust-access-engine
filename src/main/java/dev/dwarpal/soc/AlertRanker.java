package dev.dwarpal.soc;

import java.time.Instant;

/**
 * Places an alert in the analyst's queue (part E). Ranking never hides an alert: the lowest place is P4.
 * {@code actionable} must be computed from the alert's evidence, never assumed.
 */
public interface AlertRanker {

    RankedAlert rank(Alert alert, Instant now);
}

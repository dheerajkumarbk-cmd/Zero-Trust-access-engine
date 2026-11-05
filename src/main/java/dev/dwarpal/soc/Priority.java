package dev.dwarpal.soc;

import java.time.Duration;

/** An alert's or case's place in the queue, with the time by which a person should have looked at it. */
public enum Priority {
    P1(Duration.ofMinutes(15)),
    P2(Duration.ofHours(1)),
    P3(Duration.ofHours(8)),
    P4(Duration.ofHours(72));

    private final Duration respondWithin;

    Priority(Duration respondWithin) {
        this.respondWithin = respondWithin;
    }

    /** Default response time (SLA); a deployment may set its own in part F's case management. */
    public Duration respondWithin() {
        return respondWithin;
    }

    /** Whether this priority is at least as urgent as {@code other}. */
    public boolean atLeast(Priority other) {
        return ordinal() <= other.ordinal();
    }
}

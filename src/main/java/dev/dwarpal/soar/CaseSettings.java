package dev.dwarpal.soar;

import dev.dwarpal.soc.Priority;

import java.time.Duration;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * Limits and service levels of case management, fixed at deployment.
 *
 * @param respondWithin  time to first response (assignment, note or verdict) per priority, 1 minute to 30 days
 * @param maxNotes       notes per case
 * @param maxNoteChars   characters per note (longer notes are refused, not cut)
 * @param maxTimeline    timeline entries per case; beyond it the oldest entries after the first are dropped and counted
 * @param maxLinks       linked cases remembered per case
 */
public record CaseSettings(Map<Priority, Duration> respondWithin, int maxNotes, int maxNoteChars, int maxTimeline,
                           int maxLinks) {

    public static final int HARD_MAX_NOTES = 1_000;
    public static final int HARD_MAX_NOTE_CHARS = 4_000;
    public static final int HARD_MAX_TIMELINE = 5_000;

    public CaseSettings {
        Objects.requireNonNull(respondWithin, "respondWithin");
        EnumMap<Priority, Duration> sla = new EnumMap<>(Priority.class);
        for (Priority p : Priority.values()) {
            Duration d = Objects.requireNonNull(respondWithin.get(p), "respondWithin for " + p);
            if (d.compareTo(Duration.ofMinutes(1)) < 0 || d.compareTo(Duration.ofDays(30)) > 0) {
                throw new IllegalArgumentException("a response time is 1 minute to 30 days");
            }
            sla.put(p, d);
        }
        for (int i = 1; i < Priority.values().length; i++) {
            if (sla.get(Priority.values()[i]).compareTo(sla.get(Priority.values()[i - 1])) < 0) {
                throw new IllegalArgumentException("a less urgent priority cannot have a shorter response time");
            }
        }
        respondWithin = Map.copyOf(sla);
        if (maxNotes < 1 || maxNotes > HARD_MAX_NOTES || maxNoteChars < 1 || maxNoteChars > HARD_MAX_NOTE_CHARS
                || maxTimeline < 10 || maxTimeline > HARD_MAX_TIMELINE || maxLinks < 0 || maxLinks > 100) {
            throw new IllegalArgumentException("case limits out of range");
        }
    }

    /** The response times of {@link Priority}, 100 notes of 2,000 characters, 500 timeline entries, 20 links. */
    public static CaseSettings defaults() {
        Map<Priority, Duration> sla = new EnumMap<>(Priority.class);
        for (Priority p : Priority.values()) {
            sla.put(p, p.respondWithin());
        }
        return new CaseSettings(sla, 100, 2_000, 500, 20);
    }

    public Duration sla(Priority p) {
        return respondWithin.get(p);
    }

    public CaseSettings withLimits(int notes, int noteChars, int timeline, int links) {
        return new CaseSettings(respondWithin, notes, noteChars, timeline, links);
    }
}

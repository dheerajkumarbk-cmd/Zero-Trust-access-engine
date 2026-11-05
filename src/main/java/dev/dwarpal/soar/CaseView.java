package dev.dwarpal.soar;

import dev.dwarpal.domain.Validate;
import dev.dwarpal.response.Case;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.RankedAlert;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * What an analyst sees of one case: part B's case (alerts, state, actions in force) with case management on top.
 *
 * @param priority        the most urgent priority among its alerts
 * @param score           the highest ranking score among its alerts
 * @param deadline        when a first response is due (the service level of its priority)
 * @param acknowledgedAt  the first response (assignment, note or verdict), if any
 * @param breached        no response by the deadline (or the first response came late)
 * @param awaitingSecond  a first verdict waits for a second analyst
 * @param alerts          its alerts as ranked, oldest first
 * @param links           other cases about the same entities
 * @param timelineDropped timeline entries dropped because the timeline was full
 */
public record CaseView(String id, Entity key, Case.State state, Priority priority, double score, Instant openedAt,
                       Instant deadline, Optional<Instant> acknowledgedAt, boolean breached,
                       Optional<String> assignee, boolean holdsActions, boolean awaitingSecond,
                       List<RankedAlert> alerts, Set<Entity> entities, List<Note> notes, List<TimelineEntry> timeline,
                       List<String> links, long timelineDropped) {

    /** One note, sanitised, by an analyst. */
    public record Note(String id, String author, Instant at, String text) {
        public Note {
            Validate.id(id, "note.id");
            Validate.id(author, "note.author");
            Objects.requireNonNull(at, "note.at");
            Objects.requireNonNull(text, "note.text");
        }
    }

    /** One event in a case's life. {@code detail} is a short sanitised line built from ids, never from payloads. */
    public record TimelineEntry(Instant at, Kind kind, String actor, String detail) {
        public enum Kind { OPENED, ALERT, PRIORITY, ASSIGNED, NOTE, VERDICT, ACTION, ISOLATION, NOTIFIED, LINKED }

        public TimelineEntry {
            Objects.requireNonNull(at, "at");
            Objects.requireNonNull(kind, "kind");
            Validate.id(actor, "actor");
            Objects.requireNonNull(detail, "detail");
        }
    }

    public CaseView {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(priority, "priority");
        Objects.requireNonNull(openedAt, "openedAt");
        Objects.requireNonNull(deadline, "deadline");
        Objects.requireNonNull(acknowledgedAt, "acknowledgedAt");
        Objects.requireNonNull(assignee, "assignee");
        alerts = List.copyOf(alerts);
        entities = Set.copyOf(entities);
        notes = List.copyOf(notes);
        timeline = List.copyOf(timeline);
        links = List.copyOf(links);
    }

    /** Whether {@code subjectId} is one of the people this case is about. */
    public boolean concerns(String subjectId) {
        return entities.contains(Entity.subject(subjectId));
    }
}

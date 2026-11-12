package dev.dwarpal.directory;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * A request in the access process. A JOINER request is raised by HR for a person who does not exist yet; an ACCESS
 * request is raised by a person for themselves; a LEAVER request is raised by HR and is carried out at once.
 * {@code items} are the items that were granted or asked for (a joiner's are known once the administrator saves).
 */
public record AccessRequest(String id, Kind kind, Status status, String subjectId, String requestedBy, String reason,
                            String displayName, String department, String businessRole, String decidedBy,
                            String decisionReason, Instant createdAt, Instant updatedAt, List<String> items) {

    /**
     * The last four are privileged changes: an administrator asks, and only a DIFFERENT administrator decides. CREATE_ADMIN makes a
     * new person with the administrator role; ADD_ADMIN gives it to an existing person; REMOVE_ADMIN takes it away; OWN_ACCESS
     * is an administrator's change to their own access.
     */
    public enum Kind {
        JOINER, LEAVER, ACCESS, CREATE_ADMIN, ADD_ADMIN, REMOVE_ADMIN, OWN_ACCESS;

        public boolean privileged() {
            return this == CREATE_ADMIN || this == ADD_ADMIN || this == REMOVE_ADMIN || this == OWN_ACCESS;
        }
    }

    /** PENDING waits for the administrator (joiners) or is being processed; APPROVED waits only for second approvers. */
    public enum Status { PENDING, APPROVED, REJECTED, DONE, CANCELLED }

    public AccessRequest {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(subjectId, "subjectId");
        Objects.requireNonNull(requestedBy, "requestedBy");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        items = List.copyOf(items);
    }
}

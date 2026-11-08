package dev.dwarpal.directory;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * One grant record: one item for one person. It is the single source of truth for what was ever given, so a leaver's
 * removal uses these records and not a re-calculation from the role: one-off extras go too. A hard grant is ACTIVE
 * only when every approval it needs is APPROVED.
 */
public record AccessGrant(String id, String requestId, String personId, String itemId, State state, Instant createdAt,
                          Instant grantedAt, Instant removedAt, String removedReason, List<Approval> approvals) {

    public enum State { PENDING, ACTIVE, REJECTED, REMOVED }

    public enum Decision { PENDING, APPROVED, REJECTED }

    /** One needed approval: by an ADMIN or by a LEAD. {@code approverId} is empty until somebody decides. */
    public record Approval(String role, String approverId, Decision decision, String reason, Instant decidedAt) {
        public Approval {
            Objects.requireNonNull(role, "role");
            Objects.requireNonNull(decision, "decision");
        }
    }

    public AccessGrant {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(requestId, "requestId");
        Objects.requireNonNull(personId, "personId");
        Objects.requireNonNull(itemId, "itemId");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(createdAt, "createdAt");
        approvals = List.copyOf(approvals);
    }
}

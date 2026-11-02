package dev.dwarpal.pam;

import dev.dwarpal.domain.Validate;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * A time-boxed privileged role held by one subject.
 *
 * @param approvedBy empty for a break-glass grant (nobody approved it; it is reviewed afterwards)
 */
public record ElevationGrant(String grantId, String subjectId, String role, Instant from, Instant until,
                             Optional<String> approvedBy, boolean breakGlass, String justification) {

    public ElevationGrant {
        Validate.id(grantId, "grant.id");
        Validate.id(subjectId, "grant.subjectId");
        role = Validate.label(role, "grant.role");
        Objects.requireNonNull(from, "grant.from");
        Objects.requireNonNull(until, "grant.until");
        if (!from.isBefore(until)) {
            throw new IllegalArgumentException("grant window is empty");
        }
        Objects.requireNonNull(approvedBy, "grant.approvedBy");
        if (approvedBy.isEmpty() != breakGlass) {
            throw new IllegalArgumentException("only break-glass grants lack an approver");
        }
        Objects.requireNonNull(justification, "grant.justification");
    }

    public boolean activeAt(Instant t) {
        return !t.isBefore(from) && t.isBefore(until);
    }
}

package dev.dwarpal.soar;

import dev.dwarpal.domain.Validate;

import java.util.Objects;

/**
 * A SOC analyst known to case management and the SOC API.
 *
 * @param id   the analyst's id: the same id their {@code SOC_ANALYST} key is bound to, and their subject id in the
 *             directory (so a case about them can be recognised)
 * @param role what they may do: an {@link Role#ANALYST} works unassigned cases and their own; a {@link Role#LEAD}
 *             also assigns cases to others and sees every case (except cases about themselves)
 */
public record Analyst(String id, Role role) {

    public enum Role { ANALYST, LEAD }

    public Analyst {
        Validate.id(id, "analyst.id");
        Objects.requireNonNull(role, "analyst.role");
    }

    public boolean lead() {
        return role == Role.LEAD;
    }
}

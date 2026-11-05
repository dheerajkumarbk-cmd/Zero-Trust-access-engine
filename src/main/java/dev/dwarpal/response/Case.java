package dev.dwarpal.response;

import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * A read-only view of one case: the alerts about one entity, and where the analysts are with it.
 *
 * @param key            the entity the alerts were grouped by (the first person they name, otherwise their
 *                       first entity)
 * @param severity       the highest severity among its alerts
 * @param alerts         its alerts, oldest first, at most {@link ResponseSettings#maxAlertsPerCase()}
 * @param holdsActions   whether actions taken on its account are still in force (a false-positive
 *                       verdict can still lift them)
 */
public record Case(String id, Entity key, State state, Severity severity, Instant openedAt, List<Alert> alerts,
                   boolean holdsActions) {

    public enum State {
        /** Raised, nobody has decided yet. */
        OPEN,
        /** An analyst has decided, and the case waits for a second analyst or for the rate limit. */
        TRIAGED,
        /** Decided; what the playbook did (if anything) stays until it ends or is lifted. */
        CLOSED
    }

    public Case {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(openedAt, "openedAt");
        alerts = List.copyOf(alerts);
    }

    /** Every entity any of its alerts names. */
    public Set<Entity> entities() {
        Set<Entity> all = new LinkedHashSet<>();
        alerts.forEach(a -> all.addAll(a.entities()));
        return Set.copyOf(all);
    }

    /** Whether {@code subjectId} is one of the people this case is about. */
    public boolean concerns(String subjectId) {
        return entities().contains(Entity.subject(subjectId));
    }
}

package dev.dwarpal.soc;

import dev.dwarpal.domain.Validate;

import java.util.Objects;
import java.util.Set;

/**
 * What an entity is worth protecting, for ranking alerts and cases.
 *
 * @param criticality 1 (little harm if lost) to 5 (the business stops: payroll, the CEO, domain admins)
 * @param owner       who is responsible for it (an id), or {@code unknown}
 * @param tags        labels such as {@code executive}, {@code server}, {@code finance}; ids, at most 16
 * @param known       false when the catalogue has no entry: the criticality is then the deployment's
 *                    default for unknown assets, and the asset is shown as unknown, never as low
 */
public record Asset(Entity entity, int criticality, String owner, Set<String> tags, boolean known) {

    public static final int MAX_TAGS = 16;

    public Asset {
        Objects.requireNonNull(entity, "entity");
        if (criticality < 1 || criticality > 5) {
            throw new IllegalArgumentException("criticality is 1 to 5");
        }
        Validate.id(owner, "asset.owner");
        tags = Set.copyOf(tags);
        if (tags.size() > MAX_TAGS) {
            throw new IllegalArgumentException("at most " + MAX_TAGS + " tags");
        }
        tags.forEach(t -> Validate.id(t, "asset.tag"));
    }
}

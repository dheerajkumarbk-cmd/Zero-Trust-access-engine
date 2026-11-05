package dev.dwarpal.ueba;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import dev.dwarpal.domain.Validate;
import dev.dwarpal.soc.Asset;
import dev.dwarpal.soc.AssetCatalog;
import dev.dwarpal.soc.Entity;

/**
 * Who is compared with whom: the deployer supplies a group (role or department) per person, from the directory.
 * A device belongs to its owner's group, the owner taken from the asset catalogue; a device without a known
 * owner has no peers. Groups are fixed at start-up: an event cannot move anyone into another group.
 */
public final class PeerGroups {

    public static final int MAX_MEMBERS = 1_000_000;

    private final Map<String, String> groupOf;
    private final Map<String, Integer> sizes;
    private final AssetCatalog catalog;

    private PeerGroups(Map<String, String> groupOf, AssetCatalog catalog) {
        Objects.requireNonNull(groupOf, "groupOf");
        if (groupOf.size() > MAX_MEMBERS) {
            throw new IllegalArgumentException("at most " + MAX_MEMBERS + " people");
        }
        Map<String, String> m = new HashMap<>();
        Map<String, Integer> n = new HashMap<>();
        for (Map.Entry<String, String> e : groupOf.entrySet()) {
            String g = Validate.label(e.getValue(), "group");
            m.put(Validate.id(e.getKey(), "subject"), g);
            n.merge(g, 1, Integer::sum);
        }
        this.groupOf = Map.copyOf(m);
        this.sizes = Map.copyOf(n);
        this.catalog = catalog;
    }

    /** Groups by person id; devices have no peers. */
    public static PeerGroups of(Map<String, String> groupOfSubject) {
        return new PeerGroups(groupOfSubject, null);
    }

    /** Groups by person id; a device belongs to the group of its owner in {@code catalog}. */
    public static PeerGroups of(Map<String, String> groupOfSubject, AssetCatalog catalog) {
        return new PeerGroups(groupOfSubject, Objects.requireNonNull(catalog, "catalog"));
    }

    public static PeerGroups none() {
        return new PeerGroups(Map.of(), null);
    }

    /** The group of an entity, if it has one. */
    public Optional<String> group(Entity e) {
        Objects.requireNonNull(e, "entity");
        if (e.kind() == Entity.Kind.SUBJECT) {
            return Optional.ofNullable(groupOf.get(e.id()));
        }
        if (e.kind() == Entity.Kind.DEVICE && catalog != null) {
            Asset a = catalog.asset(e);
            return a.known() ? Optional.ofNullable(groupOf.get(a.owner())) : Optional.empty();
        }
        return Optional.empty();
    }

    /** Number of people in a group (devices are counted with their owner). */
    public int size(String group) {
        return sizes.getOrDefault(group, 0);
    }
}

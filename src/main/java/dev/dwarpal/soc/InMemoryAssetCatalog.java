package dev.dwarpal.soc;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A fixed catalogue built at start-up. Unknown entities get {@code unknownCriticality} (3, the middle, by
 * default) and are marked unknown: an attacker's new device must not rank as harmless because nobody
 * listed it.
 */
public final class InMemoryAssetCatalog implements AssetCatalog {

    public static final int MAX_ASSETS = 1_000_000;

    private final Map<Entity, Asset> assets;
    private final int unknownCriticality;

    public InMemoryAssetCatalog(List<Asset> entries, int unknownCriticality) {
        Objects.requireNonNull(entries, "entries");
        if (entries.size() > MAX_ASSETS) {
            throw new IllegalArgumentException("at most " + MAX_ASSETS + " assets");
        }
        if (unknownCriticality < 1 || unknownCriticality > 5) {
            throw new IllegalArgumentException("criticality is 1 to 5");
        }
        Map<Entity, Asset> m = new HashMap<>();
        for (Asset a : entries) {
            if (!a.known()) {
                throw new IllegalArgumentException("catalogue entries are known assets");
            }
            if (m.put(a.entity(), a) != null) {
                throw new IllegalArgumentException("duplicate asset " + a.entity());
            }
        }
        this.assets = Map.copyOf(m);
        this.unknownCriticality = unknownCriticality;
    }

    public InMemoryAssetCatalog(List<Asset> entries) {
        this(entries, 3);
    }

    @Override
    public Asset asset(Entity entity) {
        Objects.requireNonNull(entity, "entity");
        Asset a = assets.get(entity);
        return a != null ? a : new Asset(entity, unknownCriticality, "unknown", Set.of(), false);
    }

    public int size() {
        return assets.size();
    }
}

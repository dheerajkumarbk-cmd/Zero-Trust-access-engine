package dev.dwarpal.soc;

/** Asset criticality, owners and tags, supplied by the deployer; read by ranking and cases. */
public interface AssetCatalog {

    /** The asset; for an entity without an entry, an asset with {@code known == false}. */
    Asset asset(Entity entity);
}

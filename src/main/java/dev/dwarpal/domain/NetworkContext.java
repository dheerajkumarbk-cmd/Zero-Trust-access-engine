package dev.dwarpal.domain;

/**
 * Where the request comes from. {@code accuracyKm} is the GeoIP accuracy radius; the
 * impossible-travel scorer subtracts it so VPN and mobile-network noise does not look like
 * teleportation (model M7). The country code is canonicalised to upper case.
 */
public record NetworkContext(String ip, String asn, String country,
                             double latitude, double longitude, double accuracyKm) {

    public NetworkContext {
        Validate.id(ip, "network.ip");
        Validate.id(asn, "network.asn");
        country = Validate.country(country, "network.country");
        if (!(latitude >= -90 && latitude <= 90) || !(longitude >= -180 && longitude <= 180)) {
            throw new IllegalArgumentException("network coordinates out of range");
        }
        if (!(accuracyKm >= 0) || Double.isInfinite(accuracyKm)) {
            throw new IllegalArgumentException("network.accuracyKm must be finite and >= 0");
        }
    }
}

package dev.dwarpal.risk.scorers;

/** Great-circle distance on a spherical Earth (haversine formula). Error under 0.5%, ample for travel checks. */
public final class Geo {

    public static final double EARTH_RADIUS_KM = 6371.0088;

    private Geo() {
    }

    /**
     * d = 2R arcsin( sqrt( sin^2(dLat/2) + cos(lat1) cos(lat2) sin^2(dLon/2) ) )
     */
    public static double haversineKm(double lat1, double lon1, double lat2, double lon2) {
        double p1 = Math.toRadians(lat1);
        double p2 = Math.toRadians(lat2);
        double dp = Math.toRadians(lat2 - lat1);
        double dl = Math.toRadians(lon2 - lon1);
        double a = Math.sin(dp / 2) * Math.sin(dp / 2)
                + Math.cos(p1) * Math.cos(p2) * Math.sin(dl / 2) * Math.sin(dl / 2);
        // min() guards against a rounding error pushing a above 1 (asin domain) for antipodal points.
        return 2 * EARTH_RADIUS_KM * Math.asin(Math.min(1.0, Math.sqrt(a)));
    }
}

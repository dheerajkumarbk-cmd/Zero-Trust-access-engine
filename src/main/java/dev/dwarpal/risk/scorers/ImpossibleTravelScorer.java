package dev.dwarpal.risk.scorers;

import dev.dwarpal.behavior.BehaviorHistory;
import dev.dwarpal.behavior.LoginEvent;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.RiskScorer;
import dev.dwarpal.risk.SignalSnapshot;

import java.time.Duration;
import java.util.Locale;
import java.util.Optional;

/**
 * Impossible travel (model M7): the user's last trusted login and this request are too far apart
 * for the time between them.
 * <pre>
 *   v = max(0, haversine(last, now) - accuracy_last - accuracy_now) / elapsed_hours
 * </pre>
 * Subtracting both GeoIP accuracy radii is the false-positive fix: mobile networks and VPN exits
 * are often geolocated hundreds of kilometres off, and treating the uncertainty as real distance
 * is what makes naive impossible-travel rules noisy.
 *
 * <p>When v exceeds {@code maxPlausibleKmh} the evidence is ln(P(impossible | attack) /
 * P(impossible | legit)); both probabilities are configurable assumptions (legit users still
 * trigger it through VPNs). Plausible travel is <em>not</em> reassurance: an attacker in the same
 * city gives no signal here, so the scorer stays silent rather than lowering risk.
 */
public final class ImpossibleTravelScorer implements RiskScorer {

    private final BehaviorHistory history;
    private final double maxPlausibleKmh;
    private final double logLr;

    public ImpossibleTravelScorer(BehaviorHistory history, double maxPlausibleKmh,
                                  double pImpossibleGivenAttack, double pImpossibleGivenLegit) {
        this.history = history;
        this.maxPlausibleKmh = Validate.positive(maxPlausibleKmh, "maxPlausibleKmh");
        Validate.probability(pImpossibleGivenAttack, "pImpossibleGivenAttack");
        Validate.probability(pImpossibleGivenLegit, "pImpossibleGivenLegit");
        if (!(pImpossibleGivenAttack > pImpossibleGivenLegit && pImpossibleGivenLegit > 0)) {
            throw new IllegalArgumentException("need 0 < P(legit) < P(attack)");
        }
        this.logLr = Math.log(pImpossibleGivenAttack / pImpossibleGivenLegit);
    }

    /** Airliner cruise ~900 km/h, rounded up; 60% of attacks vs 2% of legit logins trip it (assumptions). */
    public static ImpossibleTravelScorer withDefaults(BehaviorHistory h) {
        return new ImpossibleTravelScorer(h, 1000, 0.60, 0.02);
    }

    @Override
    public String name() {
        return "impossible-travel";
    }

    @Override
    public Optional<RiskFactor> score(AccessRequest request, SignalSnapshot signals) {
        Optional<LoginEvent> lastOpt = history.lastLogin(request.subject().id());
        if (lastOpt.isEmpty()) {
            return Optional.empty();
        }
        LoginEvent last = lastOpt.get();
        NetworkContext a = last.network();
        NetworkContext b = request.network();
        double km = Geo.haversineKm(a.latitude(), a.longitude(), b.latitude(), b.longitude());
        double effectiveKm = Math.max(0, km - a.accuracyKm() - b.accuracyKm());
        if (effectiveKm == 0) {
            return Optional.empty();
        }
        Duration elapsed = Duration.between(last.at(), request.timestamp());
        if (elapsed.isNegative()) {
            return Optional.empty(); // out-of-order data: no basis for a speed
        }
        double hours = elapsed.toMillis() / 3_600_000.0;
        double kmh = hours == 0 ? Double.POSITIVE_INFINITY : effectiveKm / hours;
        if (kmh <= maxPlausibleKmh) {
            return Optional.empty();
        }
        return Optional.of(new RiskFactor(name(), logLr, String.format(Locale.ROOT,
                "%.0f km from last login in %s %.1f h earlier = %s (max plausible %.0f km/h)",
                effectiveKm, a.country(), hours,
                Double.isInfinite(kmh) ? "simultaneous" : String.format(Locale.ROOT, "%.0f km/h", kmh),
                maxPlausibleKmh)));
    }
}

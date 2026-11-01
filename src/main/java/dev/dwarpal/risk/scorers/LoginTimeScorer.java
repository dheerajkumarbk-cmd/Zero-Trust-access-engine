package dev.dwarpal.risk.scorers;

import dev.dwarpal.behavior.BehaviorHistory;
import dev.dwarpal.behavior.LoginEvent;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.RiskScorer;
import dev.dwarpal.risk.SignalSnapshot;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Unusual login time (model M6), with circular statistics.
 *
 * <p>The user's recent login times form a circular kernel density (each login votes for nearby
 * times on a 24-hour clock); an attacker is modelled as uniform over the day, since they work in
 * their own time zone. The evidence is the log ratio of the two densities at this login's time:
 * <pre>
 *   LLR = - c * ln( f_user(theta) / f_uniform(theta) ),    c = n / (n + k)
 * </pre>
 * c is a confidence factor so a short history cannot produce strong claims. Positive means "an odd
 * hour for this user", negative "one of their usual hours" (reassurance, capped downstream).
 *
 * <p>Why a kernel density rather than one fitted von Mises curve: a user who logs in at 09:15 and
 * again at 14:00 has two habits. A single curve averages them into 11:40, a time they never use,
 * and calls it the most normal. The kernel keeps both peaks.
 */
public final class LoginTimeScorer implements RiskScorer {

    private final BehaviorHistory history;
    private final int minSamples;
    private final double kernelKappa;
    private final double shrinkage;

    /**
     * @param kernelKappa concentration of each login's vote; 8 is a spread of about +/- 80 minutes
     */
    public LoginTimeScorer(BehaviorHistory history, int minSamples, double kernelKappa, double shrinkage) {
        if (minSamples < 2 || !(kernelKappa > 0 && kernelKappa <= 50) || !(shrinkage >= 0)) {
            throw new IllegalArgumentException("invalid login-time parameters");
        }
        this.history = history;
        this.minSamples = minSamples;
        this.kernelKappa = kernelKappa;
        this.shrinkage = shrinkage;
    }

    /** At least 8 logins; each login votes within about +/- 80 minutes; confidence n/(n+10). */
    public static LoginTimeScorer withDefaults(BehaviorHistory h) {
        return new LoginTimeScorer(h, 8, 8, 10);
    }

    @Override
    public String name() {
        return "login-time";
    }

    @Override
    public Optional<RiskFactor> score(AccessRequest request, SignalSnapshot signals) {
        List<Integer> minutes = history.loginMinutes(request.subject().id());
        if (minutes.size() < minSamples) {
            return Optional.empty();
        }
        int nowMinute = LoginEvent.of(request, false).minuteOfDayUtc();
        double logRatio = CircularStats.logDensityRatio(CircularStats.toAngle(nowMinute), minutes, kernelKappa);
        double confidence = minutes.size() / (minutes.size() + shrinkage);
        double llr = -confidence * logRatio;
        int busiest = CircularStats.busiestMinute(minutes, kernelKappa);
        return Optional.of(new RiskFactor(name(), llr, String.format(Locale.ROOT,
                "login at %02d:%02d UTC is %.2fx as typical as a random time for this user; busiest %02d:%02d UTC (n=%d)",
                nowMinute / 60, nowMinute % 60, Math.exp(logRatio), busiest / 60, busiest % 60, minutes.size())));
    }
}

package dev.dwarpal.risk.scorers;

import dev.dwarpal.behavior.FailureView;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.RiskScorer;
import dev.dwarpal.risk.SignalSnapshot;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;

/**
 * Heightened-alert mode: when the whole organisation is under a credential attack, everyone's
 * risk goes up a little.
 *
 * <p>In Bayesian terms, the base rate of attack is not constant: during a credential-stuffing
 * campaign, any given login is more likely to be hostile. The org-wide failure count is compared
 * with its normal level using the same Poisson likelihood ratio as {@link FailureRateScorer}.
 *
 * <p><b>Capped at {@code maxLogLr} (default x10).</b> Without a cap an attacker could flood failures
 * to get every employee denied, turning a defence into a company-wide denial of service. Capped,
 * the surge only removes the "familiar user" benefit, so borderline logins step up instead of
 * being denied. The cap is a deliberate, explainable policy choice.
 */
public final class AttackSurgeScorer implements RiskScorer {

    private final FailureView failures;
    private final Duration window;
    private final double lambdaNormal;
    private final double lambdaAttack;
    private final double maxLogLr;

    public AttackSurgeScorer(FailureView failures, Duration window, double lambdaNormal, double lambdaAttack, double maxLogLr) {
        this.failures = failures;
        if (window.isNegative() || window.isZero() || window.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("window must be between 0 and 1 hour");
        }
        this.window = window;
        this.lambdaNormal = Validate.positive(lambdaNormal, "lambdaNormal");
        this.lambdaAttack = Validate.positive(lambdaAttack, "lambdaAttack");
        if (lambdaAttack <= lambdaNormal) {
            throw new IllegalArgumentException("attack rate must exceed normal rate");
        }
        this.maxLogLr = Validate.positive(maxLogLr, "maxLogLr");
    }

    /**
     * 15-minute window; normally ~20 failures org-wide, ~200 in a campaign; at most x10 risk.
     * The normal rate depends on organisation size and must be set per deployment.
     */
    public static AttackSurgeScorer withDefaults(FailureView failures) {
        return new AttackSurgeScorer(failures, Duration.ofMinutes(15), 20, 200, Math.log(10));
    }

    @Override
    public String name() {
        return "attack-surge";
    }

    @Override
    public Optional<RiskFactor> score(AccessRequest request, SignalSnapshot signals) {
        Instant to = request.timestamp();
        long k = failures.totalFailures(to.minus(window), to);
        if (k <= lambdaNormal) {
            return Optional.empty();
        }
        double poisson = k * Math.log(lambdaAttack / lambdaNormal) - (lambdaAttack - lambdaNormal);
        double llr = Math.min(maxLogLr, Math.max(0, poisson));
        if (llr == 0) {
            return Optional.empty();
        }
        return Optional.of(new RiskFactor(name(), llr, String.format(Locale.ROOT,
                "org-wide: %d failed logins in %d min (normal ~%.0f): heightened alert, capped at x%.0f",
                k, window.toMinutes(), lambdaNormal, Math.exp(maxLogLr))));
    }
}

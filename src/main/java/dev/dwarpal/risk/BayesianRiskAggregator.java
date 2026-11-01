package dev.dwarpal.risk;

import dev.dwarpal.domain.Validate;

import java.util.ArrayList;
import java.util.List;

/**
 * Turns evidence into a probability of attack with Bayes' rule in log-odds form (model M3):
 *
 * <pre>
 *   logit P(attack | x) = logit P(attack) + sum_k ln( p(x_k | attack) / p(x_k | legit) )
 * </pre>
 *
 * <p>Starting from the base rate is the point: Axelsson (ACM TISSEC 2000) showed that when
 * attacks are rare, even an accurate detector produces mostly false alarms. Engines that ignore
 * the prior over-react, which is where analyst alert fatigue comes from.
 *
 * <p><b>Asymmetric bounds.</b> Evidence is not equally trustworthy in both directions. Proof of
 * attack (impossible travel, known-bad ASN) is hard to fake; "looks familiar" (same user-agent,
 * same device id) is exactly what a session-cookie thief replays. So:
 * <ul>
 *   <li>each attack-leaning factor is capped at {@code maxAttackLogLr};</li>
 *   <li>each reassuring factor is capped at {@code maxReassuranceLogLrPerFactor};</li>
 *   <li>all reassurance together is capped at {@code maxTotalReassuranceLogLr} (scaled down
 *       proportionally, so the result does not depend on scorer order).</li>
 * </ul>
 * Spoofed familiarity can therefore soften strong attack evidence, but never cancel it.
 *
 * <p>The sum assumes the factors are conditionally independent ("naive Bayes"); correlated
 * scorers will overcount, which is a documented limitation.
 */
public final class BayesianRiskAggregator {

    private final double priorAttack;
    private final double maxAttackLogLr;
    private final double maxReassuranceLogLrPerFactor;
    private final double maxTotalReassuranceLogLr;

    public BayesianRiskAggregator(double priorAttack, double maxAttackLogLr,
                                  double maxReassuranceLogLrPerFactor, double maxTotalReassuranceLogLr) {
        Validate.probability(priorAttack, "priorAttack");
        if (priorAttack == 0.0 || priorAttack == 1.0) {
            throw new IllegalArgumentException("priorAttack must be strictly between 0 and 1");
        }
        this.priorAttack = priorAttack;
        this.maxAttackLogLr = Validate.positive(maxAttackLogLr, "maxAttackLogLr");
        this.maxReassuranceLogLrPerFactor = Validate.positive(maxReassuranceLogLrPerFactor, "maxReassuranceLogLrPerFactor");
        this.maxTotalReassuranceLogLr = Validate.positive(maxTotalReassuranceLogLr, "maxTotalReassuranceLogLr");
    }

    /** Defaults: reassurance capped at a factor of 10 per signal and 10 in total. */
    public BayesianRiskAggregator(double priorAttack, double maxAttackLogLr) {
        this(priorAttack, maxAttackLogLr, Math.min(maxAttackLogLr, Math.log(10)), Math.min(maxAttackLogLr, Math.log(10)));
    }

    public double priorAttack() {
        return priorAttack;
    }

    public RiskAssessment aggregate(List<RiskFactor> rawFactors, List<String> failedScorers) {
        double rawReassurance = 0.0;
        for (RiskFactor f : rawFactors) {
            if (f.logLikelihoodRatio() < 0) {
                rawReassurance += Math.min(-f.logLikelihoodRatio(), maxReassuranceLogLrPerFactor);
            }
        }
        double reassuranceScale = rawReassurance > maxTotalReassuranceLogLr
                ? maxTotalReassuranceLogLr / rawReassurance
                : 1.0;

        List<RiskFactor> factors = new ArrayList<>(rawFactors.size());
        double total = 0.0;
        for (RiskFactor f : rawFactors) {
            double llr = f.logLikelihoodRatio();
            boolean capped;
            double used;
            if (llr >= 0) {
                capped = llr > maxAttackLogLr;
                used = capped ? maxAttackLogLr : llr;
            } else {
                capped = -llr > maxReassuranceLogLrPerFactor || reassuranceScale < 1.0;
                used = -Math.min(-llr, maxReassuranceLogLrPerFactor) * reassuranceScale;
            }
            factors.add(capped ? new RiskFactor(f.name(), used, f.evidence() + " [capped]") : f);
            total += used;
        }
        double posterior = sigmoid(logit(priorAttack) + total);
        return new RiskAssessment(factors, priorAttack, total, posterior, failedScorers);
    }

    static double logit(double p) {
        return Math.log(p / (1.0 - p));
    }

    static double sigmoid(double z) {
        return 1.0 / (1.0 + Math.exp(-z));
    }
}

package dev.dwarpal.risk;

import java.util.List;

/**
 * Result of combining all risk evidence for one request.
 *
 * @param factors          evidence that contributed, after clamping
 * @param priorAttack      base rate P(attack) before looking at evidence
 * @param totalLogLikelihoodRatio sum of all factor log-likelihood ratios
 * @param posteriorAttack  P(attack | evidence)
 * @param failedScorers    scorers whose signal source was unavailable
 */
public record RiskAssessment(List<RiskFactor> factors, double priorAttack, double totalLogLikelihoodRatio,
                             double posteriorAttack, List<String> failedScorers) {

    public RiskAssessment {
        factors = List.copyOf(factors);
        failedScorers = List.copyOf(failedScorers);
    }

    /** Assessment used when a hard gate decided before any scoring happened. */
    public static RiskAssessment notEvaluated(double priorAttack) {
        return new RiskAssessment(List.of(), priorAttack, 0.0, priorAttack, List.of());
    }

    public boolean degraded() {
        return !failedScorers.isEmpty();
    }
}

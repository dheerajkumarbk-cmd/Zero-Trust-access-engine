package dev.dwarpal.risk;

import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;

/**
 * One piece of evidence about a request, expressed as a log-likelihood ratio
 * {@code ln( p(x | attack) / p(x | legit) )} (model M1, after Freeman et al., NDSS 2016).
 * Positive values look attacker-like, negative values look like the real user, zero is neutral.
 *
 * <p>Because evidence adds up in log space, each factor is an exact, explainable share of the
 * final score; there are no hand-picked "+25 points" weights.
 *
 * <p>Evidence often quotes attacker-controlled input (a user-agent string), so it is sanitised.
 */
public record RiskFactor(String name, double logLikelihoodRatio, String evidence) {

    public static final int MAX_EVIDENCE_LENGTH = 256;

    public RiskFactor {
        Validate.id(name, "factor.name");
        Validate.finite(logLikelihoodRatio, "factor.logLikelihoodRatio");
        evidence = Sanitize.text(evidence, MAX_EVIDENCE_LENGTH);
    }

    /** How many times more likely this evidence is under attack than under legitimate use. */
    public double likelihoodRatio() {
        return Math.exp(logLikelihoodRatio);
    }
}

package dev.dwarpal.decision;

import dev.dwarpal.domain.Validate;

/**
 * Chooses ALLOW / STEP_UP / DENY by minimising expected cost (model M2), extending the
 * cost-sensitive decision threshold of Elkan (IJCAI 2001) to three actions.
 *
 * <p>With {@code p = P(attack | evidence)}:
 * <pre>
 *   L(ALLOW)   = p * C_breach
 *   L(STEP_UP) = p * beta * C_breach + (1 - p) * C_friction
 *   L(DENY)    = (1 - p) * C_wrongDeny
 * </pre>
 * where {@code beta} is the probability that an attacker gets past the step-up challenge.
 *
 * <p>Key consequence: the thresholds depend on {@code beta}. Weak push MFA under MFA-fatigue
 * attacks (high beta) makes the engine deny sooner; phishing-resistant MFA (beta near 0) makes
 * step-up preferable to deny. The three-action extension is Dwarpal's own derivation.
 *
 * @param breachCost             C_breach: cost of letting an attacker in
 * @param frictionCost           C_friction: cost of challenging a legitimate user
 * @param wrongDenyCost          C_wrongDeny: cost of blocking a legitimate user
 * @param stepUpBypassProbability beta: P(attacker passes step-up)
 */
public record CostModel(double breachCost, double frictionCost, double wrongDenyCost,
                        double stepUpBypassProbability) {

    public CostModel {
        Validate.positive(breachCost, "breachCost");
        Validate.positive(frictionCost, "frictionCost");
        Validate.positive(wrongDenyCost, "wrongDenyCost");
        Validate.probability(stepUpBypassProbability, "stepUpBypassProbability");
    }

    public double expectedLoss(Outcome outcome, double pAttack) {
        Validate.probability(pAttack, "pAttack");
        return switch (outcome) {
            case ALLOW -> pAttack * breachCost;
            case STEP_UP -> pAttack * stepUpBypassProbability * breachCost + (1 - pAttack) * frictionCost;
            case DENY -> (1 - pAttack) * wrongDenyCost;
            case ALLOW_LIMITED -> throw new IllegalArgumentException(
                    "ALLOW_LIMITED is policy-driven and has no cost-model loss");
        };
    }

    /**
     * Action with the lowest expected loss. Ties go to the more restrictive action, so rounding
     * can never tip a borderline case toward ALLOW.
     */
    public Outcome bestAction(double pAttack) {
        Outcome best = Outcome.DENY;
        double bestLoss = expectedLoss(Outcome.DENY, pAttack);
        for (Outcome candidate : new Outcome[]{Outcome.STEP_UP, Outcome.ALLOW}) {
            double loss = expectedLoss(candidate, pAttack);
            if (loss < bestLoss) {
                best = candidate;
                bestLoss = loss;
            }
        }
        return best;
    }

    /** Closed form: STEP_UP beats ALLOW when p exceeds this value. */
    public double stepUpOverAllowThreshold() {
        return frictionCost / (frictionCost + breachCost * (1 - stepUpBypassProbability));
    }

    /**
     * Closed form: DENY beats STEP_UP when p exceeds this value. Negative infinity when blocking
     * a user is no costlier than challenging them, i.e. DENY always beats STEP_UP.
     */
    public double denyOverStepUpThreshold() {
        double net = wrongDenyCost - frictionCost;
        if (net <= 0) {
            return Double.NEGATIVE_INFINITY;
        }
        return net / (net + stepUpBypassProbability * breachCost);
    }
}

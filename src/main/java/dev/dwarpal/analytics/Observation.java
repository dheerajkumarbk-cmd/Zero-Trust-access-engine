package dev.dwarpal.analytics;

import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.risk.RiskFactor;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * One labelled decision: what the request really was, and what the engine did. The label comes from the
 * caller (the simulated organisation's scenario, or an analyst's verdict), never from the decision.
 * Only the scenario name, the outcome and the risk numbers are kept: nothing that identifies the request.
 *
 * @param scenario  a label such as {@code L1_NORMAL} or {@code A5_TOR}
 * @param attack    true if the request really was an attack
 * @param outcome   the engine's final outcome
 * @param restricted whether the decision was restricted
 * @param posterior P(attack | evidence) as the engine computed it (the prior when a gate decided first)
 * @param gated     true when a hard gate decided before risk was evaluated
 * @param factors   risk factor name to its log-likelihood ratio, as used by the engine
 */
public record Observation(String scenario, boolean attack, Outcome outcome, boolean restricted, double posterior,
                          boolean gated, Map<String, Double> factors) {

    public Observation {
        Validate.id(scenario, "scenario");
        Objects.requireNonNull(outcome, "outcome");
        Validate.probability(posterior, "posterior");
        factors = Map.copyOf(factors);
        factors.values().forEach(v -> Validate.finite(v, "factor"));
    }

    public static Observation of(String scenario, boolean attack, Decision d) {
        Map<String, Double> f = new LinkedHashMap<>();
        for (RiskFactor rf : d.risk().factors()) {
            f.merge(rf.name(), rf.logLikelihoodRatio(), Double::sum);
        }
        return new Observation(scenario, attack, d.outcome(), d.restricted(), d.risk().posteriorAttack(),
                d.matchedPolicyId().startsWith("hard-gate:"), f);
    }

    /**
     * A score that orders decisions by how suspicious the engine found them: the outcome first (a gate or
     * policy DENY outranks any posterior), then the posterior within one outcome. Using the posterior alone
     * would rank a request a hard gate denied (whose posterior is just the prior) as the most benign of all.
     */
    public double score() {
        return outcome.ordinal() * 2.0 + posterior;
    }
}

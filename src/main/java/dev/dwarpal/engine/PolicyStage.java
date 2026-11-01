package dev.dwarpal.engine;

import dev.dwarpal.policy.EvaluationContext;
import dev.dwarpal.policy.PolicySet;

/** Stage 3: evaluate the policy set. Its effect is a floor the risk result cannot go below. */
final class PolicyStage implements DecisionStage {

    private final PolicySet policySet;

    PolicyStage(PolicySet policySet) {
        this.policySet = policySet;
    }

    @Override
    public String name() {
        return "policy";
    }

    @Override
    public void apply(DecisionContext ctx) {
        PolicySet.Result result = policySet.evaluate(
                new EvaluationContext(ctx.request(), ctx.risk().posteriorAttack()));
        ctx.matchedPolicyId(result.policyId());
        ctx.escalate(result.effect().floor(), result.defaulted()
                ? "no policy grants access; default effect " + result.effect()
                : "policy " + result.policyId() + " requires at least " + result.effect().floor());
    }
}

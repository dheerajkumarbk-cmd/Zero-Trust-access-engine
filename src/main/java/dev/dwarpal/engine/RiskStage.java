package dev.dwarpal.engine;

import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.FailMode;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.risk.RiskAssessment;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.RiskScorer;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Stage 2: run every scorer, combine the evidence with Bayes (M3), then pick the cost-optimal
 * action (M2). Unavailable signals trigger the resource's fail mode.
 */
final class RiskStage implements DecisionStage {

    private final List<RiskScorer> scorers;
    private final BayesianRiskAggregator aggregator;
    private final CostModel costModel;

    RiskStage(List<RiskScorer> scorers, BayesianRiskAggregator aggregator, CostModel costModel) {
        this.scorers = List.copyOf(scorers);
        this.aggregator = aggregator;
        this.costModel = costModel;
    }

    @Override
    public String name() {
        return "risk";
    }

    @Override
    public void apply(DecisionContext ctx) {
        List<RiskFactor> factors = new ArrayList<>();
        List<String> failed = new ArrayList<>();
        for (RiskScorer scorer : scorers) {
            try {
                Optional<RiskFactor> factor = scorer.score(ctx.request(), ctx.signals());
                factor.ifPresent(factors::add);
            } catch (RuntimeException e) {
                failed.add(scorer.name());
            }
        }
        RiskAssessment risk = aggregator.aggregate(factors, failed);
        ctx.risk(risk);

        double p = risk.posteriorAttack();
        Outcome action = costModel.bestAction(p);
        ctx.escalate(action, String.format(Locale.ROOT,
                "cost-optimal action at P(attack)=%.4f is %s (step-up above %.4f, deny above %.4f, beta=%.2f)",
                p, action, costModel.stepUpOverAllowThreshold(), costModel.denyOverStepUpThreshold(),
                costModel.stepUpBypassProbability()));

        if (risk.degraded()) {
            FailMode mode = ctx.request().resource().failMode();
            if (mode == FailMode.FAIL_CLOSED) {
                ctx.terminate(Outcome.DENY, "fail-closed",
                        "signal source unavailable " + failed + "; resource is FAIL_CLOSED");
            } else {
                ctx.escalate(Outcome.STEP_UP,
                        "signal source unavailable " + failed + "; degraded mode requires step-up");
            }
        }
    }
}

package dev.dwarpal.engine;

import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.Action;

/**
 * Stage 5: enforce the meaning of a restricted (read-only) session inside the engine, instead of
 * trusting every PEP to interpret ALLOW_LIMITED correctly. A restricted session may only READ;
 * a DOWNLOAD, WRITE or ADMIN request under a restriction is denied outright.
 */
final class ObligationStage implements DecisionStage {

    @Override
    public String name() {
        return "obligations";
    }

    @Override
    public void apply(DecisionContext ctx) {
        Action action = ctx.request().action();
        if (ctx.restricted() && action != Action.READ) {
            ctx.terminate(Outcome.DENY, ctx.matchedPolicyId(),
                    "session is restricted to READ; " + action + " is not permitted");
        }
    }
}

package dev.dwarpal.engine;

import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AuthenticationContext;

import java.time.Duration;
import java.util.Locale;
import java.util.Optional;

/**
 * Stage 5: if the decision so far is STEP_UP and the subject has <em>already</em> passed a
 * verified, fresh, strong-enough authentication, treat that as the step-up and decide again.
 *
 * <p>Passing an authenticator is Bayesian evidence. A legitimate user passes almost always; an
 * attacker passes with probability {@code beta} of that method. So:
 * <pre>
 *   P(attack | passed) = p * beta / (p * beta + (1 - p))
 * </pre>
 * and the cost model (M2) picks again with this new probability. WebAuthn (beta 0.01) collapses
 * the risk; push approval (beta 0.30) barely moves it, so under real suspicion the engine still
 * asks for something stronger, or denies. That is how the authentication layer and the core
 * engine share one model of trust.
 *
 * <p>This is the only place an outcome can go down, and only from STEP_UP to ALLOW/ALLOW_LIMITED:
 * a requirement being satisfied, not a policy being loosened. Read-only restrictions survive.
 */
final class StepUpResolutionStage implements DecisionStage {

    private final AssuranceSettings settings;
    private final CostModel costModel;

    StepUpResolutionStage(AssuranceSettings settings, CostModel costModel) {
        this.settings = settings;
        this.costModel = costModel;
    }

    @Override
    public String name() {
        return "step-up-resolution";
    }

    @Override
    public void apply(DecisionContext ctx) {
        if (ctx.outcome() != Outcome.STEP_UP) {
            return;
        }
        Optional<AuthenticationContext> verified = ctx.verifiedAuthentication();
        if (verified.isEmpty()) {
            ctx.note("no verified authentication in this request; challenge required");
            return;
        }
        AuthenticationContext auth = verified.get();
        Duration age = Duration.between(auth.authenticatedAt(), ctx.request().timestamp());
        if (age.isNegative()) {
            ctx.note("authentication time is after the request time; ignored");
            return;
        }
        if (age.compareTo(settings.maxAuthenticationAge()) > 0) {
            ctx.note("last authentication (" + auth.method() + ") is " + age.toMinutes()
                    + " min old; re-authentication required");
            return;
        }
        if (!auth.method().satisfiesStepUp()) {
            ctx.note(auth.method() + " alone does not satisfy step-up");
            return;
        }

        double p = ctx.risk().posteriorAttack();
        double beta = settings.bypass(auth.method());
        double after = (p * beta) / (p * beta + (1 - p));
        Outcome action = costModel.bestAction(after);
        String detail = String.format(Locale.ROOT, "%s (beta=%.2f) passed %d min ago: P(attack) %.4f -> %.4f",
                auth.method(), beta, age.toMinutes(), p, after);

        switch (action) {
            case ALLOW -> ctx.satisfyStepUp(detail + "; step-up satisfied");
            case STEP_UP -> ctx.note(detail + "; a stronger authenticator than " + auth.method() + " is required");
            case DENY -> ctx.terminate(Outcome.DENY, ctx.matchedPolicyId(),
                    detail + "; risk remains too high even after authentication");
            default -> throw new IllegalStateException("cost model returned " + action);
        }
    }
}

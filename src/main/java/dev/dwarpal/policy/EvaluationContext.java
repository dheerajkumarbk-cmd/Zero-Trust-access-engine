package dev.dwarpal.policy;

import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Validate;

import java.util.Objects;

/** Everything a policy condition may look at: the request plus the computed attack probability. */
public record EvaluationContext(AccessRequest request, double posteriorAttack) {

    public EvaluationContext {
        Objects.requireNonNull(request, "context.request");
        Validate.probability(posteriorAttack, "context.posteriorAttack");
    }
}

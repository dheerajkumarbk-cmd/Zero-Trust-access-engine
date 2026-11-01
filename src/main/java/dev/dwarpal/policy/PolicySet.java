package dev.dwarpal.policy;

import dev.dwarpal.domain.Validate;

import java.util.List;
import java.util.Objects;

/**
 * A versioned, immutable bundle of policies. The default effect is mandatory: there is no
 * implicit "allow if nothing matched".
 *
 * <p>Evaluation separates grants from constraints (see {@link Effect}):
 * <ul>
 *   <li>DENY_OVERRIDES: the result is the most restrictive of all matching grants and
 *       constraints; with no matching grant, the default effect stands in for the grant.</li>
 *   <li>FIRST_APPLICABLE: policies are scanned in order; a DENY ends the scan, a grant ends the
 *       scan, and REQUIRE_STEP_UP constraints seen before the grant still apply.</li>
 * </ul>
 */
public record PolicySet(String version, CombiningAlgorithm algorithm, Effect defaultEffect, List<Policy> policies) {

    /** Policy id reported when no policy granted access and the default effect applied. */
    public static final String DEFAULT_POLICY_ID = "default";

    public PolicySet {
        Validate.id(version, "policySet.version");
        Objects.requireNonNull(algorithm, "policySet.algorithm");
        Objects.requireNonNull(defaultEffect, "policySet.default");
        policies = List.copyOf(policies);
    }

    /**
     * Outcome of evaluating the policy set against one request.
     *
     * @param defaulted true when no policy granted access, so the default effect was used
     */
    public record Result(Effect effect, String policyId, boolean defaulted) {
    }

    public Result evaluate(EvaluationContext context) {
        Policy grant = null;
        Policy constraint = null;
        for (Policy p : policies) {
            if (!p.when().matches(context)) {
                continue;
            }
            if (p.effect().grants()) {
                if (grant == null || p.effect().compareTo(grant.effect()) > 0) {
                    grant = p;
                }
                if (algorithm == CombiningAlgorithm.FIRST_APPLICABLE) {
                    break;
                }
            } else {
                if (constraint == null || p.effect().compareTo(constraint.effect()) > 0) {
                    constraint = p;
                }
                if (algorithm == CombiningAlgorithm.FIRST_APPLICABLE && p.effect() == Effect.DENY) {
                    break;
                }
            }
        }

        Effect base = grant == null ? defaultEffect : grant.effect();
        String baseId = grant == null ? DEFAULT_POLICY_ID : grant.id();
        if (constraint != null && constraint.effect().compareTo(base) > 0) {
            return new Result(constraint.effect(), constraint.id(), grant == null);
        }
        return new Result(base, baseId, grant == null);
    }
}

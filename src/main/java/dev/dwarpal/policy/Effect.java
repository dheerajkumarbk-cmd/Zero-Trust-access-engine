package dev.dwarpal.policy;

import dev.dwarpal.decision.Outcome;

/**
 * What a matching policy demands. Effects come in two kinds:
 * <ul>
 *   <li><b>Grants</b> (PERMIT, PERMIT_LIMITED) authorise access. Without at least one matching
 *       grant, the policy set's default effect applies.</li>
 *   <li><b>Constraints</b> (REQUIRE_STEP_UP, DENY) only tighten. A constraint on its own never
 *       authorises anything: "restricted data needs MFA" must not mean "anyone who passes MFA
 *       may read restricted data".</li>
 * </ul>
 * Each effect is also a floor: the risk engine may make the outcome stricter, never looser.
 */
public enum Effect {
    PERMIT(Outcome.ALLOW, true),
    PERMIT_LIMITED(Outcome.ALLOW_LIMITED, true),
    REQUIRE_STEP_UP(Outcome.STEP_UP, false),
    DENY(Outcome.DENY, false);

    private final Outcome floor;
    private final boolean grants;

    Effect(Outcome floor, boolean grants) {
        this.floor = floor;
        this.grants = grants;
    }

    public Outcome floor() {
        return floor;
    }

    public boolean grants() {
        return grants;
    }
}

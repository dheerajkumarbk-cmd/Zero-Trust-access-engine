package dev.dwarpal.policy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Static checks on a policy set before it can be deployed (requirement FR-05).
 *
 * <p>Conflict detection here is structural: two policies conflict when their conditions are
 * identical (same canonical description) but their effects differ. Full semantic overlap
 * ("can any request match both?") is an SMT problem, as solved by Margrave (ICSE 2005) and
 * Cedar (OOPSLA 2024); Dwarpal covers the semantic side empirically with What-If replay.
 */
public final class PolicyLinter {

    public enum Severity { ERROR, WARNING }

    public record Finding(Severity severity, String policyId, String message) {
        @Override
        public String toString() {
            return severity + " " + policyId + ": " + message;
        }
    }

    public List<Finding> lint(PolicySet set) {
        List<Finding> out = new ArrayList<>();

        if (set.defaultEffect() != Effect.DENY) {
            out.add(new Finding(Severity.WARNING, PolicySet.DEFAULT_POLICY_ID,
                    "default effect is " + set.defaultEffect() + "; unmatched requests are not denied (fail-open)"));
            if (set.policies().isEmpty()) {
                out.add(new Finding(Severity.WARNING, PolicySet.DEFAULT_POLICY_ID,
                        "no policies: every request gets the default effect " + set.defaultEffect()));
            }
        }

        Set<String> seenIds = new HashSet<>();
        Map<String, Policy> byCondition = new HashMap<>();
        boolean catchAllSeen = false;
        Policy firstLooser = null;

        for (Policy p : set.policies()) {
            if (!seenIds.add(p.id())) {
                out.add(new Finding(Severity.ERROR, p.id(), "duplicate policy id"));
            }

            boolean catchAll = p.when() instanceof Conditions.Always;
            if (set.algorithm() == CombiningAlgorithm.FIRST_APPLICABLE) {
                if (catchAllSeen) {
                    out.add(new Finding(Severity.ERROR, p.id(), "unreachable: an earlier catch-all policy always matches first"));
                } else if (firstLooser != null && p.effect().compareTo(firstLooser.effect()) > 0) {
                    // Order-dependent bypass: a request matching both gets the earlier, looser effect.
                    out.add(new Finding(Severity.WARNING, p.id(), "stricter effect " + p.effect()
                            + " can be shadowed by earlier " + firstLooser.id() + " (" + firstLooser.effect()
                            + "); place restrictive policies first or use DENY_OVERRIDES"));
                }
                if (firstLooser == null || p.effect().compareTo(firstLooser.effect()) < 0) {
                    firstLooser = p;
                }
            }
            if (set.algorithm() == CombiningAlgorithm.DENY_OVERRIDES && catchAll && p.effect() == Effect.DENY
                    && set.policies().size() > 1) {
                out.add(new Finding(Severity.ERROR, p.id(), "catch-all DENY under DENY_OVERRIDES makes every other policy dead"));
            }
            catchAllSeen |= catchAll;

            String key = p.when().describe();
            Policy earlier = byCondition.putIfAbsent(key, p);
            if (earlier != null) {
                if (earlier.effect() != p.effect()) {
                    out.add(new Finding(Severity.ERROR, p.id(), "conflicts with " + earlier.id()
                            + ": identical condition, effect " + p.effect() + " vs " + earlier.effect()));
                } else {
                    out.add(new Finding(Severity.WARNING, p.id(), "redundant: same condition and effect as " + earlier.id()));
                }
            }
        }
        return out;
    }
}

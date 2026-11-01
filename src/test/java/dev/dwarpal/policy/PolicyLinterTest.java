package dev.dwarpal.policy;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyLinterTest {

    private final PolicyLinter linter = new PolicyLinter();

    private static Policy p(String id, Condition c, Effect e) {
        return new Policy(id, "", c, e);
    }

    private static boolean has(List<PolicyLinter.Finding> f, PolicyLinter.Severity s, String text) {
        return f.stream().anyMatch(x -> x.severity() == s && x.message().contains(text));
    }

    @Test
    void warnsOnFailOpenDefaultAndEmptySet() {
        var f = linter.lint(new PolicySet("v1", CombiningAlgorithm.DENY_OVERRIDES, Effect.PERMIT, List.of()));
        assertTrue(has(f, PolicyLinter.Severity.WARNING, "fail-open"));
        assertTrue(has(f, PolicyLinter.Severity.WARNING, "no policies"));
    }

    @Test
    void duplicateIdIsAnError() {
        var c = new Conditions.RoleIn(Set.of("a"));
        var f = linter.lint(new PolicySet("v1", CombiningAlgorithm.DENY_OVERRIDES, Effect.DENY,
                List.of(p("X", c, Effect.PERMIT), p("X", new Conditions.RoleIn(Set.of("b")), Effect.PERMIT))));
        assertTrue(has(f, PolicyLinter.Severity.ERROR, "duplicate"));
    }

    @Test
    void sameConditionWrittenInDifferentOrderIsStillDetected() {
        var c1 = new Conditions.AllOf(List.of(new Conditions.RoleIn(Set.of("a")), new Conditions.DeviceManaged(true)));
        var c2 = new Conditions.AllOf(List.of(new Conditions.DeviceManaged(true), new Conditions.RoleIn(Set.of("a"))));
        var conflict = linter.lint(new PolicySet("v1", CombiningAlgorithm.DENY_OVERRIDES, Effect.DENY,
                List.of(p("A", c1, Effect.PERMIT), p("B", c2, Effect.DENY))));
        assertTrue(has(conflict, PolicyLinter.Severity.ERROR, "conflicts with A"));

        var redundant = linter.lint(new PolicySet("v1", CombiningAlgorithm.DENY_OVERRIDES, Effect.DENY,
                List.of(p("A", c1, Effect.PERMIT), p("B", c2, Effect.PERMIT))));
        assertTrue(has(redundant, PolicyLinter.Severity.WARNING, "redundant"));
    }

    @Test
    void policiesAfterACatchAllAreUnreachableUnderFirstApplicable() {
        var f = linter.lint(new PolicySet("v1", CombiningAlgorithm.FIRST_APPLICABLE, Effect.DENY,
                List.of(p("ALL", new Conditions.Always(), Effect.PERMIT),
                        p("LATER", new Conditions.RoleIn(Set.of("x")), Effect.DENY))));
        assertTrue(has(f, PolicyLinter.Severity.ERROR, "unreachable"));
    }

    @Test
    void catchAllDenyUnderDenyOverridesKillsEverything() {
        var f = linter.lint(new PolicySet("v1", CombiningAlgorithm.DENY_OVERRIDES, Effect.DENY,
                List.of(p("OK", new Conditions.RoleIn(Set.of("x")), Effect.PERMIT),
                        p("ALL", new Conditions.Always(), Effect.DENY))));
        assertTrue(has(f, PolicyLinter.Severity.ERROR, "dead"));
    }
}

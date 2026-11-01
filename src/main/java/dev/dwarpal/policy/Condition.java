package dev.dwarpal.policy;

/**
 * A boolean test over the evaluation context (Specification pattern). Conditions compose into
 * trees through {@link Conditions.AllOf}, {@link Conditions.AnyOf} and {@link Conditions.Not}
 * (Composite pattern).
 */
public interface Condition {

    boolean matches(EvaluationContext context);

    /**
     * Canonical, human-readable form. Two conditions with the same description are logically
     * identical; the linter relies on this to find conflicting and shadowed policies.
     */
    String describe();
}

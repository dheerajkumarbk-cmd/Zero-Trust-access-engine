package dev.dwarpal.policy;

import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.domain.SubjectType;
import dev.dwarpal.domain.Validate;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

/**
 * The fixed vocabulary of policy conditions. Keeping the vocabulary closed (no expressions,
 * no scripting) is a security decision: a policy file can only describe, never execute
 * (stress-test weakness W14).
 */
public final class Conditions {

    private Conditions() {
    }

    // ---- composites -------------------------------------------------------------------------

    public record AllOf(List<Condition> parts) implements Condition {
        public AllOf {
            parts = nonEmpty(parts, "all");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return parts.stream().allMatch(p -> p.matches(c));
        }

        @Override
        public String describe() {
            return "all(" + sortedDescriptions(parts) + ")";
        }
    }

    public record AnyOf(List<Condition> parts) implements Condition {
        public AnyOf {
            parts = nonEmpty(parts, "any");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return parts.stream().anyMatch(p -> p.matches(c));
        }

        @Override
        public String describe() {
            return "any(" + sortedDescriptions(parts) + ")";
        }
    }

    public record Not(Condition inner) implements Condition {
        public Not {
            Objects.requireNonNull(inner, "not");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return !inner.matches(c);
        }

        @Override
        public String describe() {
            return "not(" + inner.describe() + ")";
        }
    }

    /** Matches every request. Used for catch-all policies. */
    public record Always() implements Condition {
        @Override
        public boolean matches(EvaluationContext c) {
            return true;
        }

        @Override
        public String describe() {
            return "always";
        }
    }

    // ---- subject ----------------------------------------------------------------------------

    public record RoleIn(Set<String> roles) implements Condition {
        public RoleIn {
            roles = validLabels(roles, "roleIn");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return c.request().subject().hasAnyRole(roles);
        }

        @Override
        public String describe() {
            return "roleIn" + new TreeSet<>(roles);
        }
    }

    public record DepartmentIn(Set<String> departments) implements Condition {
        public DepartmentIn {
            departments = validLabels(departments, "departmentIn");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return departments.contains(c.request().subject().department());
        }

        @Override
        public String describe() {
            return "departmentIn" + new TreeSet<>(departments);
        }
    }

    public record SubjectTypeIs(SubjectType type) implements Condition {
        public SubjectTypeIs {
            Objects.requireNonNull(type, "subjectType");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return c.request().subject().type() == type;
        }

        @Override
        public String describe() {
            return "subjectType=" + type;
        }
    }

    // ---- resource & action ------------------------------------------------------------------

    public record ResourceKindIs(ResourceKind kind) implements Condition {
        public ResourceKindIs {
            Objects.requireNonNull(kind, "resourceKind");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return c.request().resource().kind() == kind;
        }

        @Override
        public String describe() {
            return "resourceKind=" + kind;
        }
    }

    public record ResourceIdIn(Set<String> ids) implements Condition {
        public ResourceIdIn {
            ids = validIds(ids, "resourceIdIn");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return ids.contains(c.request().resource().id());
        }

        @Override
        public String describe() {
            return "resourceIdIn" + new TreeSet<>(ids);
        }
    }

    public record ClassificationAtLeast(DataClassification level) implements Condition {
        public ClassificationAtLeast {
            Objects.requireNonNull(level, "classificationAtLeast");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return c.request().resource().classification().atLeast(level);
        }

        @Override
        public String describe() {
            return "classification>=" + level;
        }
    }

    public record ClassificationAtMost(DataClassification level) implements Condition {
        public ClassificationAtMost {
            Objects.requireNonNull(level, "classificationAtMost");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return c.request().resource().classification().atMost(level);
        }

        @Override
        public String describe() {
            return "classification<=" + level;
        }
    }

    public record ActionIn(Set<Action> actions) implements Condition {
        public ActionIn {
            actions = Set.copyOf(actions);
            if (actions.isEmpty()) {
                throw new IllegalArgumentException("actionIn must not be empty");
            }
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return actions.contains(c.request().action());
        }

        @Override
        public String describe() {
            return "actionIn" + new TreeSet<>(actions);
        }
    }

    // ---- device -----------------------------------------------------------------------------

    public record DeviceManaged(boolean expected) implements Condition {
        @Override
        public boolean matches(EvaluationContext c) {
            return c.request().device().managed() == expected;
        }

        @Override
        public String describe() {
            return "deviceManaged=" + expected;
        }
    }

    /**
     * Device is healthy AND the health claim is backed by at least the given assurance level.
     * A self-reported "healthy" does not satisfy a policy that asks for AGENT_SIGNED (W5).
     */
    public record DeviceHealthyWithAssurance(AssuranceLevel minimum) implements Condition {
        public DeviceHealthyWithAssurance {
            Objects.requireNonNull(minimum, "deviceHealthyWithAssurance");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            var posture = c.request().device().posture();
            return posture.healthy() && posture.assurance().atLeast(minimum);
        }

        @Override
        public String describe() {
            return "deviceHealthy[assurance>=" + minimum + "]";
        }
    }

    // ---- network & risk ---------------------------------------------------------------------

    public record CountryIn(Set<String> countries) implements Condition {
        public CountryIn {
            countries = validCountries(countries, "countryIn");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return countries.contains(c.request().network().country());
        }

        @Override
        public String describe() {
            return "countryIn" + new TreeSet<>(countries);
        }
    }

    /** SASE point of presence that enforced the request. */
    public record RegionIn(Set<String> regions) implements Condition {
        public RegionIn {
            regions = validLabels(regions, "regionIn");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return regions.contains(c.request().pepRegion());
        }

        @Override
        public String describe() {
            return "regionIn" + new TreeSet<>(regions);
        }
    }

    /** P(attack | evidence) strictly above a threshold. */
    public record RiskAbove(double threshold) implements Condition {
        public RiskAbove {
            Validate.probability(threshold, "riskAbove");
        }

        @Override
        public boolean matches(EvaluationContext c) {
            return c.posteriorAttack() > threshold;
        }

        @Override
        public String describe() {
            return "risk>" + threshold;
        }
    }

    // ---- helpers ----------------------------------------------------------------------------

    private static List<Condition> nonEmpty(List<Condition> parts, String name) {
        List<Condition> copy = List.copyOf(parts);
        if (copy.isEmpty()) {
            throw new IllegalArgumentException(name + " needs at least one condition");
        }
        return copy;
    }

    private static Set<String> validIds(Set<String> values, String name) {
        return canonical(values, name, v -> Validate.id(v, name));
    }

    /** Same canonical form as {@link dev.dwarpal.domain.Subject}: "Contractor" == "contractor". */
    private static Set<String> validLabels(Set<String> values, String name) {
        return canonical(values, name, v -> Validate.label(v, name));
    }

    private static Set<String> validCountries(Set<String> values, String name) {
        return canonical(values, name, v -> Validate.country(v, name));
    }

    private static Set<String> canonical(Set<String> values, String name, UnaryOperator<String> canon) {
        Set<String> copy = values.stream().map(canon).collect(Collectors.toUnmodifiableSet());
        if (copy.isEmpty()) {
            throw new IllegalArgumentException(name + " must not be empty");
        }
        return copy;
    }

    private static String sortedDescriptions(List<Condition> parts) {
        return parts.stream().map(Condition::describe).sorted().collect(Collectors.joining(","));
    }
}

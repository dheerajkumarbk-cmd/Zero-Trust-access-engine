package dev.dwarpal.policy;

import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.domain.SubjectType;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.error.MarkedYAMLException;
import org.yaml.snakeyaml.error.YAMLException;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Loads policy files from YAML, defensively.
 *
 * <p>The policy file is an attack surface: whoever can change it controls access. Defences:
 * <ul>
 *   <li><b>No object construction.</b> {@link SafeConstructor} only builds maps, lists and
 *       scalars. This blocks CVE-2022-1471, where a tag such as
 *       {@code !!javax.script.ScriptEngineManager} made SnakeYAML instantiate arbitrary classes
 *       and led to remote code execution.</li>
 *   <li><b>No aliases.</b> Stops "billion laughs" alias-expansion denial of service.</li>
 *   <li><b>No duplicate keys.</b> Prevents a second {@code effect:} silently overriding the first
 *       one during review.</li>
 *   <li><b>Size, nesting and node limits.</b> Bounded memory and CPU per load.</li>
 *   <li><b>Strict schema.</b> Unknown keys are errors, not ignored, so a typo like
 *       {@code efect: DENY} cannot quietly turn a deny rule into nothing.</li>
 *   <li><b>Lint gate.</b> A file with linter ERRORs is rejected as a whole.</li>
 * </ul>
 */
public final class SafePolicyLoader {

    public static final int MAX_BYTES = 256 * 1024;
    public static final int MAX_CONDITION_DEPTH = 16;
    public static final int MAX_CONDITION_NODES = 10_000;
    public static final int MAX_POLICIES = 1_000;

    private static final Set<String> ROOT_KEYS = Set.of("version", "algorithm", "default", "policies");
    private static final Set<String> POLICY_KEYS = Set.of("id", "description", "when", "effect");

    private final PolicyLinter linter = new PolicyLinter();
    private final boolean failOnWarnings;

    /** Strict by default: linter warnings block deployment too. */
    public SafePolicyLoader() {
        this(true);
    }

    /** {@code failOnWarnings=false} is for tooling that shows warnings to an author, never for deployment. */
    public SafePolicyLoader(boolean failOnWarnings) {
        this.failOnWarnings = failOnWarnings;
    }

    public PolicySet load(String yamlText) {
        // Cheap check first (UTF-8 never uses fewer bytes than chars), then the exact one.
        if (yamlText.length() > MAX_BYTES || yamlText.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            throw new PolicyLoadException("policy file exceeds " + MAX_BYTES + " bytes");
        }
        Object root;
        try {
            root = newYaml().load(yamlText);
        } catch (YAMLException e) {
            // Parser messages quote file content, so neither the message nor the exception (whose
            // stack trace would print it) is propagated. Only the position is kept.
            String where = e instanceof MarkedYAMLException m && m.getProblemMark() != null
                    ? " at line " + (m.getProblemMark().getLine() + 1) + ", column " + (m.getProblemMark().getColumn() + 1)
                    : "";
            throw new PolicyLoadException("policy file is not valid safe YAML (" + e.getClass().getSimpleName() + ")" + where);
        }
        PolicySet set = compileRoot(root);
        List<PolicyLinter.Finding> blocking = linter.lint(set).stream()
                .filter(f -> failOnWarnings || f.severity() == PolicyLinter.Severity.ERROR)
                .toList();
        if (!blocking.isEmpty()) {
            throw new PolicyLoadException("policy set rejected by linter: " + blocking);
        }
        return set;
    }

    private static Yaml newYaml() {
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        options.setMaxAliasesForCollections(0);
        options.setAllowRecursiveKeys(false);
        options.setNestingDepthLimit(2 * MAX_CONDITION_DEPTH + 8);
        options.setCodePointLimit(MAX_BYTES);
        return new Yaml(new SafeConstructor(options));
    }

    // ---- root & policies --------------------------------------------------------------------

    private PolicySet compileRoot(Object root) {
        Map<?, ?> map = asMap(root, "<root>");
        requireOnlyKeys(map, ROOT_KEYS, "<root>");
        String version = asString(require(map, "version", "<root>"), "version");
        CombiningAlgorithm algorithm = asEnum(CombiningAlgorithm.class, require(map, "algorithm", "<root>"), "algorithm");
        Effect defaultEffect = asEnum(Effect.class, require(map, "default", "<root>"), "default");
        List<?> rawPolicies = asList(require(map, "policies", "<root>"), "policies");
        if (rawPolicies.size() > MAX_POLICIES) {
            throw new PolicyLoadException("more than " + MAX_POLICIES + " policies");
        }
        Counter nodes = new Counter();
        List<Policy> policies = new ArrayList<>(rawPolicies.size());
        for (int i = 0; i < rawPolicies.size(); i++) {
            policies.add(compilePolicy(rawPolicies.get(i), "policies[" + i + "]", nodes));
        }
        try {
            return new PolicySet(version, algorithm, defaultEffect, policies);
        } catch (IllegalArgumentException e) {
            throw new PolicyLoadException("invalid policy set: " + e.getMessage(), e);
        }
    }

    private Policy compilePolicy(Object raw, String path, Counter nodes) {
        Map<?, ?> map = asMap(raw, path);
        requireOnlyKeys(map, POLICY_KEYS, path);
        String id = asString(require(map, "id", path), path + ".id");
        Object rawDescription = map.get("description");
        String description = rawDescription == null ? "" : asString(rawDescription, path + ".description");
        Condition when = compileCondition(require(map, "when", path), path + ".when", 1, nodes);
        Effect effect = asEnum(Effect.class, require(map, "effect", path), path + ".effect");
        try {
            return new Policy(id, description, when, effect);
        } catch (IllegalArgumentException e) {
            throw new PolicyLoadException(path + ": " + e.getMessage(), e);
        }
    }

    // ---- conditions -------------------------------------------------------------------------

    private Condition compileCondition(Object raw, String path, int depth, Counter nodes) {
        if (depth > MAX_CONDITION_DEPTH) {
            throw new PolicyLoadException(path + ": conditions nested deeper than " + MAX_CONDITION_DEPTH);
        }
        if (nodes.increment() > MAX_CONDITION_NODES) {
            throw new PolicyLoadException("more than " + MAX_CONDITION_NODES + " condition nodes");
        }
        Map<?, ?> map = asMap(raw, path);
        if (map.size() != 1) {
            throw new PolicyLoadException(path + ": a condition must have exactly one key, got " + map.keySet());
        }
        Map.Entry<?, ?> entry = map.entrySet().iterator().next();
        String key = String.valueOf(entry.getKey());
        Object value = entry.getValue();
        String at = path + "." + key;
        try {
            return switch (key) {
                case "all" -> new Conditions.AllOf(compileList(value, at, depth, nodes));
                case "any" -> new Conditions.AnyOf(compileList(value, at, depth, nodes));
                case "not" -> new Conditions.Not(compileCondition(value, at, depth + 1, nodes));
                case "always" -> {
                    if (!Boolean.TRUE.equals(value)) {
                        throw new PolicyLoadException(at + ": only 'always: true' is allowed");
                    }
                    yield new Conditions.Always();
                }
                case "roleIn" -> new Conditions.RoleIn(asStringSet(value, at));
                case "departmentIn" -> new Conditions.DepartmentIn(asStringSet(value, at));
                case "countryIn" -> new Conditions.CountryIn(asStringSet(value, at));
                case "regionIn" -> new Conditions.RegionIn(asStringSet(value, at));
                case "resourceIdIn" -> new Conditions.ResourceIdIn(asStringSet(value, at));
                case "subjectType" -> new Conditions.SubjectTypeIs(asEnum(SubjectType.class, value, at));
                case "resourceKind" -> new Conditions.ResourceKindIs(asEnum(ResourceKind.class, value, at));
                case "classificationAtLeast" ->
                        new Conditions.ClassificationAtLeast(asEnum(DataClassification.class, value, at));
                case "classificationAtMost" ->
                        new Conditions.ClassificationAtMost(asEnum(DataClassification.class, value, at));
                case "deviceHealthyWithAssurance" ->
                        new Conditions.DeviceHealthyWithAssurance(asEnum(AssuranceLevel.class, value, at));
                case "actionIn" -> new Conditions.ActionIn(asStringSet(value, at).stream()
                        .map(s -> asEnum(Action.class, s, at))
                        .collect(Collectors.toSet()));
                case "deviceManaged" -> new Conditions.DeviceManaged(asBoolean(value, at));
                case "riskAbove" -> new Conditions.RiskAbove(asNumber(value, at));
                default -> throw new PolicyLoadException(path + ": unknown condition '" + key + "'");
            };
        } catch (IllegalArgumentException e) {
            throw new PolicyLoadException(at + ": " + e.getMessage(), e);
        }
    }

    private List<Condition> compileList(Object value, String path, int depth, Counter nodes) {
        List<?> list = asList(value, path);
        List<Condition> out = new ArrayList<>(list.size());
        for (int i = 0; i < list.size(); i++) {
            out.add(compileCondition(list.get(i), path + "[" + i + "]", depth + 1, nodes));
        }
        return out;
    }

    // ---- strict typed accessors -------------------------------------------------------------

    private static Object require(Map<?, ?> map, String key, String path) {
        Object v = map.get(key);
        if (v == null) {
            throw new PolicyLoadException(path + ": missing required key '" + key + "'");
        }
        return v;
    }

    private static void requireOnlyKeys(Map<?, ?> map, Set<String> allowed, String path) {
        for (Object k : map.keySet()) {
            if (!allowed.contains(String.valueOf(k))) {
                throw new PolicyLoadException(path + ": unknown key '" + k + "' (allowed: " + allowed + ")");
            }
        }
    }

    private static Map<?, ?> asMap(Object v, String path) {
        if (v instanceof Map<?, ?> m) {
            return m;
        }
        throw new PolicyLoadException(path + ": expected a mapping");
    }

    private static List<?> asList(Object v, String path) {
        if (v instanceof List<?> l) {
            return l;
        }
        throw new PolicyLoadException(path + ": expected a list");
    }

    private static String asString(Object v, String path) {
        if (v instanceof String s) {
            return s;
        }
        throw new PolicyLoadException(path + ": expected a quoted string");
    }

    private static boolean asBoolean(Object v, String path) {
        if (v instanceof Boolean b) {
            return b;
        }
        throw new PolicyLoadException(path + ": expected true or false");
    }

    private static double asNumber(Object v, String path) {
        if (v instanceof Number n) {
            return n.doubleValue();
        }
        throw new PolicyLoadException(path + ": expected a number");
    }

    private static Set<String> asStringSet(Object v, String path) {
        List<?> list = asList(v, path);
        Set<String> out = new LinkedHashSet<>();
        for (Object item : list) {
            out.add(asString(item, path));
        }
        return out;
    }

    private static <E extends Enum<E>> E asEnum(Class<E> type, Object v, String path) {
        String s = asString(v, path);
        try {
            return Enum.valueOf(type, s);
        } catch (IllegalArgumentException e) {
            throw new PolicyLoadException(path + ": '" + s + "' is not one of "
                    + Arrays.toString(type.getEnumConstants()), e);
        }
    }

    private static final class Counter {
        private int value;

        int increment() {
            return ++value;
        }
    }
}

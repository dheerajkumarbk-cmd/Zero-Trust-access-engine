package dev.dwarpal.siem.platform;

import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.SecurityEvents;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Technique;
import dev.dwarpal.soc.Techniques;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.error.MarkedYAMLException;
import org.yaml.snakeyaml.error.YAMLException;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Correlation rules as data: a safe-YAML file that analysts write and change without Java, compiled into
 * {@link Rule}s and linted before anything runs. Each rule has an id, a title, a severity, at least one MITRE
 * ATT&amp;CK technique (from {@link Techniques}; a rule file cannot invent ids) and exactly one of:
 *
 * <pre>
 * match:     "&lt;query&gt;"                                   every matching event raises an alert
 * threshold: { where, by, within, count }                 count matching events per key within a sliding window
 *            { where, by, within, distinct: f, count }   ... or distinct values of a field
 *            { where, by, within, sum: f, atLeast }      ... or the sum of a numeric field
 * sequence:  { by, within, steps: [ { where, min } ] }    steps in time order for one key, within the window,
 *                                                         across sources (min = events the step needs, default 1)
 * absence:   { where, by, within }                        a key that matched once and then nothing for 'within'
 * </pre>
 * {@code where} uses the {@link Query} language; {@code by} is one to three fields (an entity kind such as
 * {@code device} or {@code subject}, or any event field).
 *
 * <p>Loading is defensive like policy loading: SnakeYAML's {@link SafeConstructor} (no objects), no aliases, no
 * duplicate keys, at most {@link #MAX_BYTES}, unknown keys are errors, parser messages (which quote content) are
 * never passed on. The lint blocks a file with any ERROR: unknown techniques, duplicate ids, values out of range,
 * and rules that can never fire (a dataset nobody writes, two different required values for one field, a
 * provenance the dataset can never carry). WARNINGs (broad rules, critical rules fed only by collected
 * evidence) are kept for the author.
 */
public final class RuleBook {

    public static final int MAX_BYTES = 128 * 1024;
    public static final int MAX_RULES = 200;
    public static final int MAX_STEPS = 8;
    public static final int MAX_BY = 3;
    public static final int MAX_TECHNIQUES = 8;
    public static final long MAX_COUNT = 10_000;
    public static final int MAX_STEP_MIN = 1_000;
    public static final Duration MIN_WINDOW = Duration.ofMinutes(1);
    public static final Duration MAX_WINDOW = Duration.ofHours(24);
    public static final Duration MAX_ABSENCE = Duration.ofDays(7);
    public static final String DEFAULT_RESOURCE = "default-rules.yaml";
    /** Part A's rules in the language: not loaded by default (part A's engine runs them), kept as a cross-check. */
    public static final String PART_A_RESOURCE = "part-a-equivalents.yaml";

    public enum Kind { MATCH, THRESHOLD, SEQUENCE, ABSENCE }

    public enum Measure { COUNT, DISTINCT, SUM }

    public enum Level { ERROR, WARNING }

    /** One lint finding; messages hold rule ids and our own words, never file content. */
    public record Finding(Level level, String rule, String message) {
        @Override
        public String toString() {
            return level + " " + rule + ": " + message;
        }
    }

    /** One step of a sequence. */
    public record Step(Query where, int min) {
        public Step {
            Objects.requireNonNull(where, "where");
        }
    }

    /**
     * A compiled rule.
     *
     * @param where   the events it looks at (match, threshold, absence); {@link Query#all()} for a sequence
     * @param measure what a threshold counts
     * @param field   the field a distinct count or sum is over, empty otherwise
     * @param amount  the count, distinct count or sum that fires a threshold
     */
    public record Rule(String id, String title, Severity severity, List<Technique> techniques, Kind kind, Query where,
                       List<String> by, Duration within, Measure measure, String field, double amount,
                       List<Step> steps) {
        public Rule {
            techniques = List.copyOf(techniques);
            by = List.copyOf(by);
            steps = List.copyOf(steps);
        }
    }

    /** The file was refused: parse errors or lint ERRORs, listed. */
    public static final class RuleLoadException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        private final transient List<Finding> findings;

        RuleLoadException(String message, List<Finding> findings) {
            super(message);
            this.findings = List.copyOf(findings);
        }

        public List<Finding> findings() {
            return findings;
        }
    }

    private static final Set<String> ROOT_KEYS = Set.of("version", "rules");
    private static final Set<String> RULE_KEYS = Set.of("id", "title", "severity", "techniques", "match",
            "threshold", "sequence", "absence");
    private static final Set<String> THRESHOLD_KEYS = Set.of("where", "by", "within", "count", "distinct", "sum",
            "atLeast");
    private static final Set<String> SEQUENCE_KEYS = Set.of("by", "within", "steps");
    private static final Set<String> STEP_KEYS = Set.of("where", "min");
    private static final Set<String> ABSENCE_KEYS = Set.of("where", "by", "within");
    private static final Set<String> SINGLE_VALUED = Set.of("id", "dataset", "category", "action", "outcome",
            "provenance");

    private final List<Rule> rules;
    private final Map<String, Rule> byId;
    private final List<Finding> warnings;

    private RuleBook(List<Rule> rules, List<Finding> warnings) {
        this.rules = List.copyOf(rules);
        Map<String, Rule> m = new LinkedHashMap<>();
        rules.forEach(r -> m.put(r.id(), r));
        this.byId = Map.copyOf(m);
        this.warnings = List.copyOf(warnings);
    }

    public List<Rule> rules() {
        return rules;
    }

    public Optional<Rule> rule(String id) {
        return Optional.ofNullable(byId.get(id));
    }

    /** The MITRE techniques of a rule (for ranking and coverage: alerts themselves carry only the rule id). */
    public List<Technique> techniques(String ruleId) {
        Rule r = byId.get(ruleId);
        return r == null ? List.of() : r.techniques();
    }

    /** Lint warnings of the loaded file. */
    public List<Finding> warnings() {
        return warnings;
    }

    /**
     * The rules shipped with Dwarpal ({@value #DEFAULT_RESOURCE}): the cross-source rules for the stolen laptop,
     * beaconing and cloud exfiltration, and the health rules of the collectors. Part A's rules are not repeated:
     * part A's {@code DetectionEngine} runs them.
     *
     * @param datasets each dataset collectors write and the most trusted provenance it can carry
     */
    public static RuleBook defaults(Map<String, SecurityEvent.Provenance> datasets) {
        return resource(DEFAULT_RESOURCE, datasets);
    }

    /**
     * Part A's rules expressed in the language ({@value #PART_A_RESOURCE}), with their own {@code cr-} ids. Not for
     * production next to part A's engine (two cases for one attack); for demonstrating the language and for
     * checking that both engines agree on the same trail.
     */
    public static RuleBook partAEquivalents(Map<String, SecurityEvent.Provenance> datasets) {
        return resource(PART_A_RESOURCE, datasets);
    }

    private static RuleBook resource(String name, Map<String, SecurityEvent.Provenance> datasets) {
        try (InputStream in = RuleBook.class.getResourceAsStream(name)) {
            if (in == null) {
                throw new IllegalStateException("rule file " + name + " missing from the build");
            }
            byte[] b = in.readNBytes(MAX_BYTES + 1);
            return load(new String(b, StandardCharsets.UTF_8), datasets);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read the rule file " + name, e);
        }
    }

    /**
     * Loads, compiles and lints a rule file.
     *
     * @param datasets each dataset collectors write and the most trusted provenance it can carry; Dwarpal's own
     *                 trail ({@code dwarpal.audit}, {@code VERIFIED_AUDIT}) is always known
     * @throws RuleLoadException listing every problem, if the file is malformed or has lint ERRORs
     */
    public static RuleBook load(String yaml, Map<String, SecurityEvent.Provenance> datasets) {
        Objects.requireNonNull(yaml, "yaml");
        Map<String, SecurityEvent.Provenance> known = new HashMap<>(datasets);
        known.put(SecurityEvents.NATIVE_DATASET, SecurityEvent.Provenance.VERIFIED_AUDIT);
        if (yaml.length() > MAX_BYTES || yaml.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            throw new RuleLoadException("rule file larger than " + MAX_BYTES + " bytes", List.of());
        }
        Object root;
        try {
            root = newYaml().load(yaml);
        } catch (YAMLException e) {
            String where = e instanceof MarkedYAMLException m && m.getProblemMark() != null
                    ? " at line " + (m.getProblemMark().getLine() + 1) + ", column "
                    + (m.getProblemMark().getColumn() + 1) : "";
            throw new RuleLoadException("rule file is not valid safe YAML (" + e.getClass().getSimpleName() + ")"
                    + where, List.of());
        }
        List<Finding> findings = new ArrayList<>();
        List<Rule> rules = new ArrayList<>();
        Set<String> ids = new LinkedHashSet<>();
        try {
            Map<?, ?> map = map(root, "<root>");
            keys(map, ROOT_KEYS, "<root>");
            Object version = map.get("version");
            if (!(version instanceof Integer v) || v != 1) {
                throw new Bad("<root>", "version must be 1");
            }
            List<?> raw = list(map.get("rules"), "<root>", "rules");
            if (raw.isEmpty() || raw.size() > MAX_RULES) {
                throw new Bad("<root>", "1 to " + MAX_RULES + " rules");
            }
            for (int i = 0; i < raw.size(); i++) {
                String where = "rule #" + (i + 1);
                try {
                    Rule r = compile(map(raw.get(i), where), where);
                    if (!ids.add(r.id())) {
                        findings.add(new Finding(Level.ERROR, r.id(), "duplicate rule id"));
                    }
                    rules.add(r);
                    lint(r, known, findings);
                } catch (Bad b) {
                    findings.add(new Finding(Level.ERROR, b.rule, b.getMessage()));
                } catch (QueryException q) {
                    findings.add(new Finding(Level.ERROR, where, "bad query: " + q.getMessage()));
                }
            }
        } catch (Bad b) {
            findings.add(new Finding(Level.ERROR, b.rule, b.getMessage()));
        }
        List<Finding> errors = findings.stream().filter(f -> f.level() == Level.ERROR).toList();
        if (!errors.isEmpty()) {
            throw new RuleLoadException("rule file rejected: " + errors, findings);
        }
        return new RuleBook(rules, findings);
    }

    private static Yaml newYaml() {
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        options.setMaxAliasesForCollections(0);
        options.setAllowRecursiveKeys(false);
        options.setNestingDepthLimit(12);
        options.setCodePointLimit(MAX_BYTES);
        return new Yaml(new SafeConstructor(options));
    }

    // ---- compile --------------------------------------------------------------------------------------------

    /** A problem in one rule; the message is ours. */
    private static final class Bad extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String rule;

        Bad(String rule, String message) {
            super(message, null, false, false);
            this.rule = rule;
        }
    }

    private static Rule compile(Map<?, ?> m, String where) {
        keys(m, RULE_KEYS, where);
        String id = ruleId(m.get("id"), where);
        String title = Sanitize.text(string(m.get("title"), id, "title"), 120);
        if (title.isBlank()) {
            throw new Bad(id, "title must not be empty");
        }
        Severity severity = enumOf(Severity.class, string(m.get("severity"), id, "severity"), id, "severity");
        List<Technique> techniques = techniques(m.get("techniques"), id);
        int kinds = 0;
        for (String k : List.of("match", "threshold", "sequence", "absence")) {
            if (m.containsKey(k)) {
                kinds++;
            }
        }
        if (kinds != 1) {
            throw new Bad(id, "exactly one of match, threshold, sequence, absence");
        }
        if (m.containsKey("match")) {
            return new Rule(id, title, severity, techniques, Kind.MATCH, query(m.get("match"), id, "match"),
                    List.of(), Duration.ZERO, Measure.COUNT, "", 1, List.of());
        }
        if (m.containsKey("threshold")) {
            Map<?, ?> t = map(m.get("threshold"), id);
            keys(t, THRESHOLD_KEYS, id);
            Query q = query(t.get("where"), id, "where");
            List<String> by = by(t.get("by"), id);
            Duration within = duration(t.get("within"), id, MIN_WINDOW, MAX_WINDOW);
            boolean distinct = t.containsKey("distinct");
            boolean sum = t.containsKey("sum");
            if (distinct && sum) {
                throw new Bad(id, "either distinct or sum, not both");
            }
            if (sum) {
                if (t.containsKey("count")) {
                    throw new Bad(id, "a sum fires on atLeast, not count");
                }
                String f = fieldOf(t.get("sum"), id, "sum");
                double atLeast = number(t.get("atLeast"), id, "atLeast");
                if (!(atLeast > 0 && atLeast <= 1e15)) {
                    throw new Bad(id, "atLeast must be above 0 and at most 1e15");
                }
                return new Rule(id, title, severity, techniques, Kind.THRESHOLD, q, by, within, Measure.SUM, f,
                        atLeast, List.of());
            }
            if (t.containsKey("atLeast")) {
                throw new Bad(id, "atLeast goes with sum");
            }
            long count = (long) number(t.get("count"), id, "count");
            if (count < 2 || count > MAX_COUNT) {
                throw new Bad(id, "count must be 2 to " + MAX_COUNT + " (use match for a single event)");
            }
            String f = distinct ? fieldOf(t.get("distinct"), id, "distinct") : "";
            return new Rule(id, title, severity, techniques, Kind.THRESHOLD, q, by, within,
                    distinct ? Measure.DISTINCT : Measure.COUNT, f, count, List.of());
        }
        if (m.containsKey("sequence")) {
            Map<?, ?> s = map(m.get("sequence"), id);
            keys(s, SEQUENCE_KEYS, id);
            List<String> by = by(s.get("by"), id);
            Duration within = duration(s.get("within"), id, MIN_WINDOW, MAX_WINDOW);
            List<?> raw = list(s.get("steps"), id, "steps");
            if (raw.size() < 2 || raw.size() > MAX_STEPS) {
                throw new Bad(id, "a sequence has 2 to " + MAX_STEPS + " steps");
            }
            List<Step> steps = new ArrayList<>();
            for (Object o : raw) {
                Map<?, ?> st = map(o, id);
                keys(st, STEP_KEYS, id);
                int min = st.containsKey("min") ? (int) number(st.get("min"), id, "min") : 1;
                if (min < 1 || min > MAX_STEP_MIN) {
                    throw new Bad(id, "min must be 1 to " + MAX_STEP_MIN);
                }
                steps.add(new Step(query(st.get("where"), id, "where"), min));
            }
            return new Rule(id, title, severity, techniques, Kind.SEQUENCE, Query.all(), by, within, Measure.COUNT,
                    "", 1, steps);
        }
        Map<?, ?> a = map(m.get("absence"), id);
        keys(a, ABSENCE_KEYS, id);
        return new Rule(id, title, severity, techniques, Kind.ABSENCE, query(a.get("where"), id, "where"),
                by(a.get("by"), id), duration(a.get("within"), id, Duration.ofMinutes(5), MAX_ABSENCE),
                Measure.COUNT, "", 1, List.of());
    }

    private static String ruleId(Object o, String where) {
        if (!(o instanceof String s) || s.isEmpty() || s.length() > 64) {
            throw new Bad(where, "id must be a string of 1 to 64 characters");
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && i > 0) || (c == '.' && i > 0);
            if (!ok || (i == 0 && !(c >= 'a' && c <= 'z'))) {
                throw new Bad(where, "id: lower-case letters, digits, '-' and '.', starting with a letter");
            }
        }
        if (s.contains("..")) {
            throw new Bad(where, "id must not contain '..'");
        }
        return s;
    }

    private static List<Technique> techniques(Object o, String id) {
        List<?> raw = list(o, id, "techniques");
        if (raw.isEmpty() || raw.size() > MAX_TECHNIQUES) {
            throw new Bad(id, "1 to " + MAX_TECHNIQUES + " MITRE techniques");
        }
        Set<Technique> out = new LinkedHashSet<>();
        for (Object t : raw) {
            String s = string(t, id, "technique");
            Technique tech = Techniques.byId(s).orElseThrow(() -> new Bad(id,
                    "unknown MITRE technique (not in Techniques): " + Sanitize.text(s, 12)));
            if (!out.add(tech)) {
                throw new Bad(id, "technique listed twice");
            }
        }
        return List.copyOf(out);
    }

    private static List<String> by(Object o, String id) {
        List<?> raw = o instanceof String ? List.of(o) : list(o, id, "by");
        if (raw.isEmpty() || raw.size() > MAX_BY) {
            throw new Bad(id, "by names 1 to " + MAX_BY + " fields");
        }
        Set<String> out = new LinkedHashSet<>();
        for (Object x : raw) {
            if (!out.add(fieldOf(x, id, "by"))) {
                throw new Bad(id, "by names a field twice");
            }
        }
        return List.copyOf(out);
    }

    private static String fieldOf(Object o, String id, String what) {
        String s = string(o, id, what);
        if (!Query.fieldName(s) || s.equals("at")) {
            throw new Bad(id, what + " must be a field name");
        }
        return s;
    }

    private static Query query(Object o, String id, String what) {
        String s = string(o, id, what);
        Query q = Query.parse(s);
        if (!q.countBy().isEmpty()) {
            throw new Bad(id, what + ": 'count by' belongs in searches, not rules");
        }
        return q;
    }

    /** {@code 90s}, {@code 15m}, {@code 2h}, {@code 1d}. */
    static Duration duration(Object o, String id, Duration min, Duration max) {
        String s = string(o, id, "within");
        if (s.length() < 2 || s.length() > 8) {
            throw new Bad(id, "within looks like 90s, 15m, 2h or 1d");
        }
        long n = CollectorBase.count(s.substring(0, s.length() - 1));
        Duration d = switch (s.charAt(s.length() - 1)) {
            case 's' -> n < 0 ? null : Duration.ofSeconds(n);
            case 'm' -> n < 0 ? null : Duration.ofMinutes(n);
            case 'h' -> n < 0 ? null : Duration.ofHours(n);
            case 'd' -> n < 0 ? null : Duration.ofDays(n);
            default -> null;
        };
        if (d == null) {
            throw new Bad(id, "within looks like 90s, 15m, 2h or 1d");
        }
        if (d.compareTo(min) < 0 || d.compareTo(max) > 0) {
            throw new Bad(id, "within must be " + min + " to " + max);
        }
        return d;
    }

    private static double number(Object o, String id, String what) {
        if (!(o instanceof Number n)) {
            throw new Bad(id, what + " must be a number");
        }
        double d = n.doubleValue();
        if (!Double.isFinite(d) || d != Math.rint(d)) {
            throw new Bad(id, what + " must be a whole number");
        }
        return d;
    }

    private static String string(Object o, String id, String what) {
        if (!(o instanceof String s)) {
            throw new Bad(id, what + " must be a string");
        }
        return s;
    }

    private static Map<?, ?> map(Object o, String id) {
        if (!(o instanceof Map<?, ?> m)) {
            throw new Bad(id, "expected a mapping");
        }
        return m;
    }

    private static List<?> list(Object o, String id, String what) {
        if (!(o instanceof List<?> l)) {
            throw new Bad(id, what + " must be a list");
        }
        return l;
    }

    private static void keys(Map<?, ?> m, Set<String> allowed, String id) {
        for (Object k : m.keySet()) {
            if (!(k instanceof String s) || !allowed.contains(s)) {
                throw new Bad(id, "unknown key " + (k instanceof String s ? "'" + Sanitize.text(s, 24) + "'" : ""));
            }
        }
    }

    private static <E extends Enum<E>> E enumOf(Class<E> type, String v, String id, String what) {
        try {
            return Enum.valueOf(type, v);
        } catch (IllegalArgumentException e) {
            throw new Bad(id, "unknown " + what);
        }
    }

    // ---- lint -----------------------------------------------------------------------------------------------

    private static void lint(Rule r, Map<String, SecurityEvent.Provenance> known, List<Finding> out) {
        List<Query> queries = new ArrayList<>();
        if (r.kind() == Kind.SEQUENCE) {
            r.steps().forEach(s -> queries.add(s.where()));
        } else {
            queries.add(r.where());
        }
        boolean collectedOnly = true;
        for (Query q : queries) {
            Set<String> datasets = lintQuery(r, q, known, out);
            if (datasets.isEmpty() || datasets.stream()
                    .anyMatch(d -> known.getOrDefault(d, SecurityEvent.Provenance.COLLECTED).actionable())) {
                collectedOnly = false;
            }
        }
        if (collectedOnly && r.severity() == Severity.CRITICAL) {
            out.add(new Finding(Level.WARNING, r.id(), "CRITICAL but fed only by collected datasets: its alerts "
                    + "are marked collected-only and no destructive playbook may act on them"));
        }
    }

    /** Lints one query; returns the datasets it is restricted to (empty if none). */
    private static Set<String> lintQuery(Rule r, Query q, Map<String, SecurityEvent.Provenance> known,
                                         List<Finding> out) {
        Map<String, Set<String>> required = new HashMap<>();
        for (Query.Cmp c : q.required()) {
            if ((c.op() == Query.Op.EQ || c.op() == Query.Op.IN) && SINGLE_VALUED.contains(c.field())) {
                Set<String> allowed = new LinkedHashSet<>(c.values());
                Set<String> before = required.get(c.field());
                if (before != null) {
                    allowed.retainAll(before);
                    if (allowed.isEmpty()) {
                        out.add(new Finding(Level.ERROR, r.id(), "can never fire: '" + c.field()
                                + "' is required to have two different values"));
                    }
                }
                required.put(c.field(), allowed);
            }
        }
        for (Query.Cmp c : q.comparisons()) {
            if (c.field().equals("dataset") && (c.op() == Query.Op.EQ || c.op() == Query.Op.IN)) {
                for (String d : c.values()) {
                    if (!known.containsKey(d)) {
                        boolean req = required.containsKey("dataset");
                        out.add(new Finding(req ? Level.ERROR : Level.WARNING, r.id(), (req ? "can never fire" : "part "
                                + "can never match") + ": no collector writes dataset '" + Sanitize.text(d, 40) + "'"));
                    }
                }
            }
        }
        Set<String> datasets = required.getOrDefault("dataset", Set.of());
        Set<String> provenance = required.get("provenance");
        if (provenance != null && !datasets.isEmpty()) {
            boolean reachable = false;
            for (String d : datasets) {
                SecurityEvent.Provenance best = known.get(d);
                for (String p : provenance) {
                    SecurityEvent.Provenance want = SecurityEvent.Provenance.valueOf(p);
                    if (best != null && (d.equals(SecurityEvents.NATIVE_DATASET)
                            ? want == SecurityEvent.Provenance.VERIFIED_AUDIT
                            : want != SecurityEvent.Provenance.VERIFIED_AUDIT && want.compareTo(best) >= 0)) {
                        reachable = true;
                    }
                }
            }
            if (!reachable) {
                out.add(new Finding(Level.ERROR, r.id(), "can never fire: the dataset never carries that provenance"));
            }
        }
        if (q.required().stream().noneMatch(c -> c.field().equals("dataset") || c.field().equals("action")
                || c.field().equals("category"))) {
            out.add(new Finding(Level.WARNING, r.id(), "no required dataset, action or category: the rule looks at "
                    + "every event"));
        }
        return datasets;
    }
}

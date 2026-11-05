package dev.dwarpal.soar;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.response.Play;
import dev.dwarpal.response.ResponseSettings;
import dev.dwarpal.soc.Entity;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.error.MarkedYAMLException;
import org.yaml.snakeyaml.error.YAMLException;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Reads playbook files (safe YAML) and compiles them into part B's {@link Play}s, with a linter that refuses
 * anything beyond the guard rails. The file format:
 *
 * <pre>
 * version: "2026-11-05.1"                          # quoted: YAML would read a bare date as a date
 * playbooks:
 *   - rule: honeytoken-touched
 *     description: Someone touched a honeytoken
 *     steps:
 *       - revoke: subject                              # subject, device or session
 *       - deny: {target: ip, for: PT4H}                 # subject, device or ip; ISO-8601 duration
 *       - watch: {target: subject, ratio: 10, halfLife: P1D}   # likelihood ratio above 1, at most 1000
 *       - isolate: device                              # deny + revoke the device, isolate it at its sensor
 *       - notify: {connector: ticket, template: action-taken}
 * default:                                             # for rules the catalogue does not know: watches only
 *   - watch: {target: subject, ratio: 10, halfLife: P1D}
 * </pre>
 *
 * <p>Reading is defensive like the policy loader's: SnakeYAML's {@link SafeConstructor} (no objects, so no
 * CVE-2022-1471), no aliases, no duplicate keys, size and nesting limits, a strict schema (unknown keys are
 * errors). Messages name places, never content.
 *
 * <p>The linter's errors ({@link Finding.Severity#ERROR}) and, in strict mode, warnings block the file:
 * <ul>
 *   <li>a rule the catalogue does not know, or listed twice;</li>
 *   <li>a step beyond the guard rails: a deny longer than the deployment allows, a watch above x1000 or with a
 *       half-life outside 1 minute to 90 days, more than {@link Play#MAX_STEPS} steps, a target the step cannot
 *       act on;</li>
 *   <li>a destructive step (revoke, deny, isolate) for a rule whose evidence can be only collected;</li>
 *   <li>denying or isolating the person a rule names when that person is the one under attack;</li>
 *   <li>a destructive step in the default play (it runs for rules nobody reviewed);</li>
 *   <li>an unknown connector or template, or more than {@link #MAX_NOTIFY} notifications;</li>
 *   <li>anything that looks like a secret (connectors hold their own configuration; files never carry keys);</li>
 *   <li>warnings: a known rule without a playbook (it gets the default), a step listed twice.</li>
 * </ul>
 */
public final class PlaybookCompiler {

    public static final int MAX_BYTES = 64 * 1024;
    public static final String REFERENCE = "/dev/dwarpal/soar/reference-playbooks.yaml";
    public static final int MAX_PLAYBOOKS = 500;
    public static final int MAX_NOTIFY = 4;
    public static final int MAX_DESCRIPTION = 200;
    public static final int MAX_VERSION = 64;
    /** A run of this many key-like characters (letters and digits mixed) is treated as a secret. */
    static final int SECRET_RUN = 32;

    private static final Set<String> ROOT_KEYS = Set.of("version", "playbooks", "default");
    private static final Set<String> PLAYBOOK_KEYS = Set.of("rule", "description", "steps");
    private static final Set<String> STEP_KINDS = Set.of("revoke", "deny", "watch", "isolate", "notify");
    private static final Set<String> SECRET_WORDS = Set.of("password", "passwd", "pwd", "secret", "token", "apikey",
            "api_key", "api-key", "credential", "bearer");

    /** One linter finding: where, and what is wrong (never the offending value). */
    public record Finding(Severity severity, String where, String message) {
        public enum Severity { WARNING, ERROR }

        public Finding {
            Objects.requireNonNull(severity, "severity");
            Objects.requireNonNull(where, "where");
            Objects.requireNonNull(message, "message");
        }

        @Override
        public String toString() {
            return severity + " " + where + ": " + message;
        }
    }

    /** The result: the compiled set if nothing blocked it, and every finding either way. */
    public record Compilation(Optional<PlaybookSet> set, List<Finding> findings) {
        public Compilation {
            Objects.requireNonNull(set, "set");
            findings = List.copyOf(findings);
        }

        public boolean accepted() {
            return set.isPresent();
        }
    }

    private final RuleCatalogue rules;
    private final ResponseSettings settings;
    private final Set<String> connectors;
    private final boolean strict;

    /**
     * @param connectors the connector names the deployment configured
     * @param strict     warnings block too (deployment); false only for authoring tools that show warnings
     */
    public PlaybookCompiler(RuleCatalogue rules, ResponseSettings settings, Set<String> connectors, boolean strict) {
        this.rules = Objects.requireNonNull(rules, "rules");
        this.settings = Objects.requireNonNull(settings, "settings");
        this.connectors = Set.copyOf(connectors);
        this.strict = strict;
    }

    /** Compiles; throws {@link PlaybookException} only when the text cannot be read as a playbook file at all. */
    public Compilation compile(String yamlText) {
        Objects.requireNonNull(yamlText, "yaml");
        if (yamlText.length() > MAX_BYTES || yamlText.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            throw new PlaybookException("playbook file exceeds " + MAX_BYTES + " bytes");
        }
        Object root;
        try {
            root = yaml().load(yamlText);
        } catch (YAMLException e) {
            String where = e instanceof MarkedYAMLException m && m.getProblemMark() != null
                    ? " at line " + (m.getProblemMark().getLine() + 1) + ", column " + (m.getProblemMark().getColumn() + 1)
                    : "";
            throw new PlaybookException("playbook file is not valid safe YAML (" + e.getClass().getSimpleName() + ")"
                    + where);
        }
        List<Finding> findings = new ArrayList<>();
        Map<?, ?> top = map(root, "<root>");
        only(top, ROOT_KEYS, "<root>");
        String version = string(need(top, "version", "<root>"), "version", MAX_VERSION);
        secretCheck(version, "version", findings);
        try {
            Validate.id(version, "version");
        } catch (IllegalArgumentException e) {
            findings.add(error("version", "must be an identifier (letters, digits, . _ : @ / -)"));
        }
        List<?> books = list(need(top, "playbooks", "<root>"), "playbooks");
        if (books.size() > MAX_PLAYBOOKS) {
            throw new PlaybookException("more than " + MAX_PLAYBOOKS + " playbooks");
        }
        Map<String, Play> plays = new LinkedHashMap<>();
        Map<String, PlaybookSet.Extras> extras = new LinkedHashMap<>();
        for (int i = 0; i < books.size(); i++) {
            playbook(books.get(i), "playbooks[" + i + "]", plays, extras, findings);
        }
        Play fallback = Play.of();
        if (top.containsKey("default")) {
            Compiled d = steps(list(top.get("default"), "default"), "default", Optional.empty(), findings);
            if (d.play().steps().stream().anyMatch(Play.Step::destructive) || d.extras().isolate()) {
                findings.add(error("default", "the default play runs for rules nobody reviewed: watches only"));
            }
            if (!d.extras().notifications().isEmpty()) {
                findings.add(error("default", "the default play cannot notify"));
            }
            fallback = new Play(d.play().steps().stream().filter(s -> !s.destructive()).toList());
        }
        for (String known : rules.ids()) {
            if (!plays.containsKey(known)) {
                findings.add(warning("rule " + known, "known rule without a playbook: it gets the default play"));
                plays.put(known, fallback);
            }
        }
        boolean blocked = findings.stream()
                .anyMatch(f -> f.severity() == Finding.Severity.ERROR || strict);
        if (blocked) {
            return new Compilation(Optional.empty(), findings);
        }
        return new Compilation(Optional.of(new PlaybookSet(version, Digests.sha256Hex(yamlText), plays, fallback,
                extras)), findings);
    }

    /** The reference playbooks shipped with Dwarpal (part B's plays as data, plus isolation for honeytokens). */
    public Compilation compileReference() {
        try (java.io.InputStream in = PlaybookCompiler.class.getResourceAsStream(REFERENCE)) {
            if (in == null) {
                throw new PlaybookException("reference playbooks missing from the build");
            }
            return compile(decode(in.readNBytes(MAX_BYTES + 1)));
        } catch (java.io.IOException e) {
            throw new PlaybookException("cannot read the reference playbooks (" + e.getClass().getSimpleName() + ")");
        }
    }

    /** Reads a playbook file: a regular file (never a symbolic link), at most {@link #MAX_BYTES}, strict UTF-8. */
    public Compilation compile(java.nio.file.Path file) {
        if (!java.nio.file.Files.isRegularFile(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new PlaybookException("not a regular file (symbolic links are refused)");
        }
        try (java.io.InputStream in = java.nio.file.Files.newInputStream(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            return compile(decode(in.readNBytes(MAX_BYTES + 1)));
        } catch (java.io.IOException e) {
            throw new PlaybookException("cannot read the playbook file (" + e.getClass().getSimpleName() + ")");
        }
    }

    /** The text of a file read with {@link #compile(java.nio.file.Path)}'s rules, for packaging into a bundle. */
    static String decode(byte[] bytes) {
        if (bytes.length > MAX_BYTES) {
            throw new PlaybookException("playbook file exceeds " + MAX_BYTES + " bytes");
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        } catch (java.nio.charset.CharacterCodingException e) {
            throw new PlaybookException("playbook file is not valid UTF-8");
        }
    }

    // ---- playbooks ------------------------------------------------------------------------------------------

    private record Compiled(Play play, PlaybookSet.Extras extras) {
    }

    private void playbook(Object raw, String path, Map<String, Play> plays, Map<String, PlaybookSet.Extras> extras,
                          List<Finding> findings) {
        Map<?, ?> m = map(raw, path);
        only(m, PLAYBOOK_KEYS, path);
        String rule = string(need(m, "rule", path), path + ".rule", 128);
        secretCheck(rule, path + ".rule", findings);
        if (m.containsKey("description")) {
            String d = string(m.get("description"), path + ".description", MAX_DESCRIPTION);
            secretCheck(d, path + ".description", findings);
        }
        Optional<RuleCatalogue.Rule> info = rules.rule(rule);
        if (info.isEmpty()) {
            findings.add(error(path + ".rule", "unknown rule (not in the deployment's rule catalogue)"));
        }
        if (plays.containsKey(rule)) {
            findings.add(error(path + ".rule", "rule has a playbook already; one playbook per rule"));
            return;
        }
        Compiled c = steps(list(need(m, "steps", path), path + ".steps"), path + ".steps", info, findings);
        if (info.isPresent()) {
            plays.put(rule, c.play());
            if (c.extras().isolate() || !c.extras().notifications().isEmpty()) {
                extras.put(rule, c.extras());
            }
        }
    }

    private Compiled steps(List<?> raw, String path, Optional<RuleCatalogue.Rule> rule, List<Finding> findings) {
        List<Play.Step> steps = new ArrayList<>();
        List<PlaybookSet.Notify> notify = new ArrayList<>();
        boolean isolate = false;
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < raw.size(); i++) {
            String at = path + "[" + i + "]";
            Map<?, ?> m = map(raw.get(i), at);
            if (m.size() != 1) {
                throw new PlaybookException(at + ": a step has exactly one key");
            }
            String kind = String.valueOf(m.keySet().iterator().next());
            if (!STEP_KINDS.contains(kind)) {
                throw new PlaybookException(at + ": unknown step (revoke, deny, watch, isolate or notify)");
            }
            Object value = m.get(kind);
            if (!seen.add(kind + "|" + value)) {
                findings.add(warning(at, "the same step is listed twice"));
                continue;
            }
            switch (kind) {
                case "revoke" -> step(() -> new Play.Revoke(entity(value, at + ".revoke")), at, steps, findings);
                case "deny" -> deny(value, at, steps, findings);
                case "watch" -> watch(value, at, steps, findings);
                case "isolate" -> {
                    if (entity(value, at + ".isolate") != Entity.Kind.DEVICE) {
                        findings.add(error(at, "only a device can be isolated"));
                    } else if (!isolate) {
                        isolate = true;
                        steps.add(new Play.Deny(Entity.Kind.DEVICE, settings.maxDeny()));
                        steps.add(new Play.Revoke(Entity.Kind.DEVICE));
                    }
                }
                default -> notify(value, at, notify, findings);
            }
        }
        if (steps.size() > Play.MAX_STEPS) {
            findings.add(error(path, "more than " + Play.MAX_STEPS + " steps (isolate counts as two)"));
            steps = new ArrayList<>(steps.subList(0, Play.MAX_STEPS));
        }
        if (notify.size() > MAX_NOTIFY) {
            findings.add(error(path, "more than " + MAX_NOTIFY + " notifications"));
        }
        List<Play.Step> compiled = List.copyOf(steps);
        rule.ifPresent(r -> railsForRule(r, path, compiled, findings));
        return new Compiled(new Play(compiled), new PlaybookSet.Extras(isolate, notify));
    }

    /** The rules that depend on the rule's evidence and on whom it names. */
    private static void railsForRule(RuleCatalogue.Rule r, String path, List<Play.Step> steps, List<Finding> findings) {
        if (r.evidence() == RuleCatalogue.Evidence.COLLECTED_ONLY && steps.stream().anyMatch(Play.Step::destructive)) {
            findings.add(error(path, "rule " + r.id() + " rests on collected evidence only (anyone can forge it):"
                    + " watches only, no revoke, deny or isolate"));
        }
        if (r.namesVictim() && steps.stream().anyMatch(s -> s instanceof Play.Deny d
                && (d.target() == Entity.Kind.SUBJECT || d.target() == Entity.Kind.DEVICE))) {
            findings.add(error(path, "rule " + r.id() + " names the person under attack: deny addresses, never"
                    + " the person or their device"));
        }
    }

    private void deny(Object value, String at, List<Play.Step> steps, List<Finding> findings) {
        Map<?, ?> m = map(value, at + ".deny");
        only(m, Set.of("target", "for"), at + ".deny");
        Entity.Kind target = entity(need(m, "target", at + ".deny"), at + ".deny.target");
        Duration d = duration(need(m, "for", at + ".deny"), at + ".deny.for");
        if (d.isNegative() || d.isZero() || d.compareTo(settings.maxDeny()) > 0) {
            findings.add(error(at + ".deny.for", "beyond the guard rails: a deny lasts more than zero and at most "
                    + settings.maxDeny()));
            return;
        }
        step(() -> new Play.Deny(target, d), at, steps, findings);
    }

    private void watch(Object value, String at, List<Play.Step> steps, List<Finding> findings) {
        Map<?, ?> m = map(value, at + ".watch");
        only(m, Set.of("target", "ratio", "halfLife"), at + ".watch");
        Entity.Kind target = entity(need(m, "target", at + ".watch"), at + ".watch.target");
        Object r = need(m, "ratio", at + ".watch");
        if (!(r instanceof Number n) || r instanceof Double dd && !Double.isFinite(dd)) {
            throw new PlaybookException(at + ".watch.ratio: a number was expected");
        }
        double ratio = n.doubleValue();
        Duration half = duration(need(m, "halfLife", at + ".watch"), at + ".watch.halfLife");
        if (!(ratio > 1) || ratio > Math.exp(SignalFeed.MAX_WATCH_LOG_LR) + 1e-9) {
            findings.add(error(at + ".watch.ratio", "beyond the guard rails: a watch multiplies the odds by more than 1"
                    + " and at most 1000"));
            return;
        }
        if (half.compareTo(SignalFeed.MIN_HALF_LIFE) < 0 || half.compareTo(SignalFeed.MAX_HALF_LIFE) > 0) {
            findings.add(error(at + ".watch.halfLife", "beyond the guard rails: 1 minute to 90 days"));
            return;
        }
        double logLr = Math.min(Math.log(ratio), SignalFeed.MAX_WATCH_LOG_LR);
        step(() -> new Play.Watch(target, logLr, half), at, steps, findings);
    }

    private void notify(Object value, String at, List<PlaybookSet.Notify> notify, List<Finding> findings) {
        Map<?, ?> m = map(value, at + ".notify");
        only(m, Set.of("connector", "template"), at + ".notify");
        String c = string(need(m, "connector", at + ".notify"), at + ".notify.connector", 64);
        String t = string(need(m, "template", at + ".notify"), at + ".notify.template", 64);
        secretCheck(c, at + ".notify.connector", findings);
        Optional<PlaybookSet.Template> template = PlaybookSet.Template.of(t);
        if (!connectors.contains(c)) {
            findings.add(error(at + ".notify.connector", "unknown connector"));
            return;
        }
        if (template.isEmpty()) {
            findings.add(error(at + ".notify.template", "unknown template"));
            return;
        }
        notify.add(new PlaybookSet.Notify(c, template.get()));
    }

    private static void step(java.util.function.Supplier<Play.Step> make, String at, List<Play.Step> steps,
                             List<Finding> findings) {
        try {
            steps.add(make.get());
        } catch (IllegalArgumentException e) {
            findings.add(error(at, "beyond the guard rails: this step cannot act on that target"));
        }
    }

    // ---- secrets --------------------------------------------------------------------------------------------

    /** Whether free text looks like it carries a credential: a secret word followed by ':' or '=', or a long key-like run. */
    static boolean looksSecret(String text) {
        String s = text.toLowerCase(Locale.ROOT);
        if (s.contains("private key") || s.contains("-----begin")) {
            return true;
        }
        for (String w : SECRET_WORDS) {
            int from = 0;
            int i;
            while ((i = s.indexOf(w, from)) >= 0) {
                int j = i + w.length();
                while (j < s.length() && s.charAt(j) == ' ') {
                    j++;
                }
                if (j < s.length() && (s.charAt(j) == ':' || s.charAt(j) == '=')) {
                    return true;
                }
                from = i + 1;
            }
        }
        int run = 0;
        boolean letters = false;
        boolean digits = false;
        for (int i = 0; i <= text.length(); i++) {
            char c = i < text.length() ? text.charAt(i) : ' ';
            boolean keyLike = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '+' || c == '/' || c == '=' || c == '_' || c == '-';
            if (keyLike) {
                run++;
                letters |= Character.isLetter(c);
                digits |= Character.isDigit(c);
            } else {
                if (run >= SECRET_RUN && letters && digits) {
                    return true;
                }
                run = 0;
                letters = false;
                digits = false;
            }
        }
        return false;
    }

    private static void secretCheck(String text, String where, List<Finding> findings) {
        if (looksSecret(text)) {
            findings.add(error(where, "looks like a secret: playbook files never carry credentials (connectors hold"
                    + " their own configuration)"));
        }
    }

    // ---- reading helpers -------------------------------------------------------------------------------------

    private static Yaml yaml() {
        LoaderOptions o = new LoaderOptions();
        o.setAllowDuplicateKeys(false);
        o.setMaxAliasesForCollections(0);
        o.setAllowRecursiveKeys(false);
        o.setNestingDepthLimit(12);
        o.setCodePointLimit(MAX_BYTES);
        return new Yaml(new SafeConstructor(o));
    }

    private static Entity.Kind entity(Object v, String path) {
        String s = string(v, path, 16);
        return switch (s) {
            case "subject" -> Entity.Kind.SUBJECT;
            case "device" -> Entity.Kind.DEVICE;
            case "ip" -> Entity.Kind.IP;
            case "session" -> Entity.Kind.SESSION;
            case "resource" -> Entity.Kind.RESOURCE;
            default -> throw new PlaybookException(path + ": a target is subject, device, ip, session or resource");
        };
    }

    private static Duration duration(Object v, String path) {
        String s = string(v, path, 32);
        try {
            return Duration.parse(s);
        } catch (DateTimeParseException e) {
            throw new PlaybookException(path + ": an ISO-8601 duration was expected (for example PT4H or P1D)");
        }
    }

    private static Object need(Map<?, ?> m, String key, String path) {
        Object v = m.get(key);
        if (v == null) {
            throw new PlaybookException(path + ": '" + key + "' is required");
        }
        return v;
    }

    private static void only(Map<?, ?> m, Set<String> allowed, String path) {
        for (Object k : m.keySet()) {
            if (!(k instanceof String s) || !allowed.contains(s)) {
                throw new PlaybookException(path + ": unknown key (allowed: " + new java.util.TreeSet<>(allowed) + ")");
            }
        }
    }

    private static Map<?, ?> map(Object v, String path) {
        if (!(v instanceof Map<?, ?> m)) {
            throw new PlaybookException(path + ": a mapping was expected");
        }
        return m;
    }

    private static List<?> list(Object v, String path) {
        if (!(v instanceof List<?> l)) {
            throw new PlaybookException(path + ": a list was expected");
        }
        return l;
    }

    private static String string(Object v, String path, int max) {
        if (!(v instanceof String s)) {
            throw new PlaybookException(path + ": text was expected");
        }
        if (s.isEmpty() || s.length() > max) {
            throw new PlaybookException(path + ": 1 to " + max + " characters");
        }
        return s;
    }

    private static Finding error(String where, String message) {
        return new Finding(Finding.Severity.ERROR, where, message);
    }

    private static Finding warning(String where, String message) {
        return new Finding(Finding.Severity.WARNING, where, message);
    }
}

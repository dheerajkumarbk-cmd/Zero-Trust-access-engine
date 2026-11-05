package dev.dwarpal.soar;

import dev.dwarpal.response.Play;
import dev.dwarpal.response.ResponseSettings;
import dev.dwarpal.soc.Entity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Playbooks as data: abuse cases first (files that try to get past the guard rails), then what a good file gives. */
class PlaybookCompilerTest {

    private static final RuleCatalogue RULES = RuleCatalogue.partA().with(List.of(
            new RuleCatalogue.Rule("fw-port-scan", RuleCatalogue.Evidence.COLLECTED_ONLY, false),
            new RuleCatalogue.Rule("beacon-correlated", RuleCatalogue.Evidence.MIXED, false)));

    private static PlaybookCompiler lenient() {
        return new PlaybookCompiler(RULES, ResponseSettings.defaults(), Set.of("ticket"), false);
    }

    private static PlaybookCompiler strict() {
        return new PlaybookCompiler(RULES, ResponseSettings.defaults(), Set.of("ticket"), true);
    }

    private static String one(String rule, String... steps) {
        StringBuilder sb = new StringBuilder("version: \"t1\"\nplaybooks:\n  - rule: " + rule + "\n    steps:\n");
        for (String s : steps) {
            sb.append("      - ").append(s).append('\n');
        }
        if (steps.length == 0) {
            sb.setLength(sb.length() - 1);
            sb.append(" []\n");
        }
        return sb.toString();
    }

    private static boolean refusedWith(PlaybookCompiler.Compilation c, String fragment) {
        return !c.accepted() && c.findings().stream().anyMatch(f -> f.severity() == PlaybookCompiler.Finding.Severity.ERROR
                && f.message().contains(fragment));
    }

    // ---- abuse: getting past the guard rails ---------------------------------------------------------------

    @Test
    void aDenyLongerThanTheGuardRailsIsRefused() {
        assertTrue(refusedWith(lenient().compile(one("break-glass-used", "deny: {target: subject, for: P3650D}")),
                "guard rails"));
        assertTrue(refusedWith(lenient().compile(one("break-glass-used", "deny: {target: subject, for: PT-1H}")),
                "guard rails"));
        assertTrue(refusedWith(lenient().compile(one("break-glass-used", "deny: {target: subject, for: PT0S}")),
                "guard rails"));
    }

    @Test
    void aDenyWithinTighterDeploymentRailsIsMeasuredAgainstThem() {
        ResponseSettings tight = new ResponseSettings(Duration.ofDays(1), 20, 10, Duration.ofHours(1), Set.of("admin"),
                Set.of(), Set.of(), 100, 10);
        PlaybookCompiler c = new PlaybookCompiler(RULES, tight, Set.of(), false);
        assertTrue(refusedWith(c.compile(one("break-glass-used", "deny: {target: subject, for: P2D}")), "guard rails"));
        assertTrue(c.compile(one("break-glass-used", "deny: {target: subject, for: P1D}")).accepted());
    }

    @Test
    void watchesBeyondTheRailsAreRefused() {
        for (String w : List.of("{target: subject, ratio: 5000, halfLife: P1D}", "{target: subject, ratio: 1, halfLife: P1D}",
                "{target: subject, ratio: 0.5, halfLife: P1D}",
                "{target: subject, ratio: 99999999999999999999999, halfLife: P1D}",
                "{target: subject, ratio: 10, halfLife: PT1S}", "{target: subject, ratio: 10, halfLife: P365D}")) {
            assertFalse(lenient().compile(one("pam-refused", "watch: " + w)).accepted(), w);
        }
        for (String nonFinite : List.of(".inf", ".nan")) {
            assertThrows(PlaybookException.class, () -> lenient().compile(one("pam-refused",
                    "watch: {target: subject, ratio: " + nonFinite + ", halfLife: P1D}")));
        }
        assertThrows(PlaybookException.class, () -> lenient().compile(one("pam-refused",
                "watch: {target: subject, ratio: ten, halfLife: P1D}")));
    }

    @Test
    void destructiveStepsOnCollectedOnlyEvidenceAreRefused() {
        for (String s : List.of("revoke: subject", "deny: {target: ip, for: PT1H}", "isolate: device")) {
            assertTrue(refusedWith(lenient().compile(one("fw-port-scan", s)), "collected evidence only"), s);
        }
        assertTrue(lenient().compile(one("fw-port-scan", "watch: {target: ip, ratio: 10, halfLife: P1D}")).accepted());
        assertTrue(lenient().compile(one("beacon-correlated", "isolate: device")).accepted(), "mixed: decided per alert");
    }

    @Test
    void thePersonUnderAttackIsNeverDeniedOrIsolated() {
        assertTrue(refusedWith(lenient().compile(one("deny-storm-subject", "deny: {target: subject, for: PT1H}")),
                "under attack"));
        assertTrue(refusedWith(lenient().compile(one("mfa-fatigue", "isolate: device")), "under attack"));
        assertTrue(lenient().compile(one("deny-storm-ip", "deny: {target: ip, for: PT4H}")).accepted());
    }

    @Test
    void unknownAndDuplicateRulesAreRefused() {
        assertTrue(refusedWith(lenient().compile(one("no-such-rule", "revoke: subject")), "unknown rule"));
        // a homoglyph (Cyrillic i) is just another unknown rule
        assertTrue(refusedWith(lenient().compile(one("mfa-fatіgue", "revoke: subject")), "unknown rule"));
        String twice = one("pam-refused") + "  - rule: pam-refused\n    steps: []\n";
        assertTrue(refusedWith(lenient().compile(twice), "one playbook per rule"));
    }

    @Test
    void theDefaultPlayCannotBeDestructiveOrNotify() {
        String base = one("pam-refused");
        assertTrue(refusedWith(lenient().compile(base + "default:\n  - revoke: subject\n"), "watches only"));
        assertTrue(refusedWith(lenient().compile(base + "default:\n  - isolate: device\n"), "watches only"));
        assertTrue(refusedWith(lenient().compile(base + "default:\n  - notify: {connector: ticket, template: action-taken}\n"),
                "cannot notify"));
    }

    @Test
    void stepsThatCannotActOnTheirTargetAreRefused() {
        assertTrue(refusedWith(lenient().compile(one("pam-refused", "revoke: ip")), "cannot act"));
        assertTrue(refusedWith(lenient().compile(one("pam-refused", "deny: {target: session, for: PT1H}")), "cannot act"));
        assertTrue(refusedWith(lenient().compile(one("pam-refused", "isolate: subject")), "only a device"));
        String[] kinds = {"subject", "device", "ip"};
        String[] steps = new String[17];
        for (int i = 0; i < 17; i++) {
            steps[i] = "deny: {target: " + kinds[i % 3] + ", for: PT" + (i + 1) + "H}";
        }
        assertTrue(refusedWith(lenient().compile(one("break-glass-used", steps)), "more than 16"));
    }

    @Test
    void notificationsNeedAKnownConnectorAndTemplate() {
        assertTrue(refusedWith(lenient().compile(one("pam-refused", "notify: {connector: pager, template: action-taken}")),
                "unknown connector"));
        assertTrue(refusedWith(lenient().compile(one("pam-refused", "notify: {connector: ticket, template: free-text}")),
                "unknown template"));
        PlaybookCompiler two = new PlaybookCompiler(RULES, ResponseSettings.defaults(), Set.of("ticket", "chat"), false);
        String[] five = new String[5];
        PlaybookSet.Template[] t = PlaybookSet.Template.values();
        for (int i = 0; i < 5; i++) {
            five[i] = "notify: {connector: " + (i < 3 ? "ticket" : "chat") + ", template: " + t[i % t.length].key() + "}";
        }
        assertTrue(refusedWith(two.compile(one("pam-refused", five)), "more than 4 notifications"));
    }

    @Test
    void secretsInPlaybookFilesAreRefused() {
        // Built at run time so no secret-looking literal sits in the source.
        String word = "pass" + "word";
        String key = "A1b2".repeat(10);
        assertTrue(refusedWith(lenient().compile(one("pam-refused").replace("steps: []",
                "description: \"" + word + "= hunter\"\n    steps: []")), "looks like a secret"));
        assertTrue(refusedWith(lenient().compile(one("pam-refused").replace("steps: []",
                "description: \"use " + key + "\"\n    steps: []")), "looks like a secret"));
        assertTrue(refusedWith(lenient().compile(one("pam-refused").replace("\"t1\"", "\"" + key + "\"")),
                "looks like a secret"));
        assertTrue(PlaybookCompiler.looksSecret("-----BEGIN " + "PRIVATE KEY-----"));
        assertTrue(PlaybookCompiler.looksSecret("the api_key : x"));
        assertFalse(PlaybookCompiler.looksSecret("stolen token revoked; tokens are single use"));
        assertFalse(PlaybookCompiler.looksSecret("abcdefghijklmnopqrstuvwxyzabcdefghij"), "letters only");
    }

    @Test
    void unsafeYamlIsRefusedWithoutEchoingIt() {
        String marker = "MARKER" + "42";
        PlaybookException e = assertThrows(PlaybookException.class,
                () -> lenient().compile("version: [" + marker + "\nplaybooks: {"));
        assertFalse(e.getMessage().contains(marker), "messages name places, not content");
        assertThrows(PlaybookException.class, () -> lenient().compile(
                "version: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://x\"]]]]\nplaybooks: []\n"));
        assertThrows(PlaybookException.class, () -> lenient().compile(
                "a: &a [x, x]\nb: &b [*a, *a]\nversion: \"t\"\nplaybooks: []\n"));
        assertThrows(PlaybookException.class, () -> lenient().compile("version: \"t\"\nversion: \"u\"\nplaybooks: []\n"));
        assertThrows(PlaybookException.class, () -> lenient().compile("x".repeat(PlaybookCompiler.MAX_BYTES + 1)));
        assertThrows(PlaybookException.class, () -> lenient().compile("version: \"t\"\nplaybooks: []\nextra: 1\n"));
        assertThrows(PlaybookException.class, () -> lenient().compile(
                "version: \"t\"\nplaybooks:\n  - rule: pam-refused\n    steps: []\n    when: always\n"));
        assertThrows(PlaybookException.class, () -> lenient().compile(one("pam-refused", "shell: rm")));
        assertThrows(PlaybookException.class, () -> lenient().compile(one("pam-refused", "{revoke: subject, deny: x}")));
        assertThrows(PlaybookException.class, () -> lenient().compile(one("pam-refused", "revoke: everyone")));
        assertThrows(PlaybookException.class, () -> lenient().compile(one("pam-refused", "deny: {target: ip, for: soon}")));
        assertThrows(PlaybookException.class, () -> lenient().compile(one("pam-refused", "deny: {target: ip}")));
        assertThrows(PlaybookException.class, () -> lenient().compile("version: 2026-11-05\nplaybooks: []\n"));
        assertThrows(PlaybookException.class, () -> lenient().compile("- just a list"));
        assertThrows(PlaybookException.class, () -> lenient().compile("version: \"t\"\nplaybooks: {}\n"));
        assertThrows(PlaybookException.class, () -> lenient().compile("version: \"\"\nplaybooks: []\n"));
        assertTrue(refusedWith(lenient().compile("version: \"has space\"\nplaybooks: []\n"), "identifier"));
    }

    @Test
    void filesAreReadStrictly(@TempDir Path dir) throws IOException {
        Path good = Files.writeString(dir.resolve("p.yaml"), SoarWorld.TEST_PLAYBOOKS);
        PlaybookCompiler c = new SoarWorld().compiler(true);
        assertTrue(c.compile(good).accepted());
        assertThrows(PlaybookException.class, () -> c.compile(dir), "a directory is not a file");
        Path bad = Files.write(dir.resolve("bad.yaml"), new byte[]{'v', ':', ' ', (byte) 0xC3, (byte) 0x28});
        assertThrows(PlaybookException.class, () -> c.compile(bad));
        Path big = Files.write(dir.resolve("big.yaml"), new byte[PlaybookCompiler.MAX_BYTES + 1]);
        assertThrows(PlaybookException.class, () -> c.compile(big));
    }

    // ---- what a good file gives -----------------------------------------------------------------------------

    @Test
    void theReferencePlaybooksCompileStrictlyAndMatchPartB() {
        PlaybookCompiler.Compilation c = new PlaybookCompiler(RuleCatalogue.reference(), ResponseSettings.defaults(),
                Set.of(), true).compileReference();
        assertTrue(c.accepted(), c.findings().toString());
        PlaybookSet set = c.set().orElseThrow();
        assertEquals("reference-2026-11-05", set.version());
        assertEquals(64, set.sha256().length());
        assertEquals(RuleCatalogue.reference().ids(), set.plays().keySet(), "every shipped rule has a reviewed playbook");
        for (var e : dev.dwarpal.response.Playbooks.referencePlays().entrySet()) {
            if (set.extrasFor(e.getKey()).isolate()) {
                continue;   // part F adds device isolation on purpose (honeytoken-touched)
            }
            assertEquals(e.getValue(), set.playFor(e.getKey()), "part A's rules: the same plays as part B's " + e.getKey());
        }
        assertTrue(set.extrasFor("honeytoken-touched").isolate());
        assertFalse(set.extrasFor("mfa-fatigue").isolate());
        assertEquals(dev.dwarpal.response.Playbooks.referencePlays().get("deny-storm-ip"), set.playFor("deny-storm-ip"));
        assertEquals(dev.dwarpal.response.Playbooks.cautiousPlay(), set.fallback());
        assertEquals(set.fallback(), set.playFor("not-in-the-file"));
    }

    @Test
    void isolateBecomesADenyAndARevokeOfTheDevice() {
        PlaybookSet set = lenient().compile(one("honeytoken-touched", "isolate: device", "isolate: device")).set().orElseThrow();
        assertEquals(Play.of(new Play.Deny(Entity.Kind.DEVICE, ResponseSettings.HARD_MAX_DENY),
                new Play.Revoke(Entity.Kind.DEVICE)), set.playFor("honeytoken-touched"));
        assertTrue(set.extrasFor("honeytoken-touched").isolate());
    }

    @Test
    void warningsBlockOnlyInStrictMode() {
        String partial = one("pam-refused", "watch: {target: subject, ratio: 10, halfLife: P1D}",
                "watch: {target: subject, ratio: 10, halfLife: P1D}");
        PlaybookCompiler.Compilation s = strict().compile(partial);
        assertFalse(s.accepted());
        assertTrue(s.findings().stream().anyMatch(f -> f.message().contains("without a playbook")));
        assertTrue(s.findings().stream().anyMatch(f -> f.message().contains("listed twice")));
        PlaybookCompiler.Compilation l = lenient().compile(partial);
        assertTrue(l.accepted());
        assertEquals(1, l.set().orElseThrow().playFor("pam-refused").steps().size());
        assertTrue(l.findings().getFirst().toString().startsWith("WARNING"));
    }

    @Test
    void watchOnlyKeepsOnlyWatchesAndNotifications() {
        PlaybookSet set = new SoarWorld().compile(SoarWorld.TEST_PLAYBOOKS);
        PlaybookSet safe = set.watchOnly();
        safe.plays().values().forEach(p -> assertTrue(p.steps().stream().noneMatch(Play.Step::destructive)));
        assertFalse(safe.extrasFor("honeytoken-touched").isolate());
        assertEquals(3, safe.extrasFor("honeytoken-touched").notifications().size());
        assertEquals(1, safe.playFor("beacon-correlated").steps().size());
    }

    @Test
    void theCatalogueRefusesDuplicatesAndTooMany() {
        assertThrows(IllegalArgumentException.class, () -> RuleCatalogue.reference().with(List.of(
                new RuleCatalogue.Rule("mfa-fatigue", RuleCatalogue.Evidence.VERIFIED, false))));
        java.util.List<RuleCatalogue.Rule> lots = new java.util.ArrayList<>();
        for (int i = 0; i <= RuleCatalogue.MAX_RULES; i++) {
            lots.add(new RuleCatalogue.Rule("r" + i, RuleCatalogue.Evidence.VERIFIED, false));
        }
        assertThrows(IllegalArgumentException.class, () -> new RuleCatalogue(lots));
        assertTrue(RuleCatalogue.reference().rule("mfa-fatigue").orElseThrow().namesVictim());
    }
}

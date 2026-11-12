package dev.dwarpal.lab.scenarios;

import dev.dwarpal.lab.LabConfig;
import dev.dwarpal.lab.LabWorld;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.sim.SimTelemetry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The scenario tools on a real lab: the launch limits, the sandbox (including attempts to escape it) and the export
 * (including attempts to make it leak). Every attempt is a working probe; the ones that breached an earlier build
 * stay here as regression tests.
 */
class ScenarioToolsTest {

    private static LabWorld world;
    private static final String CANARY = "CANARY-MARKER-98765";
    private static final String HOST = "secret-host-77";
    private static final String HEX = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    @BeforeAll
    static void build() throws Exception {
        world = LabWorld.create(LabConfig.defaults(Files.createTempDirectory("dwarpal-tools-test")).withPort(0));
        world.warmUp(3);
        ScenarioRunner r = new ScenarioRunner(tick());
        // an A6 theft (USB, encoded PowerShell) and an A8 beacon give the sandbox something to find
        ScenarioRunner.Launch a6 = r.launch(world, "A6", "tester", true);
        world.advanceTo(a6.endsAt().plus(Duration.ofHours(1)));
        ScenarioRunner.Launch a8 = r.launch(world, "A8", "tester", true);
        world.advanceTo(a8.endsAt().plus(Duration.ofHours(1)));
    }

    @AfterAll
    static void release() {
        world.close();
    }

    private static java.util.function.LongSupplier tick() {
        AtomicLong t = new AtomicLong();
        return () -> t.addAndGet(5_000);
    }

    private static String rule(String id, String match) {
        return "version: 1\nrules:\n  - id: " + id + "\n    title: t\n    severity: MEDIUM\n    techniques: [T1052.001]\n"
                + "    match: '" + match + "'\n";
    }

    private static RuleSandbox sandbox() {
        AtomicLong wall = new AtomicLong();
        return new RuleSandbox(() -> wall.addAndGet(60_000));
    }

    // ---- the launch limits ---------------------------------------------------------------------------

    @Test
    void aPersonCannotLaunchMoreThanTwelveScenariosInFiveMinutes() {
        AtomicLong wall = new AtomicLong();
        ScenarioRunner r = new ScenarioRunner(() -> wall.addAndGet(ScenarioRunner.MIN_GAP_MILLIS + 1));
        Instant before = world.now();
        int ok = 0;
        ScenarioRunner.Refused last = null;
        for (int i = 0; i < 20; i++) {
            try {
                // L6 is two minutes long, so advancing the scenario clock lets it be launched again
                r.launch(world, "L6", "greedy", true);
                ok++;
                world.advanceTo(world.now().plus(Duration.ofMinutes(5)));
            } catch (ScenarioRunner.Refused e) {
                last = e;
                break;
            }
        }
        assertEquals(ScenarioRunner.PER_PERSON, ok);
        assertEquals(429, last.status());
        // someone else is limited on their own account
        wall.addAndGet(ScenarioRunner.MIN_GAP_MILLIS + 1);
        assertEquals("L6", r.launch(world, "L6", "someone-else", true).scenario());
        assertTrue(world.now().isAfter(before));
    }

    @Test
    void launchesCloserThanASecondApartAreRefusedAndANeverBuiltScenarioIsUnknown() {
        AtomicLong wall = new AtomicLong(1_000_000);
        ScenarioRunner r = new ScenarioRunner(wall::get);
        r.launch(world, "A5", "p", true);
        assertEquals(429, assertThrows(ScenarioRunner.Refused.class, () -> r.launch(world, "A1", "p", true)).status());
        wall.addAndGet(2_000);
        assertEquals(404, assertThrows(ScenarioRunner.Refused.class, () -> r.launch(world, "A5; DROP", "p", true)).status());
        assertEquals(409, assertThrows(ScenarioRunner.Refused.class, () -> r.launch(world, "A5", "p", true)).status(),
                "still playing out");
    }

    @Test
    void peopleRotateAndTheCeoAndTheScriptsOwnCastAreNeverChosen() {
        AtomicLong wall = new AtomicLong();
        ScenarioRunner r = new ScenarioRunner(() -> wall.addAndGet(5_000));
        Set<String> seen = new HashSet<>();
        Set<String> cast = new HashSet<>();
        world.telemetry.cast().values().forEach(cast::addAll);
        for (int i = 0; i < 10; i++) {
            ScenarioRunner.Launch l = r.launch(world, "A5", "rot", true);
            seen.add(l.person());
            world.advanceTo(world.now().plus(Duration.ofMinutes(2)));
        }
        assertEquals(10, seen.size(), "ten launches, ten different people");
        assertFalse(seen.contains(world.ceo));
        assertTrue(seen.stream().noneMatch(cast::contains));
        r.clear();
        assertTrue(r.journal().isEmpty());
    }

    @Test
    void theWorldItselfRefusesAFloodOfInjectedItems() {
        SimOrganisation.User u = world.org.users.get(30);
        List<Object> flood = new ArrayList<>();
        Instant at = world.now().plusSeconds(120);
        for (int i = 0; i < 20_000; i++) {
            flood.add(new SimTelemetry.RawLine(SimTelemetry.Source.CLOUD, at, "{}", SimTelemetry.Activity.NORMAL, u.id()));
        }
        int accepted = 0;
        boolean refused = false;
        for (int round = 0; round < 5 && !refused; round++) {
            try {
                world.inject(flood);
                accepted += flood.size();
            } catch (IllegalStateException e) {
                refused = true;
            }
        }
        assertTrue(refused, "after 50,000 waiting items the world says no (accepted " + accepted + ")");
        assertTrue(accepted <= LabWorld.MAX_INJECTED_PENDING);
        assertThrows(IllegalArgumentException.class, () -> world.inject(List.of(new SimTelemetry.RawLine(
                SimTelemetry.Source.CLOUD, world.now().minusSeconds(60), "{}", SimTelemetry.Activity.NORMAL, "u1"))),
                "nothing in the past");
        assertThrows(IllegalArgumentException.class, () -> world.inject(List.of("not an item")));
        world.advanceTo(world.now().plus(Duration.ofMinutes(10)));    // the junk lines are refused by the collector
    }

    // ---- the sandbox ---------------------------------------------------------------------------------

    @Test
    void aGoodRuleRunsOnRecordedEventsAndNothingLiveChanges() {
        int cases = world.cases.all().size();
        int raised = world.raised.size();
        long head = world.org.audit.head().sequence();
        RuleSandbox.RuleResult r = sandbox().rule(world, "learner", rule("lab-usb", "dataset = endpoint and action = usb.mount"),
                true);
        assertTrue(r.accepted() && r.ran(), r.toString());
        assertTrue(r.alerts() >= 1, "the A6 theft plugged in a USB drive");
        assertTrue(r.eventsRead() > 1_000);
        assertFalse(r.sample().isEmpty());
        assertEquals(cases, world.cases.all().size(), "no case from a learner's rule");
        assertEquals(raised, world.raised.size());
        assertEquals(head, world.org.audit.head().sequence(), "nothing written to the live chain");
        assertTrue(r.note().contains("Nothing was raised for real"));
    }

    @Test
    void aRuleThatMatchesEverythingIsBoundedByTheEnginesOwnFloodLimits() {
        RuleSandbox.RuleResult r = sandbox().rule(world, "learner", rule("lab-all", "*"), true);
        assertTrue(r.accepted() && r.ran());
        assertTrue(r.sample().size() <= RuleSandbox.MAX_SAMPLE);
        assertTrue(r.eventsRead() <= RuleSandbox.MAX_RECORDS);
    }

    @Test
    void lintingNeverEchoesWhatWasSubmitted() {
        String dangerous = "version: 1\nrules:\n  - id: x\n    title: " + CANARY + "\n    severity: MEDIUM\n"
                + "    techniques: [T1052.001]\n    match: 'dataset = " + CANARY + " and and'\n";
        RuleSandbox.RuleResult r = sandbox().rule(world, "p", dangerous, false);
        assertFalse(r.accepted());
        assertFalse(r.toString().contains(CANARY), "findings name places, not content: " + r);
    }

    @Test
    void yamlTagsAliasesAndBombsAreRefusedWithoutAStackTraceOrAnEcho() {
        List<String> attacks = List.of(
                "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://127.0.0.1/" + CANARY + "\"]]]]",
                "version: 1\nrules: !!java.lang.ProcessBuilder [calc]\n",
                "a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b]\n",
                "[".repeat(5_000),
                "version: 1\nversion: 2\nrules: []\n",
                "x".repeat(RuleSandbox.MAX_YAML + 1),
                "\u0000\u0001 " + CANARY,
                "");
        for (String a : attacks) {
            RuleSandbox.RuleResult r = sandbox().rule(world, "p", a, true);
            assertFalse(r.accepted(), a.substring(0, Math.min(40, a.length())));
            assertFalse(r.ran());
            assertFalse(r.toString().contains(CANARY));
            assertFalse(r.toString().contains("	at ") || r.toString().contains("at dev.") || r.toString().contains("java."), r.toString());
        }
    }

    @Test
    void aRuleWithTooManyRulesOrAnInventedTechniqueOrADeadConditionIsRefused() {
        StringBuilder many = new StringBuilder("version: 1\nrules:\n");
        for (int i = 0; i <= RuleSandbox.MAX_RULES; i++) {
            many.append("  - id: r").append(i).append("\n    title: t\n    severity: LOW\n    techniques: [T1071]\n    match: 'dataset = endpoint'\n");
        }
        assertFalse(sandbox().rule(world, "p", many.toString(), true).accepted(), "more than twenty rules");
        assertFalse(sandbox().rule(world, "p", rule("x", "dataset = firewall and dataset = endpoint"), true).accepted());
        assertFalse(sandbox().rule(world, "p", rule("x", "cmd ~ \".*\" and provenance = NOT_A_PROVENANCE"), true).accepted(),
                "a typo in an enum is an error, not a query that silently matches nothing");
    }

    @Test
    void oneRunAtATimeAndOneRunPerPersonEveryFewSeconds() {
        RuleSandbox sb = new RuleSandbox(new AtomicLong(0)::get);   // the wall clock never moves
        String usb = rule("lab-usb", "dataset = endpoint and action = usb.mount");
        assertTrue(sb.rule(world, "ann", usb, true).ran());
        RuleSandbox.RuleResult again = sb.rule(world, "ann", usb, true);
        assertFalse(again.ran());
        assertTrue(again.note().contains("One run every"));
        assertTrue(sb.rule(world, "bob", usb, true).ran(), "another person has their own allowance");
        assertTrue(sb.running.tryAcquire(), "the single run slot is free again after each run");
        try {
            RuleSandbox.RuleResult busy = sb.rule(world, "cat", usb, true);
            assertFalse(busy.ran());
            assertTrue(busy.note().contains("in progress"));
        } finally {
            sb.running.release();
        }
    }

    @Test
    void aPlaybookOnForgeableEvidenceIsRefusedAndOneThatSneaksPastTheGuardRailsToo() {
        RuleSandbox sb = sandbox();
        String forge = "version: \"lab.9\"\nplaybooks:\n  - rule: cloud-bulk-download-then-external-share\n    steps:\n"
                + "      - isolate: device\n      - revoke: subject\n";
        RuleSandbox.PlaybookResult r = sb.playbook(forge);
        assertFalse(r.accepted(), "destructive steps on collected-only evidence");
        assertTrue(r.findings().stream().anyMatch(f -> f.level().equals("ERROR")));
        assertTrue(r.plans().isEmpty());
        // a default play that destroys, a deny that never ends, an unknown rule, an invented step
        for (String bad : List.of(
                "version: \"lab.9\"\nplaybooks: []\ndefault:\n  - revoke: subject\n",
                "version: \"lab.9\"\nplaybooks:\n  - rule: honeytoken-touched\n    steps:\n      - deny: {target: subject, for: P400D}\n",
                "version: \"lab.9\"\nplaybooks:\n  - rule: made-up-rule\n    steps:\n      - revoke: subject\n",
                "version: \"lab.9\"\nplaybooks:\n  - rule: honeytoken-touched\n    steps:\n      - exec: rm -rf /\n",
                "version: \"lab.9\"\nplaybooks:\n  - rule: honeytoken-touched\n    steps:\n      - notify: {connector: ticket, template: action-taken, extra: 1}\n",
                "!!java.lang.Runtime {}",
                "version: \"" + CANARY + "\"\nplaybooks: [[[[")) {
            RuleSandbox.PlaybookResult p = sb.playbook(bad);
            assertFalse(p.accepted(), bad);
            assertFalse(p.toString().contains(CANARY));
        }
    }

    // ---- the export ----------------------------------------------------------------------------------

    @Test
    void theExportHoldsNoKeyNoRealNameAndNoSecretEvenWhenAnEventCarriesOne() {
        // a hostile endpoint event: key-like text, a PEM header and this host's name in an encoded command line
        SimOrganisation.User u = world.org.users.get(2);
        Instant ts = world.now().plusSeconds(60).truncatedTo(ChronoUnit.SECONDS);
        String line = "{\"ts\":\"" + ts + "\",\"device\":\"" + u.laptop() + "\",\"user\":\"" + u.id()
                + "\",\"type\":\"process.start\",\"process\":\"powershell.exe\",\"parent\":\"explorer.exe\",\"cmd\":\"powershell.exe -enc "
                + HEX + " -----BEGIN " + "PRIVATE KEY----- " + HOST + " 10.20.0.99\"}\n";
        world.inject(List.of(new SimTelemetry.EndpointBatch(u.laptop(), "agent-" + u.laptop(), 0, ts.plusSeconds(60), line,
                "unsigned", List.of(), u.id())));
        world.advanceTo(ts.plus(Duration.ofMinutes(5)));
        assertTrue(world.raised.stream().anyMatch(r -> r.alert().rule().equals("encoded-powershell")
                && r.alert().entities().stream().anyMatch(e -> e.id().equals(u.laptop()))), "the hostile event is evidence");

        String json = new RunExport(Set.of(HOST)).export(world, List.of());
        assertTrue(json.contains("dwarpal-replay/1") && json.contains("simulated organisation"));
        assertFalse(json.contains(HEX));
        assertFalse(json.contains("-----BEGIN"));
        assertFalse(json.contains(HOST), "this host's name");
        assertFalse(json.contains(u.id() + "\"") && json.contains("\"" + u.id() + "\""), "real person ids are pseudonyms");
        assertFalse(json.matches("(?s).*laptop-u[0-9].*"), "real device names");
        assertFalse(json.contains("10.20."), "internal addresses are pseudonyms");
        assertTrue(json.contains("person-1") && json.contains("device-1"));
        assertFalse(json.matches("(?s).*[0-9a-fA-F]{32,}.*"), "no hash, key or MAC");
        assertFalse(json.contains(world.config.dir().toString().replace("\\", "\\\\")), "no lab directory");
        assertFalse(json.contains(System.getProperty("user.name")), "no user name");
        assertTrue(json.contains("203.0.113.66"), "documentation-range addresses are kept so the C2 story reads");
    }

    @Test
    void theLastLineOfDefenceRefusesAnythingThatLooksLikeASecret() {
        RunExport e = new RunExport(Set.of(HOST));
        assertThrows(RunExport.Refused.class, () -> e.guard("{\"x\":\"" + HEX + "\"}"));
        assertThrows(RunExport.Refused.class, () -> e.guard("-----BEGIN " + "PRIVATE KEY-----"));
        assertThrows(RunExport.Refused.class, () -> e.guard("{\"x\":\"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\"}"));
        assertThrows(RunExport.Refused.class, () -> e.guard("on " + HOST));
        e.guard("{\"rule\":\"cloud-bulk-download-then-external-share\",\"id\":\"al-cloud-bulk-download-then-external-share-1234\"}");
        assertNotEquals("", RunExport.FORMAT);
    }
}

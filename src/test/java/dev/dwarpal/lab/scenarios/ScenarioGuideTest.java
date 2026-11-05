package dev.dwarpal.lab.scenarios;

import dev.dwarpal.lab.LabConfig;
import dev.dwarpal.lab.LabWorld;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The guide's promises, checked against a real lab: every scenario is launched on a warmed-up lab and what the
 * engine decides and the SOC ranks must be what {@link ScenarioCatalog} says. If a detector or a weight changes and
 * a walkthrough would now be wrong, this test fails first.
 */
class ScenarioGuideTest {

    private static Path dir;
    private static LabWorld world;
    private static final Map<String, ScenarioRunner.Report> REPORTS = new ConcurrentHashMap<>();

    @BeforeAll
    static void run() throws Exception {
        dir = Files.createTempDirectory("dwarpal-guide-test");
        world = LabWorld.create(LabConfig.defaults(dir).withPort(0));
        world.warmUp(3);
        long[] wall = {0};
        ScenarioRunner runner = new ScenarioRunner(() -> wall[0] += 10_000);
        for (Scenario s : ScenarioCatalog.all()) {
            ScenarioRunner.Launch l = runner.launch(world, s.id(), "tester", true);
            world.advanceTo(l.endsAt().plus(Duration.ofHours(3)));
            REPORTS.put(s.id(), runner.report(world, l.number()).orElseThrow());
        }
    }

    @AfterAll
    static void release() {
        world.close();
    }

    @Test
    void theEnginesDecisionsAreWhatTheGuideSays() {
        for (Scenario s : ScenarioCatalog.all()) {
            List<String> got = REPORTS.get(s.id()).decisions().stream().map(ScenarioRunner.Decision::outcome).toList();
            assertEquals(s.decisions(), got, s.id() + ": decisions");
        }
    }

    @Test
    void everyAlertTheGuidePromisesIsRaisedWithThatPriorityAndEvidenceClass() {
        for (Scenario s : ScenarioCatalog.all()) {
            for (Scenario.Expect e : s.expects()) {
                boolean found = REPORTS.get(s.id()).alerts().stream().anyMatch(a -> a.rule().equals(e.rule())
                        && a.engine().equals(e.engine()) && a.priority().equals(e.priority())
                        && a.actionable() == e.actionable());
                assertTrue(found, s.id() + ": " + e + " in " + REPORTS.get(s.id()).alerts().stream()
                        .map(a -> a.engine() + ":" + a.rule() + ":" + a.priority() + ":" + a.actionable()).toList());
            }
        }
    }

    @Test
    void noAlertIsMoreUrgentThanTheGuideSaysItCanBe() {
        for (Scenario s : ScenarioCatalog.all()) {
            for (ScenarioRunner.Seen a : REPORTS.get(s.id()).alerts()) {
                assertTrue(a.priority().compareTo(s.ceiling()) >= 0,
                        s.id() + ": " + a.rule() + " is " + a.priority() + " but the ceiling is " + s.ceiling());
            }
        }
    }

    @Test
    void theLookAlikesAndTheLoginAttacksRaiseNoRuleAlert() {
        for (String id : List.of("A1", "A2", "A3", "A4", "A5", "A7", "L5", "L6", "QUIET")) {
            List<String> rules = new ArrayList<>();
            for (ScenarioRunner.Seen a : REPORTS.get(id).alerts()) {
                if (!a.engine().equals("E")) {
                    rules.add(a.rule());
                }
            }
            assertTrue(rules.isEmpty(), id + " raised " + rules);
        }
        assertTrue(REPORTS.get("L6").alerts().isEmpty(), "the administrator's signed script raises nothing at all");
    }

    @Test
    void theCloudAttackCannotTriggerADestructiveActionAndTheDeviceAttacksCan() {
        assertTrue(REPORTS.get("A9").alerts().stream().noneMatch(ScenarioRunner.Seen::actionable));
        assertTrue(REPORTS.get("A8").alerts().stream().anyMatch(a -> a.actionable() && a.priority().equals("P1")));
        assertTrue(REPORTS.get("A6").alerts().stream().anyMatch(a -> a.actionable() && a.priority().equals("P1")));
    }

    private static ScenarioRunner.Decision decision(String id, int n) {
        return REPORTS.get(id).decisions().get(n);
    }

    @Test
    void theReasonsTheWalkthroughsNameAreTheReasonsTheEngineGave() {
        double p = Double.parseDouble(decision("A1", 0).pAttack());
        assertTrue(p > 0.7 && p < 0.9, "A1 'about 80 per cent': " + p);
        assertTrue(decision("A1", 0).signals().contains("network-novelty")
                && decision("A1", 0).signals().contains("device-novelty"));
        assertTrue(decision("A2", 0).signals().contains("ip-reputation"));
        assertTrue(decision("A3", 0).reasons().contains("challenge required"));
        double a3 = Double.parseDouble(decision("A3", 0).pAttack());
        assertTrue(a3 > 0.001 && a3 < 0.05, "A3 'about one per cent': " + a3);
        assertTrue(decision("A4", 1).signals().contains("impossible-travel"));
        assertTrue(decision("A4", 1).reasons().length() > 0);
        assertTrue(decision("A5", 0).signals().contains("ip-reputation"));
        assertTrue(decision("A6", 0).reasons().contains("step-up satisfied"), "the thief's security key");
        assertTrue(decision("A7", 0).signals().contains("password-spray"));
    }

    private static long matched(String query) {
        return world.store.search(query, world.scriptStart, world.now().plusSeconds(1), 1).matched();
    }

    @Test
    void theHuntsTheWalkthroughsSuggestFindWhatTheyPromise() {
        assertEquals(1, matched("ip = 198.51.100.66"), "A7: one request from the spray address");
        assertEquals(1, matched("dataset = cloud and share = partner-mail.example"), "A9: the external share");
        assertTrue(matched("dataset = endpoint and process = powershell.exe and signer = corp-it") > 0, "L6");
        assertEquals(0, matched("dataset = endpoint and process = powershell.exe and cmd ~ \" -enc\" and signer = corp-it"),
                "A6's encoded PowerShell has no signer");
        String laptop = REPORTS.get("A8").launch().devices().get(0);
        var counts = world.store.counts("dataset = firewall and dst = 203.0.113.66 | count by device",
                world.scriptStart, world.now().plusSeconds(1));
        assertTrue(counts.groups().stream().anyMatch(g -> g.values().equals(List.of(laptop)) && g.count() == 120),
                "A8: 120 flows from the launched laptop: " + counts);
    }

    @Test
    void decidingTheStolenLaptopCaseDoesWhatTheWalkthroughSays() {
        ScenarioRunner.Seen p1 = REPORTS.get("A6").alerts().stream().filter(a -> a.rule().equals("stolen-laptop-collection"))
                .findFirst().orElseThrow();
        String device = REPORTS.get("A6").launch().devices().get(0);
        var verdict = world.signVerdict("ana", p1.alertId(), dev.dwarpal.soc.Verdict.Outcome.TRUE_POSITIVE);
        var result = world.soar.handle(verdict);
        assertEquals(dev.dwarpal.response.Playbooks.Status.APPLIED, result.status(), result.message());
        assertTrue(result.isolated().contains(device), "the playbook isolates the laptop");
        assertEquals(dev.dwarpal.soar.DeviceIsolation.State.PENDING_ACK, world.isolation.of(device).orElseThrow().state(),
                "pending until the device's own key acknowledges");
        world.advanceTo(world.now().plusSeconds(60));
        assertEquals(dev.dwarpal.soar.DeviceIsolation.State.ISOLATED, world.isolation.of(device).orElseThrow().state(),
                "the simulated sensor answers with a batch signed by the device's key");
        var again = world.soar.handle(verdict);
        assertEquals(dev.dwarpal.response.Playbooks.Status.REFUSED, again.status(), "a verdict is single use");
    }

    @Test
    void eachLaunchNamesWhoItIsAboutAndWhenItRuns() {
        for (Scenario s : ScenarioCatalog.all()) {
            ScenarioRunner.Launch l = REPORTS.get(s.id()).launch();
            assertEquals(s.id(), l.scenario());
            assertFalse(l.endsAt().isBefore(l.startsAt()));
            assertTrue(l.items() > 0);
            assertEquals(s.id().equals("QUIET"), l.person().isEmpty());
        }
    }
}

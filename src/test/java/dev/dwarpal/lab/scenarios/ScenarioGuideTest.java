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

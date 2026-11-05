package dev.dwarpal.console.lab;

import dev.dwarpal.console.ConsoleModule.Response;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.lab.LabConfig;
import dev.dwarpal.lab.LabRunner;
import dev.dwarpal.lab.scenarios.LabSession;
import dev.dwarpal.wire.JsonValue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static dev.dwarpal.console.lab.FakeRoutes.ADMIN;
import static dev.dwarpal.console.lab.FakeRoutes.ADMIN_STALE;
import static dev.dwarpal.console.lab.FakeRoutes.ANALYST;
import static dev.dwarpal.console.lab.FakeRoutes.LEAD;
import static dev.dwarpal.console.lab.FakeRoutes.USER;
import static dev.dwarpal.console.lab.FakeRoutes.json;
import static dev.dwarpal.console.lab.FakeRoutes.text;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The lab module's routes, called directly the way the console host will call them, on a real lab. */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class LabModuleTest {

    private static LabSession session;
    private static FakeRoutes routes;

    @BeforeAll
    static void open() throws Exception {
        Path dir = Files.createTempDirectory("dwarpal-labmodule-test");
        session = LabSession.open(LabConfig.defaults(dir).withPort(0));
        session.runner().pause();
        routes = FakeRoutes.of(new LabModule(session));
    }

    @AfterAll
    static void close() {
        session.close();
    }

    private static void gap() throws InterruptedException {
        Thread.sleep(1_100);
    }

    @Test
    @Order(1)
    void everyRouteIsRegisteredWithItsRoleAndStepUp() {
        assertEquals(Role.ADMIN, routes.route("POST", "control/reset").minimum());
        assertTrue(routes.route("POST", "control/reset").stepUp(), "reset is a privileged write");
        assertEquals(Role.LEAD, routes.route("POST", "control/speed").minimum());
        assertEquals(Role.LEAD, routes.route("POST", "control/fastforward").minimum());
        assertEquals(Role.LEAD, routes.route("POST", "control/pause").minimum());
        assertEquals(Role.LEAD, routes.route("GET", "export").minimum());
        assertEquals(Role.ANALYST, routes.route("POST", "launch/{}").minimum());
        assertFalse(routes.route("POST", "launch/{}").stepUp());
        assertEquals(Role.ANALYST, routes.route("POST", "sandbox/rule").minimum());
        assertEquals(14, routes.all().size());
        assertEquals("lab", new LabModule(session).id());
    }

    @Test
    @Order(2)
    void aHandlerChecksTheRoleAgainEvenIfTheHostDid_not() {
        // the host checks the minimum first; the handler must hold on its own if it is ever called without that
        for (String p : List.of("control/pause", "control/resume", "control/speed", "control/fastforward")) {
            assertEquals(403, routes.call("POST", p, ANALYST, "{}").status(), p + " is for leads");
        }
        assertEquals(403, routes.call("POST", "control/reset", LEAD, "{}").status(), "reset is for administrators");
        assertEquals(403, routes.call("POST", "control/reset", ANALYST, "{}").status());
        assertEquals(403, routes.call("POST", "launch/A5", USER, "{}").status(), "an ordinary person is no analyst");
        assertEquals(403, routes.call("GET", "export", ANALYST, "").status());
        assertEquals(403, routes.call("GET", "status", USER, "").status());
        assertEquals(403, routes.call("POST", "sandbox/rule", USER, "{\"yaml\":\"x\"}").status());
    }

    @Test
    @Order(3)
    void resetNeedsAFreshSecondFactorEvenForAnAdministrator() {
        long before = session.generation();
        Response r = routes.call("POST", "control/reset", ADMIN_STALE, "{}");
        assertEquals(403, r.status());
        assertEquals(before, session.generation(), "nothing was reset");
    }

    @Test
    @Order(4)
    void scenariosAndStatusAreReadable() {
        JsonValue.JObject s = json(routes.call("GET", "scenarios", ANALYST, ""));
        assertTrue(s.get("scenarios").orElseThrow() instanceof JsonValue.JArray a && a.size() == 12);
        JsonValue.JObject st = json(routes.call("GET", "status", ANALYST, ""));
        assertEquals("PAUSED", text(st.get("state").orElseThrow()));
        assertTrue(st.get("openByPriority").isPresent());
        assertFalse(routes.call("GET", "status", ANALYST, "").body().contains("Exception"));
    }

    @Test
    @Order(5)
    void aLaunchSaysWhoItIsAboutAndThatTheClockIsPaused() throws Exception {
        Response r = routes.call("POST", "launch/A5", ANALYST, "");
        assertEquals(200, r.status(), r.body());
        JsonValue.JObject o = json(r);
        JsonValue.JObject launch = (JsonValue.JObject) o.get("launch").orElseThrow();
        assertFalse(text(launch.get("person").orElseThrow()).isEmpty());
        assertTrue(text(o.get("note").orElseThrow()).contains("paused"));
        JsonValue.JObject sc = (JsonValue.JObject) o.get("scenario").orElseThrow();
        assertFalse(text(sc.get("attacker").orElseThrow()).isEmpty(), "it says what the attacker does before it runs");
        assertFalse(text(sc.get("defender").orElseThrow()).isEmpty());
        gap();
        // the same scenario is refused only while it is still playing; A5 is a single event so it is over once time moves
    }

    @Test
    @Order(6)
    void fastForwardPlaysItAndTheLaunchReportShowsTheEnginesDecision() throws Exception {
        Instant before = session.world().now();
        Response ff = routes.call("POST", "control/fastforward", LEAD, "{\"minutes\":10}");
        assertEquals(200, ff.status(), ff.body());
        assertTrue(session.world().now().isAfter(before.plusSeconds(590)));
        JsonValue.JObject rep = json(routes.call("GET", "launches/1", ANALYST, ""));
        JsonValue.JArray d = (JsonValue.JArray) rep.get("decisions").orElseThrow();
        assertEquals(1, d.size());
        assertEquals("DENY", text(((JsonValue.JObject) d.get(0)).get("outcome").orElseThrow()));
        assertEquals(404, routes.call("GET", "launches/999", ANALYST, "").status());
        assertEquals(400, routes.call("GET", "launches/x%00", ANALYST, "").status());
    }

    @Test
    @Order(7)
    void badLaunchesAreRefusedWithShortMessages() throws Exception {
        assertEquals(404, routes.call("POST", "launch/Z9", ANALYST, "").status());
        Response traversal = routes.call("POST", "launch/..%2F..%2Fetc", ANALYST, "");
        assertEquals(400, traversal.status());
        assertFalse(traversal.body().contains("etc"), "the input is not echoed");
        assertEquals(400, routes.call("POST", "launch/A5", ANALYST, "{\"hostile\":1}").status(), "unknown fields");
        assertEquals(400, routes.call("POST", "launch/A5", ANALYST, "[1]").status());
        assertEquals(400, routes.call("POST", "launch/A5", ANALYST, "{not json").status());
    }

    @Test
    @Order(8)
    void aScenarioButtonHeldDownIsNotADenialOfService() throws Exception {
        gap();
        int accepted = 0;
        int refused = 0;
        for (int i = 0; i < 60; i++) {
            Response r = routes.call("POST", "launch/QUIET", ANALYST, "");
            if (r.status() == 200) {
                accepted++;
            } else {
                refused++;
                assertTrue(r.status() == 429 || r.status() == 409, r.body());
            }
        }
        assertEquals(1, accepted, "the quiet day is accepted once; while it plays it cannot be stacked");
        assertEquals(59, refused);
        // a second person is limited on their own, and the lab still answers
        gap();
        int ok = 0;
        for (String s : List.of("A1", "A2", "A3", "A4", "A5", "A7", "L6", "A1", "A2", "A3", "A4", "A5", "A7", "A9", "A8")) {
            Response r = routes.call("POST", "launch/" + s, ANALYST, "");
            if (r.status() == 200) {
                ok++;
            }
            Thread.sleep(1_050);
        }
        assertTrue(ok <= 12, "no more than twelve launches per person in five minutes, got " + ok);
        assertEquals(200, routes.call("GET", "status", ANALYST, "").status(), "the lab still answers");
    }

    @Test
    @Order(9)
    void speedAndFastForwardAreBounded() {
        for (String body : List.of("{\"speed\":0}", "{\"speed\":-5}", "{\"speed\":100000}", "{\"speed\":\"fast\"}", "{}",
                "{\"speed\":1,\"x\":2}")) {
            assertEquals(400, routes.call("POST", "control/speed", LEAD, body).status(), body);
        }
        assertEquals(200, routes.call("POST", "control/speed", LEAD, "{\"speed\":120}").status());
        assertEquals(120.0, session.runner().speed());
        for (String body : List.of("{\"minutes\":0}", "{\"minutes\":-1}", "{\"minutes\":721}", "{\"minutes\":1.5}", "{}")) {
            assertEquals(400, routes.call("POST", "control/fastforward", LEAD, body).status(), body);
        }
    }

    @Test
    @Order(10)
    void pauseAndResumeMoveTheClockState() {
        assertEquals(200, routes.call("POST", "control/resume", LEAD, "").status());
        assertEquals(LabRunner.State.RUNNING, session.runner().state());
        assertEquals(200, routes.call("POST", "control/pause", LEAD, "").status());
        assertEquals(LabRunner.State.PAUSED, session.runner().state());
    }

    @Test
    @Order(11)
    void theSandboxLintsRunsAndKeepsTheLiveLabUntouched() {
        int cases = session.world().cases.all().size();
        long head = session.world().org.audit.head().sequence();
        String yaml = "version: 1\\nrules:\\n  - id: lab-usb\\n    title: usb\\n    severity: MEDIUM\\n    techniques: [T1052.001]\\n"
                + "    match: 'dataset = endpoint and action = usb.mount'\\n";
        Response r = routes.call("POST", "sandbox/rule", ANALYST, "{\"yaml\":\"" + yaml + "\",\"run\":true}");
        assertEquals(200, r.status(), r.body());
        JsonValue.JObject o = json(r);
        assertEquals(JsonValue.bool(true), o.get("accepted").orElseThrow());
        assertEquals(JsonValue.bool(true), o.get("ran").orElseThrow());
        assertEquals(cases, session.world().cases.all().size(), "no case from the learner's rule");
        assertEquals(head, session.world().org.audit.head().sequence(), "nothing was written to the live chain");
        assertEquals(400, routes.call("POST", "sandbox/rule", ANALYST, "{\"yaml\":1}").status());
        assertEquals(400, routes.call("POST", "sandbox/rule", ANALYST, "{\"yaml\":\"x\",\"extra\":1}").status());
        Response p = routes.call("POST", "sandbox/playbook", ANALYST, "{\"yaml\":\"version: x\"}");
        assertEquals(200, p.status());
        assertEquals(JsonValue.bool(false), json(p).get("accepted").orElseThrow());
    }

    @Test
    @Order(12)
    void theExportIsForLeadsAndHoldsNoSecret() {
        Response r = routes.call("GET", "export", LEAD, "");
        assertEquals(200, r.status());
        JsonValue.JObject o = json(r);
        assertEquals("dwarpal-replay/1", text(o.get("format").orElseThrow()));
        String body = r.body();
        assertFalse(body.contains("-----BEGIN"));
        assertFalse(body.matches("(?s).*[0-9a-f]{64}.*"), "no hash or key");
        assertFalse(body.contains(session.config().dir().toString().replace("\\", "\\\\")), "no lab directory");
        assertFalse(body.contains(System.getProperty("user.name")), "no user name");
    }

    @Test
    @Order(99)
    void resetGoesBackToDayZeroAndForgetsTheLaunches() throws Exception {
        long gen = session.generation();
        Instant scriptStart = session.world().scriptStart;
        // while the reset rebuilds the world, launches and fast-forwards are refused, not lost in the old world
        java.util.concurrent.atomic.AtomicInteger during = new java.util.concurrent.atomic.AtomicInteger();
        Thread watcher = new Thread(() -> {
            long end = System.currentTimeMillis() + 60_000;
            while (System.currentTimeMillis() < end && during.get() == 0) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    return;
                }
                if (session.resetting() && during.get() == 0) {
                    Response l = routes.call("POST", "launch/A5", ANALYST, "");
                    Response f = routes.call("POST", "control/fastforward", LEAD, "{\"minutes\":5}");
                    if (l.status() == 409 && f.status() == 409) {
                        during.set(1);
                    }
                    Response again = routes.call("POST", "control/reset", ADMIN, "");
                    if (again.status() != 429 && again.status() != 409) {
                        during.set(-1);
                    }
                }
            }
        });
        watcher.start();
        Response r = routes.call("POST", "control/reset", ADMIN, "");
        watcher.join();
        assertEquals(1, during.get(), "launch and fast-forward refused with 409 during a reset; a second reset is refused");
        assertEquals(200, r.status(), r.body());
        assertEquals(gen + 1, session.generation());
        assertTrue(session.world().now().isBefore(scriptStart.plusSeconds(4 * 86_400L)), "back at the end of the warm-up");
        assertEquals(0, ((JsonValue.JArray) json(routes.call("GET", "launches", ANALYST, "")).get("launches")
                .orElseThrow()).size());
        assertNotEquals(LabRunner.State.FAILED, session.runner().state());
        Thread.sleep(1_100);
        assertEquals(200, routes.call("POST", "launch/A5", ANALYST, "").status(), "the new lab takes launches");
    }
}

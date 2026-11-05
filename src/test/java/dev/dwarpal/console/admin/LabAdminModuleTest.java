package dev.dwarpal.console.admin;

import dev.dwarpal.console.ConsoleModule.Principal;
import dev.dwarpal.console.ConsoleModule.Response;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.console.lab.FakeRoutes;
import dev.dwarpal.lab.LabConfig;
import dev.dwarpal.lab.scenarios.LabSession;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static dev.dwarpal.console.lab.FakeRoutes.json;
import static dev.dwarpal.console.lab.FakeRoutes.text;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The admin module on the running lab: an installed policy changes what the lab decides. */
class LabAdminModuleTest {

    private static final Principal ADA = new Principal("ada", Set.of(Role.ADMIN), true);
    private static final Principal RAY = new Principal("ray", Set.of(Role.ADMIN), true);

    private static LabSession session;
    private static FakeRoutes routes;

    @BeforeAll
    static void open() throws Exception {
        session = LabSession.open(LabConfig.defaults(Files.createTempDirectory("dwarpal-adminlab")).withPort(0)
                .withUsers(30).withWarmupDays(1));
        session.runner().pause();
        routes = FakeRoutes.of(new AdminModule(new LabAdminServices(session)));
    }

    @AfterAll
    static void close() {
        session.close();
    }

    private static String body(String yaml) {
        return "{\"yaml\":" + JsonWriter.write(JsonValue.str(yaml)) + "}";
    }

    @Test
    void anInstalledPolicyChangesWhatTheLabDecidesAndTheLabShowsWhoApprovedIt() throws Exception {
        String current = text(json(routes.call("GET", "policy", ADA, "")).get("version").orElseThrow());
        assertEquals("2026.11.03-1", current);
        String yaml;
        try (var in = dev.dwarpal.sim.SimRequests.class.getResourceAsStream("/policies/default-policy.yaml")) {
            yaml = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).replace("2026.11.03-1", "2026.11.06-7");
        }
        String id = text(json(routes.call("POST", "policy/propose", ADA, body(yaml))).get("id").orElseThrow());
        assertEquals(200, routes.call("POST", "proposals/" + id + "/approve", ADA, "").status());
        assertEquals(200, routes.call("POST", "proposals/" + id + "/approve", RAY, "").status());
        JsonValue.JObject done = json(routes.call("POST", "proposals/" + id + "/install", ADA, ""));
        assertEquals(JsonValue.bool(true), done.get("installed").orElseThrow(), done.toString());
        assertEquals(1, session.world().policies.currentSequence());

        // a request decided after the install carries the new policy version in the chain
        Thread.sleep(1_100);
        session.scenarios().launch(session.world(), "A5", "tester", false);
        session.fastForward(Duration.ofMinutes(5));
        assertTrue(session.world().org.sink.snapshot().stream().anyMatch(r -> r.type().equals("ACCESS_DECISION")
                && r.payloadJson().contains("2026.11.06-7")), "the lab decides under the installed policy");
        Response mine = routes.call("GET", "policy", ADA, "");
        assertTrue(mine.body().contains("POLICY_INSTALLED"), "the change and its approvers are in the history");
    }

    @Test
    void sessionsDevicesAndPrivilegedAccessWorkOnTheRealComponents() {
        assertTrue(((JsonValue.JArray) json(routes.call("GET", "sessions", ADA, "")).get("sessions").orElseThrow()).size() > 0);
        assertTrue(((JsonValue.JArray) json(routes.call("GET", "devices", ADA, "")).get("devices").orElseThrow()).size() > 0);
        String req = "{\"role\":\"prod-admin\",\"minutes\":30,\"justification\":\"rotate the certificates\"}";
        JsonValue.JObject made = json(routes.call("POST", "pam/request", ADA, req));
        assertEquals(JsonValue.bool(true), made.get("ok").orElseThrow(), made.toString());
        String reqId = text(made.get("id").orElseThrow());
        assertEquals(JsonValue.bool(false), json(routes.call("POST", "pam/approve/" + reqId, ADA, "")).get("ok").orElseThrow());
        JsonValue.JObject granted = json(routes.call("POST", "pam/approve/" + reqId, RAY, ""));
        assertEquals(JsonValue.bool(true), granted.get("ok").orElseThrow(), granted.toString());
        assertFalse(session.world().pam.activeRoles("ada", session.world().now()).isEmpty());
        assertEquals(200, routes.call("POST", "pam/revoke/" + text(granted.get("id").orElseThrow()), RAY, "{}").status());
        assertTrue(session.world().pam.activeRoles("ada", session.world().now()).isEmpty());
    }

    @Test
    void anOrdinaryPersonSeesTheirOwnDecisionsInTheRequestersWords() {
        var rows = Decisions.rows(new LabAdminServices(session).recentAudit(50_000));
        Decisions.Row any = rows.getFirst();
        Principal me = new Principal(any.subject(), Set.of(Role.USER), false);
        String list = routes.call("GET", "me/decisions", me, "").body();
        assertTrue(list.contains("Reference: ") || list.contains("Access granted."));
        assertFalse(list.contains(any.policy()) && !any.policy().isBlank());
    }

    @Test
    void hostileFilesAreRefusedAndNeverKept() {
        List<String> attacks = List.of("!!java.lang.ProcessBuilder [calc]", "a: &a [x, x]\nb: *a\n", "[".repeat(5_000),
                "version: x\nversion: y\n", "\u0000\u0001", "default: DENY\n");
        for (String a : attacks) {
            Response p = routes.call("POST", "policy/propose", ADA, body(a));
            if (p.status() == 400) {
                continue;       // refused before it was even read (a control character is not valid JSON text)
            }
            assertEquals(200, p.status());
            assertEquals(JsonValue.bool(false), json(p).get("linted").orElseThrow(), a.substring(0, Math.min(20, a.length())));
            assertFalse(p.body().contains("ProcessBuilder") && p.body().contains("Exception"), p.body());
            Response q = routes.call("POST", "playbooks/propose", ADA, body(a));
            assertEquals(200, q.status());
            assertEquals(JsonValue.bool(false), json(q).get("linted").orElseThrow());
        }
        assertEquals(0, ((JsonValue.JArray) json(routes.call("GET", "proposals", ADA, "")).get("proposals").orElseThrow()).size());
    }
}

package dev.dwarpal.console;

import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import dev.dwarpal.console.admin.AdminModule;
import dev.dwarpal.console.admin.LabAdminServices;
import dev.dwarpal.console.lab.LabModule;
import dev.dwarpal.lab.LabConfig;
import dev.dwarpal.lab.scenarios.LabSession;
import dev.dwarpal.wire.JsonValue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Five administrator actions (request, approve and revoke privileged access, and the two lab resets) need an open elevation
 * and no fresh password, PIN or single-use passkey; the three that change what the engine enforces or use a signing key keep
 * their fresh proof. On the real console server and the real admin and lab modules.
 */
class AdminElevationTest {

    private static final String PASSKEY = "admin-elevation-passkey";
    private static final String PAM_REQUEST = "{\"role\":\"prod-admin\",\"minutes\":30,\"justification\":\"deploy the fix for ticket 42\"}";

    private static LabSession lab;
    private ConsoleFixture f;

    @BeforeAll
    static void openLab() throws Exception {
        lab = LabSession.open(LabConfig.defaults(Files.createTempDirectory("dwarpal-admin-elevation")).withPort(0).withUsers(30)
                .withWarmupDays(1));
        lab.runner().pause();
    }

    @AfterAll
    static void closeLab() {
        lab.close();
    }

    @BeforeEach
    void start() throws Exception {
        f = ConsoleFixture.start(b -> b.module(new LabModule(lab)).module(new AdminModule(new LabAdminServices(lab))),
                ConsoleSettings.defaults().fastHashing());
    }

    @AfterEach
    void stop() {
        if (f != null) f.close();
    }

    private Sess signedIn(String id) throws Exception {
        Sess s = f.login(id);
        ConsoleAuth.Enrolment e = f.person(id);
        assertEquals(200, f.post("/console/api/profile/passkey", s, "{\"password\":\"" + e.password() + "\",\"pin\":\""
                + e.pin() + "\",\"passkey\":\"" + PASSKEY + "\"}").status());
        return s;
    }

    private Resp elevate(Sess s) throws Exception {
        return f.post("/console/api/session/elevate", s, "{\"pin\":\"" + f.person(s.user()).pin() + "\",\"passkey\":\"" + PASSKEY
                + "\",\"reason\":\"administering the lab\"}");
    }

    private String elevationId(Sess s) throws Exception {
        JsonValue.JObject e = (JsonValue.JObject) ((JsonValue.JObject) f.get("/console/api/me", s).json()).get("elevation").orElseThrow();
        return ((JsonValue.JString) e.get("id").orElseThrow()).value();
    }

    private List<AuditRecord> since(long seq) {
        return f.world.org.sink.snapshot().stream().filter(r -> r.sequence() > seq).toList();
    }

    /** The host's records of the write with this route fragment, in order. */
    private static List<AuditRecord> writes(List<AuditRecord> records, String route) {
        return records.stream().filter(r -> r.type().equals("CONSOLE_WRITE") && r.payloadJson().contains(route)
                && r.payloadJson().contains("\"phase\":\"result\"")).toList();
    }

    /**
     * The whole rule for one route: refused with 423 outside an elevation and nothing done; works inside one without a fresh
     * step-up, under the elevation's id; refused again once the ten minutes are over.
     */
    private void exercise(String path, String route, String body, int insideStatus, String insideText) throws Exception {
        Sess dana = signedIn("dana");
        long before = f.world.org.audit.head().sequence();
        long generation = lab.generation();
        int pending = lab.world().pam.pendingRequests().size();

        Resp refused = f.post(path, dana, body);
        assertEquals(423, refused.status(), refused.body());
        assertTrue(refused.body().contains("elevation required"), refused.body());
        assertEquals(generation, lab.generation(), "the lab was not reset");
        assertEquals(pending, lab.world().pam.pendingRequests().size(), "nothing was requested");
        List<AuditRecord> first = writes(since(before), route);
        assertFalse(first.isEmpty(), "the refusal is on the trail");
        assertTrue(first.stream().allMatch(r -> r.payloadJson().contains("\"status\":\"423\"")), "nothing was recorded as done");
        assertTrue(first.stream().noneMatch(r -> r.payloadJson().contains("\"elevation\"")), "and no elevation is named");

        assertEquals(200, elevate(dana).status());
        String id = elevationId(dana);
        long mark = f.world.org.audit.head().sequence();
        Resp done = f.post(path, dana, body);
        assertEquals(insideStatus, done.status(), done.body());
        assertTrue(done.body().contains(insideText), done.body());
        List<AuditRecord> inside = writes(since(mark), route);
        assertFalse(inside.isEmpty());
        assertTrue(inside.stream().allMatch(r -> r.payloadJson().contains("\"elevation\":\"" + id + "\"")
                && r.payloadJson().contains("\"status\":\"" + insideStatus + "\"")), inside.toString());

        f.clock.advance(Duration.ofMinutes(10).plusSeconds(1));
        long late = f.world.org.audit.head().sequence();
        Resp closed = f.post(path, dana, body);
        assertEquals(423, closed.status(), closed.body());
        assertTrue(closed.body().contains("elevation required"));
        assertTrue(writes(since(late), route).stream().allMatch(r -> r.payloadJson().contains("\"status\":\"423\"")));
    }

    @Test
    void requestingPrivilegedAccessNeedsAnOpenElevationAndNoFreshProof() throws Exception {
        exercise("/console/api/admin/pam/request", "pam/request", PAM_REQUEST, 200, "\"ok\"");
    }

    @Test
    void approvingPrivilegedAccessNeedsAnOpenElevationAndNoFreshProof() throws Exception {
        exercise("/console/api/admin/pam/approve/none", "pam/approve", "{}", 404, "no such open request");
    }

    @Test
    void revokingPrivilegedAccessNeedsAnOpenElevationAndNoFreshProof() throws Exception {
        exercise("/console/api/admin/pam/revoke/none", "pam/revoke", "{}", 404, "no such grant");
    }

    @Test
    void theAdminPagesLabResetNeedsAnOpenElevationAndNoFreshProof() throws Exception {
        exercise("/console/api/admin/lab/reset", "lab/reset", "{}", 200, "reset");
    }

    @Test
    void theLabPagesResetNeedsAnOpenElevationAndNoFreshProof() throws Exception {
        exercise("/console/api/lab/control/reset", "control/reset", "{}", 200, "state");
    }

    @Test
    void theThreeKeptActionsStillNeedAFreshStepUpWhateverElevationIsOpen() throws Exception {
        Sess dana = signedIn("dana");
        assertEquals(200, elevate(dana).status());
        f.clock.advance(Duration.ofMinutes(6));        // the sign-in proof is stale, the elevation (ten minutes) is not
        for (String p : List.of("/console/api/admin/proposals/x/approve", "/console/api/admin/proposals/x/install",
                "/console/api/admin/pam/review/x")) {
            Resp r = f.post(p, dana, "{\"verdict\":\"justified\"}");
            assertEquals(403, r.status(), p + " " + r.body());
            assertTrue(r.body().contains("step-up required"), r.body());
        }
        Sess fresh = f.stepUp(dana);
        for (String p : List.of("/console/api/admin/proposals/x/approve", "/console/api/admin/proposals/x/install")) {
            assertEquals(404, f.post(p, fresh, "{}").status(), p + ": with the fresh proof it reaches the handler");
        }
    }

    @Test
    void anAnalystInsideNothingIsStillRefusedAndCannotElevate() throws Exception {
        Sess ana = signedIn("ana");
        for (String p : List.of("/console/api/admin/pam/request", "/console/api/admin/pam/approve/x", "/console/api/admin/pam/revoke/x",
                "/console/api/admin/lab/reset", "/console/api/lab/control/reset")) {
            int s = f.post(p, ana, "{}").status();
            assertTrue(s == 403 || s == 404, p + " answered " + s);
            assertNotEquals(423, s, p);
        }
        assertEquals(403, elevate(ana).status());
    }
}

package dev.dwarpal.console;

import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import dev.dwarpal.console.access.AccessApi;
import dev.dwarpal.console.access.AccessModule;
import dev.dwarpal.directory.Access;
import dev.dwarpal.directory.CredentialLifecycle;
import dev.dwarpal.directory.PostgresAccess;
import dev.dwarpal.directory.PostgresDirectory;
import dev.dwarpal.directory.TestDatabase;
import dev.dwarpal.wire.JsonValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An elevation on the real console server: the privileged decisions of the access process need the PIN, the passkey and a
 * reason; the elevation lasts ten REAL minutes (the scenario clock is not involved), shows its time left, can be ended by the
 * person, belongs to one session, and everything done inside it is written under its identifier.
 */
class ElevationEndToEndTest {

    private static final String PASSKEY = "elevation-test-passkey";

    private ConsoleFixture f;
    private PostgresAccess access;
    private PostgresDirectory directory;

    @BeforeEach
    void start() throws Exception {
        TestDatabase.require();
        TestDatabase.reset();
        directory = new PostgresDirectory(TestDatabase.app());
        access = new PostgresAccess(TestDatabase.app());
        AccessApi api = new AccessApi(access, directory, CredentialLifecycle.NONE);
        f = ConsoleFixture.start(b -> b.module(new AccessModule(api)), ConsoleSettings.defaults().fastHashing());
        DirectoryPeople.sync(directory, f.people, Clock.systemUTC());
    }

    @AfterEach
    void stop() {
        f.close();
    }

    /** Signs in and gives the person a passkey, as the profile page does. */
    private Sess withPasskey(String id) throws Exception {
        Sess s = f.login(id);
        ConsoleAuth.Enrolment e = f.person(id);
        assertEquals(200, f.post("/console/api/profile/passkey", s, "{\"password\":\"" + e.password() + "\",\"pin\":\""
                + e.pin() + "\",\"passkey\":\"" + PASSKEY + "\"}").status());
        return s;
    }

    private Resp elevate(Sess s, String pin, String passkey, String reason) throws Exception {
        return f.post("/console/api/session/elevate", s, "{\"pin\":\"" + pin + "\",\"passkey\":\"" + passkey + "\",\"reason\":\""
                + reason + "\"}");
    }

    private Resp elevateRight(Sess s, String reason) throws Exception {
        return elevate(s, f.person(s.user()).pin(), PASSKEY, reason);
    }

    /** A hard grant that waits for the administrator and a lead. */
    private String waiting(String item) {
        Access.AccessResult r = access.requestAccess("uma", Set.of(item), "needed for the month end");
        return r.grants().getFirst().id();
    }

    private Resp decide(Sess s, String grant) throws Exception {
        return f.post("/console/api/access/approvals/" + grant + "/decision", s, "{\"approve\":true,\"reason\":\"checked\"}");
    }

    private JsonValue.JObject elevationOf(Sess s) throws Exception {
        return (JsonValue.JObject) ((JsonValue.JObject) f.get("/console/api/me", s).json()).get("elevation").orElseThrow();
    }

    private boolean open(Sess s) throws Exception {
        return ((JsonValue.JBool) elevationOf(s).get("open").orElseThrow()).value();
    }

    private List<AuditRecord> since(long seq) {
        return f.world.org.sink.snapshot().stream().filter(r -> r.sequence() > seq).toList();
    }

    // ---- the elevation is asked for, given and used -------------------------------------------------------------------------

    @Test
    void aLeadsDecisionAsksForAnElevationAndWorksInsideOne() throws Exception {
        Sess cleo = withPasskey("cleo");
        String grant = waiting("finance");
        Resp refused = decide(cleo, grant);
        assertEquals(423, refused.status(), refused.body());
        assertTrue(refused.body().contains("elevation required"));
        assertFalse(open(cleo));

        long before = f.world.org.audit.head().sequence();
        Resp started = elevateRight(cleo, "approving the finance request for uma");
        assertEquals(200, started.status(), started.body());
        assertTrue(open(cleo));
        long left = ((JsonValue.JNumber) elevationOf(cleo).get("seconds").orElseThrow()).asLong();
        assertTrue(left > 590 && left <= 600, "ten real minutes, counted down for the footer: " + left);

        Resp done = decide(cleo, grant);
        assertEquals(200, done.status(), done.body());

        String id = ((JsonValue.JString) elevationOf(cleo).get("id").orElseThrow()).value();
        List<AuditRecord> written = since(before);
        AuditRecord startRecord = written.stream().filter(r -> r.type().equals("ELEVATION_STARTED")).findFirst().orElseThrow();
        assertEquals("cleo", startRecord.actor());
        assertTrue(startRecord.payloadJson().contains(id) && startRecord.payloadJson().contains("approving the finance request for uma"));
        assertTrue(startRecord.payloadJson().contains("\"real\""), "with the real time it started");
        assertFalse(startRecord.payloadJson().contains(PASSKEY) || startRecord.payloadJson().contains(f.person("cleo").pin()),
                "neither secret is ever written");
        AuditRecord approved = written.stream().filter(r -> r.type().equals("ACCESS_APPROVED")).findFirst().orElseThrow();
        assertEquals("cleo", approved.actor());
        assertTrue(approved.payloadJson().contains(id) && approved.payloadJson().contains("\"elevationReason\"")
                && approved.payloadJson().contains("\"before\"") && approved.payloadJson().contains("\"after\""), approved.payloadJson());
        assertTrue(written.stream().anyMatch(r -> r.type().equals("CONSOLE_WRITE") && r.payloadJson().contains("\"elevation\":\"" + id + "\"")),
                "the host's own record of the write names the elevation too");
    }

    @Test
    void theElevationClosesByItselfAfterTenRealMinutesAndTheCloseIsRecorded() throws Exception {
        Sess cleo = withPasskey("cleo");
        String first = waiting("finance");
        String second = waiting("prod-db");
        assertEquals(200, elevateRight(cleo, "approving the requests of the month end").status());
        assertEquals(200, decide(cleo, first).status());
        String id = ((JsonValue.JString) elevationOf(cleo).get("id").orElseThrow()).value();
        long before = f.world.org.audit.head().sequence();

        f.clock.advance(Duration.ofMinutes(5));
        assertTrue(open(cleo), "five minutes in, it is still open");
        f.clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        assertFalse(open(cleo), "ten real minutes later it is closed, whatever the lab's scenario clock says");
        Resp late = decide(cleo, second);
        assertEquals(423, late.status(), late.body());
        assertTrue(access.grantsOf("uma").stream().anyMatch(g -> g.id().equals(second) && g.state().name().equals("PENDING")),
                "the second request was not touched");

        f.server.closeElevations();
        AuditRecord ended = since(before).stream().filter(r -> r.type().equals("ELEVATION_ENDED")).findFirst().orElseThrow();
        assertTrue(ended.payloadJson().contains(id) && ended.payloadJson().contains("time ran out"), ended.payloadJson());
        f.server.closeElevations();
        assertEquals(1, since(before).stream().filter(r -> r.type().equals("ELEVATION_ENDED")).count(), "written once");
    }

    @Test
    void thePersonCanEndItAtOnceAndThenTheNextDecisionAsksAgain() throws Exception {
        Sess cleo = withPasskey("cleo");
        String grant = waiting("finance");
        assertEquals(200, elevateRight(cleo, "approving the finance request").status());
        long before = f.world.org.audit.head().sequence();
        assertEquals(200, f.post("/console/api/session/elevate/end", cleo, "{}").status());
        assertFalse(open(cleo));
        assertEquals(423, decide(cleo, grant).status());
        AuditRecord ended = since(before).stream().filter(r -> r.type().equals("ELEVATION_ENDED")).findFirst().orElseThrow();
        assertTrue(ended.payloadJson().contains("ended by the person"));
        assertEquals(200, f.post("/console/api/session/elevate/end", cleo, "{}").status(), "ending nothing is harmless");
    }

    @Test
    void aWrongPinOrPasskeyOrNoReasonGivesNoElevationAndTheAnswerDoesNotSayWhich() throws Exception {
        Sess cleo = withPasskey("cleo");
        Resp wrongPin = elevate(cleo, "000000x", PASSKEY, "approving the finance request");
        Resp wrongKey = elevate(cleo, f.person("cleo").pin(), "not-the-passkey", "approving the finance request");
        assertEquals(401, wrongPin.status());
        assertEquals(401, wrongKey.status());
        assertEquals(wrongPin.body(), wrongKey.body(), "the same words for either");
        assertEquals(400, elevate(cleo, f.person("cleo").pin(), PASSKEY, "ok").status(), "a reason of five characters or more");
        assertEquals(400, elevate(cleo, f.person("cleo").pin(), PASSKEY, "x".repeat(250)).status());
        assertFalse(open(cleo));
        assertTrue(f.world.org.sink.snapshot().stream().anyMatch(r -> r.type().equals("ELEVATION_FAILED") && r.actor().equals("cleo")));
    }

    @Test
    void onlyAdministratorsAndLeadsCanBeElevatedAndAnElevationBelongsToItsSession() throws Exception {
        Sess uma = f.login("uma");
        assertEquals(403, f.post("/console/api/session/elevate", uma, "{\"pin\":\"abcdef\",\"passkey\":\"abcdefghij\",\"reason\":\"let me in\"}").status());
        Sess ana = withPasskey("ana");
        assertEquals(403, elevateRight(ana, "an analyst has no privileged actions").status());

        Sess cleo = withPasskey("cleo");
        assertEquals(200, elevateRight(cleo, "approving the finance request").status());
        Sess other = f.login("cleo");
        assertFalse(open(other), "a second sign-in of the same person is not elevated");
        Sess fresh = f.stepUp(cleo);
        assertTrue(open(fresh), "a fresh password and PIN keep the session, and its elevation");
        assertNotEquals(cleo.cookie(), fresh.cookie());
    }

    @Test
    void aLeadsApprovalMakesAGrantedRoleRealAtOnceAndEndsTheOldSession() throws Exception {
        Sess uma = f.login("uma");
        assertEquals(200, f.get("/console/api/me", uma).status());
        String grant = waiting("console-analyst");
        access.decide("dana", "ADMIN", grant, true, "ok");
        Sess cleo = withPasskey("cleo");
        assertEquals(200, elevateRight(cleo, "approving umas analyst access").status());
        assertEquals(200, decide(cleo, grant).status());

        assertEquals(401, f.get("/console/api/me", uma).status(), "her old session ended, so the new role is real when she signs in");
        Sess again = f.login("uma");
        String me = f.get("/console/api/me", again).body();
        assertTrue(me.contains("ANALYST") && me.contains("USER"), me);
    }

    // ---- the passkey check is one function --------------------------------------------------------------------------------------

    @Test
    void anotherWayOfProvingThePasskeyReplacesTheTypedOneWithoutTouchingTheCallers() throws Exception {
        f.close();
        AccessApi api = new AccessApi(access, directory, CredentialLifecycle.NONE);
        ConsoleAuth.Person cleo = f.person("cleo").person();
        PasskeyStepUp device = (personId, evidence, source) -> personId.equals("cleo") && evidence.equals("device-answer")
                ? new ConsoleAuth.Authenticated(ConsoleAuth.Status.OK, cleo, 0, personId)
                : new ConsoleAuth.Authenticated(ConsoleAuth.Status.FAILED, null, 0, personId);
        f = ConsoleFixture.start(b -> b.module(new AccessModule(api)).passkeyStepUp(device)
                .passkeyLock(Duration.ofMinutes(15), Duration.ofMinutes(5)), ConsoleSettings.defaults().fastHashing());
        DirectoryPeople.sync(directory, f.people, Clock.systemUTC());
        Sess s = f.login("cleo");
        assertEquals(401, elevate(s, f.person("cleo").pin(), PASSKEY, "approving the finance request").status());
        assertEquals(200, elevate(s, f.person("cleo").pin(), "device-answer", "approving the finance request").status());
        assertEquals(401, f.post("/console/api/session/unlock", s, "{\"passkey\":\"" + PASSKEY + "\",\"scope\":\"window\"}").status());
        assertEquals(200, f.post("/console/api/session/unlock", s, "{\"passkey\":\"device-answer\",\"scope\":\"window\"}").status(),
                "the unlock route asks the same function");
    }
}

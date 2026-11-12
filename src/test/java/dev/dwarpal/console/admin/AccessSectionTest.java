package dev.dwarpal.console.admin;

import dev.dwarpal.console.ConsoleModule;
import dev.dwarpal.console.ConsoleModule.Principal;
import dev.dwarpal.console.ConsoleModule.Response;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.console.access.AccessApi;
import dev.dwarpal.console.access.AccessModule;
import dev.dwarpal.console.lab.FakeRoutes;
import dev.dwarpal.directory.CredentialLifecycle;
import dev.dwarpal.directory.DirectoryPerson;
import dev.dwarpal.directory.PostgresAccess;
import dev.dwarpal.directory.PostgresDirectory;
import dev.dwarpal.directory.TestDatabase;
import dev.dwarpal.wire.JsonValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static dev.dwarpal.console.lab.FakeRoutes.json;
import static dev.dwarpal.console.lab.FakeRoutes.text;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The access process through the console's routes, as each person would call them: the roles are checked strictly
 * (an administrator is not a lead, HR is nobody's approver), every change reaches the audit trail, a leaver's sessions
 * are ended, and a refusal says why and changes nothing.
 */
class AccessSectionTest {

    private static final Principal HR = new Principal("hana", Set.of(Role.HR), true);
    /** The decisions of an administrator and of a lead are made inside an elevation (PIN, passkey and a reason). */
    private static final ConsoleModule.Elevation ELEVATION = new ConsoleModule.Elevation("elv-test", "testing the access process",
            Instant.parse("2099-01-01T00:00:00Z"));
    private static final Principal ADMIN = new Principal("dana", Set.of(Role.ADMIN), true, ELEVATION);
    private static final Principal ADMIN_NOT_ELEVATED = new Principal("dana", Set.of(Role.ADMIN), true);
    private static final Principal LEAD = new Principal("cleo", Set.of(Role.LEAD, Role.ANALYST), true, ELEVATION);
    private static final Principal LEAD_NOT_ELEVATED = new Principal("cleo", Set.of(Role.LEAD, Role.ANALYST), true);
    private static final Principal ANALYST = new Principal("ana", Set.of(Role.ANALYST), true);
    private static final Principal USER = new Principal("uma", Set.of(Role.USER), true);

    /** What the console would do for the module: it records the audit records and the accounts it was told to close. */
    private static final class RecordingHost implements ConsoleModule.Host {
        final List<String[]> audits = new ArrayList<>();
        final List<String> closed = new ArrayList<>();
        final List<String> rolesChanged = new ArrayList<>();
        boolean trailWorks = true;

        @Override
        public boolean audit(String type, String person, Map<String, String> fields) {
            audits.add(new String[]{type, person, fields.toString()});
            return trailWorks;
        }

        @Override
        public void closeAccount(String personId) {
            closed.add(personId);
        }

        @Override
        public void rolesChanged(String personId, Set<String> roles) {
            rolesChanged.add(personId + ":" + String.join(",", new java.util.TreeSet<>(roles)));
        }

        long count(String type) {
            return audits.stream().filter(a -> a[0].equals(type)).count();
        }
    }

    private RecordingHost host;
    private final List<String> created = new ArrayList<>();
    private final List<String> removed = new ArrayList<>();
    private FakeRoutes admin;
    private FakeRoutes access;
    private PostgresDirectory directory;
    private AdminFixture fx;

    @BeforeEach
    void build() {
        TestDatabase.require();
        TestDatabase.reset();
        directory = new PostgresDirectory(TestDatabase.app());
        seed("hana", "Human Resources", "HR officer", "HR");
        seed("dana", "IT Security", "Administrator", "ADMIN");
        seed("spector", "Administration", "Administrator", "ADMIN");
        seed("cleo", "SOC", "SOC lead", "ANALYST", "LEAD");
        seed("ana", "SOC", "Security analyst", "ANALYST");
        seed("uma", "Finance", "Finance officer", "USER");
        AccessApi api = new AccessApi(new PostgresAccess(TestDatabase.app()), directory, new CredentialLifecycle() {
            @Override
            public void personCreated(String personId) {
                created.add(personId);
            }

            @Override
            public void personRemoved(String personId) {
                removed.add(personId);
            }
        });
        host = new RecordingHost();
        fx = new AdminFixture();
        fx.access = api;
        AdminModule adminModule = new AdminModule(fx);
        adminModule.attach(host);
        admin = FakeRoutes.of(adminModule);
        AccessModule module = new AccessModule(api);
        module.attach(host);
        access = FakeRoutes.of(module);
    }

    private void seed(String id, String dept, String job, String... roles) {
        directory.addIfAbsent(new DirectoryPerson(id, "Name of " + id, dept, job, DirectoryPerson.Status.ACTIVE,
                DirectoryPerson.Source.SEED, Instant.parse("2026-11-01T09:00:00Z"), Set.of(roles)));
    }

    private String joinerBody(String id) {
        return "{\"id\":\"" + id + "\",\"name\":\"Priya Nair\",\"department\":\"Engineering\",\"businessRole\":\"Software engineer\","
                + "\"reason\":\"starts on Monday\"}";
    }

    private static String requestId(Response r) {
        return text(((JsonValue.JObject) json(r).get("request").orElseThrow()).get("id").orElseThrow());
    }

    private static List<String> ids(JsonValue.JArray items) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < items.size(); i++) {
            out.add(text(((JsonValue.JObject) items.get(i)).get("id").orElseThrow()));
        }
        return out;
    }

    private static List<String> grantIds(Response r, String state) {
        List<String> out = new ArrayList<>();
        JsonValue.JArray grants = (JsonValue.JArray) json(r).get("grants").orElseThrow();
        for (int i = 0; i < grants.size(); i++) {
            JsonValue.JObject g = (JsonValue.JObject) grants.get(i);
            if (text(g.get("state").orElseThrow()).equals(state)) {
                out.add(text(g.get("id").orElseThrow()));
            }
        }
        return out;
    }

    // ---- joiner ------------------------------------------------------------------------------------------------------

    @Test
    void hrAsksTheAdministratorTicksAndSavesAndEveryGrantIsAudited() {
        Response asked = access.call("POST", "hr/joiner", HR, joinerBody("priya"));
        assertEquals(200, asked.status(), asked.body());
        String id = requestId(asked);
        assertTrue(directory.find("priya").isEmpty(), "nothing exists until the administrator saves");

        Response queue = admin.call("GET", "access/queue", ADMIN, "");
        assertEquals(200, queue.status(), queue.body());
        assertTrue(queue.body().contains(id) && queue.body().contains("Software engineer"));
        assertTrue(queue.body().contains("\"templates\""), "the role's usual items come with the queue, to be pre-ticked");

        Response saved = admin.call("POST", "access/joiners/" + id + "/save", ADMIN, "{\"items\":[\"email\",\"console\",\"finance\"]}");
        assertEquals(200, saved.status(), saved.body());
        assertEquals(2, grantIds(saved, "ACTIVE").size());
        assertEquals(1, grantIds(saved, "PENDING").size());
        assertEquals(0, json(saved).get("auditFailures").map(v -> ((JsonValue.JNumber) v).asLong()).orElseThrow());
        assertEquals(1, host.count("ACCESS_PERSON_ADDED"));
        assertEquals(2, host.count("ACCESS_GRANTED"));
        assertEquals(1, host.count("ACCESS_PENDING"));
        assertTrue(host.audits.stream().allMatch(a -> a[0].startsWith("ACCESS_") && !a[2].toLowerCase(java.util.Locale.ROOT).contains("password")));
        assertEquals(List.of("priya"), created, "the credential side hears that a person appeared");
        assertEquals(DirectoryPerson.Status.ACTIVE, directory.find("priya").orElseThrow().status());
    }

    @Test
    void aSensitiveItemNeedsTheAdministratorAndALeadAndTheLeadSeesItInTheirOwnList() {
        String id = requestId(access.call("POST", "hr/joiner", HR, joinerBody("priya")));
        Response saved = admin.call("POST", "access/joiners/" + id + "/save", ADMIN, "{\"items\":[\"email\",\"finance\"]}");
        String finance = grantIds(saved, "PENDING").getFirst();

        Response waiting = access.call("GET", "approvals", LEAD, "");
        assertEquals(200, waiting.status(), waiting.body());
        assertTrue(waiting.body().contains(finance) && waiting.body().contains("\"canDecide\":true"));
        assertTrue(admin.call("GET", "access/queue", ADMIN, "").body().contains("\"waiting\":[]"),
                "the administrator already approved it by saving: nothing waits for them");

        Response approved = access.call("POST", "approvals/" + finance + "/decision", LEAD, "{\"approve\":true}");
        assertEquals(200, approved.status(), approved.body());
        assertEquals(2, grantIds(approved, "ACTIVE").size(), "email and finance are active now");
        assertEquals(2, host.count("ACCESS_GRANTED"), "email was granted when saved; finance when the lead approved");
    }

    @Test
    void aRefusedJoinerNeedsAReasonAndCreatesNothing() {
        String id = requestId(access.call("POST", "hr/joiner", HR, joinerBody("priya")));
        assertEquals(400, admin.call("POST", "access/joiners/" + id + "/reject", ADMIN, "{\"reason\":\"\"}").status());
        Response refused = admin.call("POST", "access/joiners/" + id + "/reject", ADMIN, "{\"reason\":\"no position approved\"}");
        assertEquals(200, refused.status(), refused.body());
        assertTrue(directory.find("priya").isEmpty());
        assertEquals(1, host.count("ACCESS_REJECTED"));
        assertEquals(409, admin.call("POST", "access/joiners/" + id + "/save", ADMIN, "{\"items\":[\"email\"]}").status());
        assertTrue(created.isEmpty(), "nobody was created, so the credential side hears nothing");
    }

    // ---- roles are strict -----------------------------------------------------------------------------------------------

    @Test
    void everyRouteRefusesTheRolesThatAreNotItsOwn() {
        String id = requestId(access.call("POST", "hr/joiner", HR, joinerBody("priya")));
        assertEquals(403, access.call("POST", "hr/joiner", ANALYST, joinerBody("zed")).status());
        assertEquals(403, access.call("POST", "hr/joiner", ADMIN, joinerBody("zed")).status());
        assertEquals(403, access.call("POST", "hr/leaver", ADMIN, "{\"id\":\"uma\",\"reason\":\"x\"}").status());
        assertEquals(403, access.call("GET", "hr", USER, "").status());
        assertEquals(403, access.call("GET", "hr", ADMIN, "").status());
        assertEquals(403, access.call("GET", "approvals", ADMIN, "").status(), "an administrator is not a lead");
        assertEquals(403, access.call("GET", "approvals", ANALYST, "").status());
        assertEquals(403, access.call("GET", "approvals", HR, "").status());
        assertEquals(403, admin.call("GET", "access/queue", HR, "").status());
        assertEquals(403, admin.call("GET", "access/queue", LEAD, "").status());
        assertEquals(403, admin.call("POST", "access/joiners/" + id + "/save", HR, "{\"items\":[\"email\"]}").status());
        assertEquals(403, admin.call("POST", "access/joiners/" + id + "/save", LEAD, "{\"items\":[\"email\"]}").status());
        assertEquals(403, admin.call("POST", "access/approvals/x/decision", LEAD, "{\"approve\":true}").status());
        assertEquals(403, access.call("POST", "approvals/x/decision", ADMIN, "{\"approve\":true}").status());
        assertTrue(directory.find("priya").isEmpty(), "none of that changed anything");
    }

    @Test
    void hrAsksForAFreshSecondFactorAndTheDecisionsAskForAnElevationInstead() {
        for (String r : List.of("hr/joiner", "hr/leaver")) {
            assertTrue(access.route("POST", r).stepUp(), r);
        }
        // HR holds no passkey, so it keeps the password and PIN; a decision on access is made inside an elevation
        assertFalse(access.route("POST", "approvals/{}/decision").stepUp(), "the lead's decision asks for an elevation");
        for (String r : List.of("access/joiners/{}/save", "access/joiners/{}/reject", "access/approvals/{}/decision",
                "access/privileged", "access/privileged/{}/decision")) {
            assertFalse(admin.route("POST", r).stepUp(), r + " asks for an elevation, not for a password");
        }
        assertFalse(access.route("POST", "request").stepUp(), "asking for more access for oneself is not privileged");
    }

    @Test
    void withoutAnElevationEveryDecisionIsRefusedAndChangesNothing() {
        String id = requestId(access.call("POST", "hr/joiner", HR, joinerBody("priya")));
        Response noSave = admin.call("POST", "access/joiners/" + id + "/save", ADMIN_NOT_ELEVATED, "{\"items\":[\"email\"]}");
        assertEquals(423, noSave.status(), noSave.body());
        assertTrue(noSave.body().contains("elevation required"));
        assertEquals(423, admin.call("POST", "access/joiners/" + id + "/reject", ADMIN_NOT_ELEVATED, "{\"reason\":\"no\"}").status());
        assertEquals(423, admin.call("POST", "access/privileged", ADMIN_NOT_ELEVATED,
                "{\"change\":\"ADD_ADMIN\",\"target\":\"uma\",\"reason\":\"x\"}").status());
        assertEquals(423, admin.call("POST", "access/privileged/x/decision", ADMIN_NOT_ELEVATED, "{\"approve\":true}").status());
        assertEquals(423, admin.call("POST", "access/approvals/x/decision", ADMIN_NOT_ELEVATED, "{\"approve\":true}").status());
        assertEquals(423, access.call("POST", "approvals/x/decision", LEAD_NOT_ELEVATED, "{\"approve\":true}").status());
        assertTrue(directory.find("priya").isEmpty(), "nothing was created");
        assertEquals(1, host.count("ACCESS_REQUESTED"), "and nothing was recorded but HR's own request");
        assertEquals(403, access.call("POST", "approvals/x/decision", USER, "{\"approve\":true}").status(),
                "a person with the wrong role is told no before the elevation is even mentioned");
    }

    @Test
    void everyRecordOfAnElevatedActionNamesTheElevationAndItsReason() {
        String id = requestId(access.call("POST", "hr/joiner", HR, joinerBody("priya")));
        host.audits.clear();
        Response saved = admin.call("POST", "access/joiners/" + id + "/save", ADMIN, "{\"items\":[\"email\",\"finance\"]}");
        assertEquals(200, saved.status(), saved.body());
        assertFalse(host.audits.isEmpty());
        for (String[] a : host.audits) {
            assertTrue(a[2].contains("elevation=elv-test") && a[2].contains("elevationReason=testing the access process"), a[0] + " " + a[2]);
            assertEquals("dana", a[1]);
        }
        assertTrue(host.audits.stream().anyMatch(a -> a[0].equals("ACCESS_PERSON_ADDED") && a[2].contains("before=no such person")
                && a[2].contains("after=ACTIVE")), "a change says what it was before and what it is after");
        host.audits.clear();
        String finance = grantIds(saved, "PENDING").getFirst();
        assertEquals(200, access.call("POST", "approvals/" + finance + "/decision", LEAD, "{\"approve\":true,\"reason\":\"checked\"}").status());
        for (String[] a : host.audits) {
            assertTrue(a[2].contains("elevation=elv-test") && a[1].equals("cleo"), a[0] + " " + a[2]);
        }
        assertTrue(host.audits.stream().anyMatch(a -> a[0].equals("ACCESS_GRANTED") && a[2].contains("before=PENDING") && a[2].contains("after=ACTIVE")));
        host.audits.clear();
        assertEquals(200, access.call("POST", "request", USER, "{\"items\":[\"vpn\"],\"reason\":\"work\"}").status());
        assertTrue(host.audits.stream().noneMatch(a -> a[2].contains("elevation=")), "a person who is not elevated leaves no elevation id");
    }

    // ---- more access --------------------------------------------------------------------------------------------------------

    @Test
    void anOrdinaryPersonAsksForMoreAndSimpleItemsAreAutomaticWhileHardOnesWaitForBothApprovers() {
        Response asked = access.call("POST", "request", USER, "{\"items\":[\"wiki\",\"finance\"],\"reason\":\"month end close\"}");
        assertEquals(200, asked.status(), asked.body());
        assertEquals(1, grantIds(asked, "ACTIVE").size());
        String finance = grantIds(asked, "PENDING").getFirst();

        Response mine = access.call("GET", "mine", USER, "");
        assertTrue(mine.body().contains("\"available\"") && mine.body().contains("month end close"));
        List<String> offered = ids((JsonValue.JArray) json(mine).get("available").orElseThrow());
        assertFalse(offered.contains("wiki") || offered.contains("finance"), "what is held or waiting is no longer offered: " + offered);
        assertTrue(offered.contains("vpn"));

        assertEquals(403, access.call("POST", "approvals/" + finance + "/decision", USER, "{\"approve\":true}").status());
        assertEquals(200, access.call("POST", "approvals/" + finance + "/decision", LEAD, "{\"approve\":true}").status());
        Response done = admin.call("POST", "access/approvals/" + finance + "/decision", ADMIN, "{\"approve\":true}");
        assertEquals(200, done.status(), done.body());
        assertEquals(2, grantIds(done, "ACTIVE").size(), "both approvals are in: now it is active");
    }

    @Test
    void aBadBodyIsRefusedWithoutTouchingAnything() {
        assertEquals(400, access.call("POST", "request", USER, "{\"items\":\"wiki\",\"reason\":\"x\"}").status());
        assertEquals(400, access.call("POST", "request", USER, "{\"items\":[1],\"reason\":\"x\"}").status());
        assertEquals(400, access.call("POST", "request", USER, "{\"items\":[\"wiki\"],\"reason\":\"x\",\"extra\":1}").status());
        assertEquals(400, access.call("POST", "request", USER, "{\"items\":[\"wiki\"]}").status());
        assertEquals(400, access.call("POST", "request", USER, "not json").status());
        assertEquals(400, access.call("POST", "request", USER, "{\"items\":[],\"reason\":\"x\"}").status());
        assertEquals(400, access.call("POST", "request", USER, "{\"items\":[\"root-shell\"],\"reason\":\"x\"}").status());
        assertEquals(400, access.call("POST", "hr/joiner", HR, joinerBody("x' OR '1'='1")).status());
        assertEquals(400, access.call("POST", "hr/joiner", HR, joinerBody("priya").replace("starts on Monday", "x".repeat(400))).status());
        assertEquals(400, access.call("POST", "approvals/x/decision", LEAD, "{\"reason\":\"no approve flag\"}").status());
        assertEquals(404, access.call("POST", "approvals/grt-nothing/decision", LEAD, "{\"approve\":true}").status());
        assertTrue(host.audits.isEmpty(), "nothing was recorded because nothing happened");
    }

    // ---- leaver ------------------------------------------------------------------------------------------------------------

    @Test
    void aLeaverIsRemovedAndTheConsoleIsToldToEndTheirSessionsAndShutTheDoor() {
        access.call("POST", "request", USER, "{\"items\":[\"wiki\",\"crm\"],\"reason\":\"work\"}");
        host.audits.clear();
        Response r = access.call("POST", "hr/leaver", HR, "{\"id\":\"uma\",\"reason\":\"last day was Friday\"}");
        assertEquals(200, r.status(), r.body());
        assertEquals(List.of("uma"), host.closed, "sessions end and sign-in is refused at once");
        assertEquals(List.of("uma"), removed, "the credential side hears that the person left");
        assertEquals(2, host.count("ACCESS_REMOVED"));
        assertEquals(1, host.count("ACCESS_PERSON_DISABLED"));
        assertEquals(DirectoryPerson.Status.DISABLED, directory.find("uma").orElseThrow().status());
        assertTrue(directory.find("uma").orElseThrow().consoleRoles().isEmpty());
        assertEquals(409, access.call("POST", "hr/leaver", HR, "{\"id\":\"uma\",\"reason\":\"again\"}").status());
        assertEquals(1, host.closed.size(), "a refused request closes nothing more");
    }

    @Test
    void hrCannotRemoveTheAdministratorItselfOrSomeoneWhoDoesNotExistAndSeesNoAdministratorInItsList() {
        assertEquals(403, access.call("POST", "hr/leaver", HR, "{\"id\":\"dana\",\"reason\":\"x\"}").status());
        assertEquals(403, access.call("POST", "hr/leaver", HR, "{\"id\":\"hana\",\"reason\":\"x\"}").status());
        assertEquals(404, access.call("POST", "hr/leaver", HR, "{\"id\":\"nobody\",\"reason\":\"x\"}").status());
        assertTrue(host.closed.isEmpty() && removed.isEmpty());
        String people = access.call("GET", "hr", HR, "").body();
        assertTrue(people.contains("\"uma\"") && people.contains("\"cleo\""));
        assertFalse(people.contains("\"dana\"") || people.contains("\"hana\""), "no administrator and not HR itself in the leaver list");
        assertFalse(people.contains("consoleRoles") || people.contains("ADMIN"), "HR sees names and jobs, not roles");
    }

    // ---- the audit trail is never hidden -------------------------------------------------------------------------------------

    @Test
    void aRecordThatCouldNotBeWrittenIsReportedNotHidden() {
        host.trailWorks = false;
        Response r = access.call("POST", "request", USER, "{\"items\":[\"wiki\"],\"reason\":\"docs\"}");
        assertEquals(200, r.status(), r.body());
        assertEquals(2, json(r).get("auditFailures").map(v -> ((JsonValue.JNumber) v).asLong()).orElseThrow(),
                "the request and the grant: both records failed, and both are counted");
    }

    @Test
    void withoutTheDatabaseTheAdministratorsSectionSaysSo() {
        fx.access = null;
        Response r = admin.call("GET", "access/queue", ADMIN, "");
        assertEquals(404, r.status());
        assertTrue(r.body().contains("switched off"));
    }
}

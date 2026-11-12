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
import java.util.TreeSet;

import static dev.dwarpal.console.lab.FakeRoutes.json;
import static dev.dwarpal.console.lab.FakeRoutes.text;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An administrator's own requests go to the OTHER administrator: a new administrator account, the administrator role
 * given or taken away, a change to the administrator's own access. Nobody approves their own request, the lead is not
 * asked, the last administrator can never be removed, and a refused request changes nothing. The test person who operates
 * both accounts is two accounts to the code.
 */
class PrivilegedChangeTest {

    private static ConsoleModule.Elevation elevation(String id) {
        return new ConsoleModule.Elevation(id, "a privileged change for the test", Instant.parse("2099-01-01T00:00:00Z"));
    }

    private static final Principal DANA = new Principal("dana", Set.of(Role.ADMIN), true, elevation("elv-dana"));
    private static final Principal SPECTOR = new Principal("spector", Set.of(Role.ADMIN), true, elevation("elv-spector"));
    private static final Principal DANA_PLAIN = new Principal("dana", Set.of(Role.ADMIN), true);
    private static final Principal LEAD = new Principal("cleo", Set.of(Role.LEAD, Role.ANALYST), true, elevation("elv-cleo"));
    private static final Principal USER = new Principal("uma", Set.of(Role.USER), true);

    private static final class Host implements ConsoleModule.Host {
        final List<String[]> audits = new ArrayList<>();
        final List<String> roles = new ArrayList<>();

        @Override
        public boolean audit(String type, String person, Map<String, String> fields) {
            audits.add(new String[]{type, person, fields.toString()});
            return true;
        }

        @Override
        public void closeAccount(String personId) {
        }

        @Override
        public void rolesChanged(String personId, Set<String> r) {
            roles.add(personId + ":" + String.join(",", new TreeSet<>(r)));
        }

        String last(String type) {
            return audits.stream().filter(a -> a[0].equals(type)).reduce((a, b) -> b).map(a -> a[2]).orElse("");
        }

        long count(String type) {
            return audits.stream().filter(a -> a[0].equals(type)).count();
        }
    }

    private Host host;
    private final List<String> created = new ArrayList<>();
    private FakeRoutes admin;
    private FakeRoutes access;
    private PostgresDirectory directory;

    @BeforeEach
    void build() {
        TestDatabase.require();
        TestDatabase.reset();
        directory = new PostgresDirectory(TestDatabase.app());
        seed("dana", "Dana", "IT Security", "Administrator", "ADMIN");
        seed("spector", "Spector", "Administration", "Administrator", "ADMIN");
        seed("cleo", "Cleo", "SOC", "SOC lead", "ANALYST", "LEAD");
        seed("uma", "Uma", "Finance", "Finance officer", "USER");
        seed("hana", "Hana", "Human Resources", "HR officer", "HR");
        AccessApi api = new AccessApi(new PostgresAccess(TestDatabase.app()), directory, new CredentialLifecycle() {
            @Override
            public void personCreated(String personId) {
                created.add(personId);
            }

            @Override
            public void personRemoved(String personId) {
            }
        });
        host = new Host();
        AdminFixture fx = new AdminFixture();
        fx.access = api;
        AdminModule module = new AdminModule(fx);
        module.attach(host);
        admin = FakeRoutes.of(module);
        AccessModule am = new AccessModule(api);
        am.attach(host);
        access = FakeRoutes.of(am);
    }

    private void seed(String id, String name, String dept, String job, String... roles) {
        directory.addIfAbsent(new DirectoryPerson(id, name, dept, job, DirectoryPerson.Status.ACTIVE, DirectoryPerson.Source.SEED,
                Instant.parse("2026-11-01T09:00:00Z"), Set.of(roles)));
    }

    private Response ask(Principal who, String change, String target, String reason) {
        return admin.call("POST", "access/privileged", who, "{\"change\":\"" + change + "\",\"target\":\"" + target + "\",\"reason\":\""
                + reason + "\"}");
    }

    private static String id(Response r) {
        return text(((JsonValue.JObject) json(r).get("request").orElseThrow()).get("id").orElseThrow());
    }

    private Response decide(Principal who, String request, boolean approve, String reason) {
        return admin.call("POST", "access/privileged/" + request + "/decision", who,
                "{\"approve\":" + approve + (reason == null ? "" : ",\"reason\":\"" + reason + "\"") + "}");
    }

    private Set<String> roles(String person) {
        return directory.find(person).orElseThrow().consoleRoles();
    }

    // ---- the request goes to the other administrator ----------------------------------------------------------------------

    @Test
    void anAdministratorsOwnRequestForMoreAccessIsNoLongerSentToNobody() {
        Response r = access.call("POST", "request", DANA, "{\"items\":[\"finance\"],\"reason\":\"month end\"}");
        assertEquals(403, r.status(), r.body());
        assertTrue(r.body().contains("privileged change"));
        assertTrue(host.audits.isEmpty(), "and nothing was created or recorded");
        assertTrue(access.call("GET", "mine", DANA, "").body().contains("\"canRequestMore\":false"),
                "the page is told to offer the privileged change instead");
        assertTrue(access.call("GET", "mine", USER, "").body().contains("\"canRequestMore\":true"));
    }

    @Test
    void theRequestWaitsForTheOtherAdministratorWhoCanDecideItAndTheAskerCannot() {
        Response asked = ask(DANA, "ADD_ADMIN", "uma", "uma covers while I am away");
        assertEquals(200, asked.status(), asked.body());
        String id = id(asked);
        assertFalse(roles("uma").contains("ADMIN"), "nothing changes until the other administrator approves");

        String mineQueue = admin.call("GET", "access/queue", DANA, "").body();
        assertTrue(mineQueue.contains(id) && mineQueue.contains("\"canDecide\":false"), "the asker sees it, and cannot decide it");
        String theirQueue = admin.call("GET", "access/queue", SPECTOR, "").body();
        assertTrue(theirQueue.contains(id) && theirQueue.contains("\"canDecide\":true"), "the other administrator can");

        Response self = decide(DANA, id, true, null);
        assertEquals(403, self.status(), "nobody approves their own request: " + self.body());
        assertEquals(403, decide(new Principal("dana", Set.of(Role.ADMIN), true, elevation("elv-dana-2")), id, true, null).status(),
                "a second session of the same account is the same account");
        assertEquals(403, decide(LEAD, id, true, null).status(), "the lead is not asked");
        assertFalse(roles("uma").contains("ADMIN"));

        Response done = decide(SPECTOR, id, true, "agreed");
        assertEquals(200, done.status(), done.body());
        assertTrue(roles("uma").contains("ADMIN"));
        assertEquals(List.of("uma:ADMIN,USER"), host.roles, "the console takes the new roles at once");
        assertEquals(409, decide(SPECTOR, id, true, null).status(), "it was decided already");
    }

    @Test
    void theRulesTreatTwoAccountsOperatedByOnePersonAsTwoPeople() {
        // the same tester operates dana and spector; the approval still has to come from the other account
        String id = id(ask(SPECTOR, "ADD_ADMIN", "uma", "uma covers for me"));
        assertEquals(403, decide(SPECTOR, id, true, null).status());
        assertEquals(200, decide(DANA, id, true, null).status());
        assertTrue(host.last("ACCESS_PRIVILEGED_APPROVED").contains("asked by=spector"));
        assertTrue(host.audits.stream().filter(a -> a[0].equals("ACCESS_PRIVILEGED_APPROVED")).allMatch(a -> a[1].equals("dana")),
                "recorded under the account that approved");
    }

    @Test
    void aRefusalNeedsAReasonAndChangesNothing() {
        String id = id(ask(DANA, "ADD_ADMIN", "uma", "uma covers while I am away"));
        assertEquals(400, decide(SPECTOR, id, false, "").status());
        Response refused = decide(SPECTOR, id, false, "uma does not need it");
        assertEquals(200, refused.status(), refused.body());
        assertFalse(roles("uma").contains("ADMIN"));
        assertEquals(1, host.count("ACCESS_PRIVILEGED_REJECTED"));
        assertEquals(0, host.count("ACCESS_ROLE_ADDED"));
        assertEquals(409, decide(SPECTOR, id, true, null).status(), "a refused request cannot be approved afterwards");
    }

    // ---- the four changes -----------------------------------------------------------------------------------------------------

    @Test
    void anAdministratorCanBeRemovedOnlyWhileAnotherRemains() {
        String id = id(ask(DANA, "REMOVE_ADMIN", "spector", "spector moves to another team"));
        Response done = decide(SPECTOR, id, true, "yes");
        assertEquals(200, done.status(), done.body());
        assertFalse(roles("spector").contains("ADMIN"));
        assertTrue(host.last("ACCESS_ROLE_REMOVED").contains("before=roles: ADMIN") && host.last("ACCESS_ROLE_REMOVED").contains("after=roles: none"));
        assertTrue(host.roles.contains("spector:"), "the console is told spector now holds no role: " + host.roles);

        Response last = ask(DANA, "REMOVE_ADMIN", "dana", "I would like to leave");
        assertEquals(409, last.status(), "the last administrator is never removed: " + last.body());
        assertTrue(roles("dana").contains("ADMIN"));
    }

    @Test
    void theLastAdministratorGuardAlsoHoldsAtApprovalTime() {
        String first = id(ask(DANA, "REMOVE_ADMIN", "spector", "one"));
        String second = id(ask(SPECTOR, "REMOVE_ADMIN", "dana", "two"));
        assertEquals(200, decide(SPECTOR, first, true, null).status(), "spector approves dana's request to remove spector");
        Response blocked = decide(DANA, second, true, null);
        assertEquals(409, blocked.status(), "spector is no longer an administrator, and dana is the last one: " + blocked.body());
        assertTrue(roles("dana").contains("ADMIN"));
    }

    @Test
    void aNewAdministratorAccountIsCreatedOnlyWhenTheOtherAdministratorApproves() {
        Response asked = admin.call("POST", "access/privileged", DANA, "{\"change\":\"CREATE_ADMIN\",\"target\":\"morgan\","
                + "\"name\":\"Morgan Lee\",\"department\":\"Administration\",\"businessRole\":\"Administrator\",\"reason\":\"third pair of hands\"}");
        assertEquals(200, asked.status(), asked.body());
        assertTrue(directory.find("morgan").isEmpty());
        String id = id(asked);
        assertEquals(403, decide(DANA, id, true, null).status());
        assertEquals(200, decide(SPECTOR, id, true, null).status());
        DirectoryPerson p = directory.find("morgan").orElseThrow();
        assertEquals(Set.of("ADMIN"), p.consoleRoles());
        assertEquals(DirectoryPerson.Source.ADMIN, p.source());
        assertEquals("Administration", p.department());
        assertEquals(List.of("morgan"), created, "the credential side hears that a person appeared");
    }

    @Test
    void anAdministratorsOwnAccessChangesOnlyWhenTheOtherApprovesAndNeverTakesAConsoleRole() {
        assertEquals(400, admin.call("POST", "access/privileged", DANA, "{\"change\":\"OWN_ACCESS\",\"items\":[\"console-lead\"],\"reason\":\"x\"}")
                .status(), "console roles change through the administrator changes");
        Response asked = admin.call("POST", "access/privileged", DANA, "{\"change\":\"OWN_ACCESS\",\"items\":[\"finance\"],"
                + "\"reason\":\"month end close\"}");
        assertEquals(200, asked.status(), asked.body());
        String id = id(asked);
        assertFalse(access.call("GET", "mine", DANA, "").body().contains("\"itemId\":\"finance\""), "nothing is granted yet");
        assertEquals(403, decide(DANA, id, true, null).status());
        Response done = decide(SPECTOR, id, true, "ok");
        assertEquals(200, done.status(), done.body());
        assertTrue(done.body().contains("\"itemId\":\"finance\"") && done.body().contains("\"state\":\"ACTIVE\""));
        assertTrue(host.last("ACCESS_GRANTED").contains("approved by the other administrator"));
        assertEquals(409, admin.call("POST", "access/privileged", DANA, "{\"change\":\"OWN_ACCESS\",\"items\":[\"finance\"],\"reason\":\"again\"}")
                .status(), "already held");
    }

    @Test
    void badRequestsAreRefusedWithoutTouchingAnything() {
        assertEquals(400, ask(DANA, "NOT_A_CHANGE", "uma", "x").status());
        assertEquals(400, ask(DANA, "JOINER", "uma", "x").status(), "only the privileged kinds");
        assertEquals(404, ask(DANA, "ADD_ADMIN", "nobody", "x").status());
        assertEquals(409, ask(DANA, "ADD_ADMIN", "spector", "already one").status());
        assertEquals(404, ask(DANA, "REMOVE_ADMIN", "uma", "uma is no administrator").status());
        assertEquals(400, ask(DANA, "ADD_ADMIN", "x' OR '1'='1", "x").status());
        assertEquals(400, admin.call("POST", "access/privileged", DANA, "{\"change\":\"ADD_ADMIN\",\"target\":\"uma\",\"reason\":\"x\",\"extra\":1}")
                .status());
        assertEquals(403, ask(new Principal("hana", Set.of(Role.HR), true, elevation("e")), "ADD_ADMIN", "uma", "x").status());
        assertEquals(403, ask(LEAD, "ADD_ADMIN", "uma", "x").status(), "a lead is not an administrator");
        assertEquals(423, ask(DANA_PLAIN, "ADD_ADMIN", "uma", "x").status());
        assertEquals(200, ask(DANA, "ADD_ADMIN", "uma", "valid").status());
        assertEquals(409, ask(DANA, "ADD_ADMIN", "uma", "same again").status(), "one waiting request per change and person");
        assertEquals(1, host.count("ACCESS_PRIVILEGED_REQUESTED"));
    }

    @Test
    void everyStepIsAuditedWithTheElevationBeforeAndAfter() {
        String id = id(ask(DANA, "ADD_ADMIN", "uma", "uma covers while I am away"));
        decide(SPECTOR, id, true, "agreed");
        String requested = host.last("ACCESS_PRIVILEGED_REQUESTED");
        assertTrue(requested.contains("elevation=elv-dana") && requested.contains("reason=uma covers while I am away")
                && requested.contains("target=uma") && requested.contains("change=ADD_ADMIN") && requested.contains("before=roles: USER"),
                requested);
        String approved = host.last("ACCESS_PRIVILEGED_APPROVED");
        assertTrue(approved.contains("elevation=elv-spector") && approved.contains("reason=agreed") && approved.contains("asked by=dana"), approved);
        String added = host.last("ACCESS_ROLE_ADDED");
        assertTrue(added.contains("before=roles: USER") && added.contains("after=roles: ADMIN,USER") && added.contains("elevation=elv-spector"), added);
        assertEquals("dana", host.audits.stream().filter(a -> a[0].equals("ACCESS_PRIVILEGED_REQUESTED")).findFirst().orElseThrow()[1]);
        assertEquals("spector", host.audits.stream().filter(a -> a[0].equals("ACCESS_ROLE_ADDED")).findFirst().orElseThrow()[1]);
    }
}

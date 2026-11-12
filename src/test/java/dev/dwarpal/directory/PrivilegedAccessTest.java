package dev.dwarpal.directory;

import dev.dwarpal.directory.Access.AccessResult;
import dev.dwarpal.directory.Access.Refused;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The rules of the privileged changes in the database layer, whoever calls: only an administrator asks, only a different
 * administrator decides, nobody approves their own request, a lead or HR or the person concerned is not an approver, the
 * last administrator stays, and a refused request creates nothing.
 */
class PrivilegedAccessTest {

    private PostgresDirectory directory;
    private PostgresAccess access;

    @BeforeEach
    void freshDatabase() {
        TestDatabase.require();
        TestDatabase.reset();
        directory = new PostgresDirectory(TestDatabase.app());
        access = new PostgresAccess(TestDatabase.app());
        seed("dana", "IT Security", "ADMIN");
        seed("spector", "Administration", "ADMIN");
        seed("cleo", "SOC", "ANALYST", "LEAD");
        seed("hana", "Human Resources", "HR");
        seed("uma", "Finance", "USER");
    }

    private void seed(String id, String dept, String... roles) {
        assertTrue(directory.addIfAbsent(new DirectoryPerson(id, "Name of " + id, dept, "Employee", DirectoryPerson.Status.ACTIVE,
                DirectoryPerson.Source.SEED, Instant.parse("2026-11-01T09:00:00Z"), Set.of(roles))));
    }

    private static void refused(Refused.Code code, Runnable call) {
        assertEquals(code, assertThrows(Refused.class, call::run).code());
    }

    private AccessRequest ask(String by, AccessRequest.Kind kind, String target) {
        return access.requestPrivileged(by, kind, target, "Morgan Lee", "Administration", "Administrator", Set.of(), "a reason").request();
    }

    @Test
    void onlyAnActiveAdministratorMayAsk() {
        for (String who : new String[]{"cleo", "hana", "uma", "nobody"}) {
            refused(Refused.Code.FORBIDDEN, () -> ask(who, AccessRequest.Kind.ADD_ADMIN, "uma"));
        }
        assertTrue(access.openPrivileged().isEmpty());
    }

    @Test
    void onlyADifferentAdministratorMayDecideAndNeverTheOneWhoAsked() {
        AccessRequest q = ask("dana", AccessRequest.Kind.ADD_ADMIN, "uma");
        assertEquals(AccessRequest.Status.PENDING, q.status());
        refused(Refused.Code.FORBIDDEN, () -> access.decidePrivileged("dana", q.id(), true, null));
        refused(Refused.Code.FORBIDDEN, () -> access.decidePrivileged("dana", q.id(), false, "no"));
        for (String who : new String[]{"cleo", "hana", "uma", "nobody"}) {
            refused(Refused.Code.FORBIDDEN, () -> access.decidePrivileged(who, q.id(), true, null));
        }
        assertFalse(directory.find("uma").orElseThrow().consoleRoles().contains("ADMIN"));
        assertEquals(1, access.openPrivileged().size(), "still waiting");
        AccessResult done = access.decidePrivileged("spector", q.id(), true, "agreed");
        assertEquals(AccessRequest.Status.DONE, done.request().status());
        assertEquals("spector", done.request().decidedBy());
        assertTrue(directory.find("uma").orElseThrow().consoleRoles().contains("ADMIN"));
        assertTrue(access.openPrivileged().isEmpty());
    }

    @Test
    void aDecisionIsFinalAndAnUnknownOrOrdinaryRequestIsNotFound() {
        AccessRequest q = ask("dana", AccessRequest.Kind.ADD_ADMIN, "uma");
        access.decidePrivileged("spector", q.id(), false, "not needed");
        refused(Refused.Code.CONFLICT, () -> access.decidePrivileged("spector", q.id(), true, null));
        refused(Refused.Code.NOT_FOUND, () -> access.decidePrivileged("spector", "req-nothing", true, null));
        refused(Refused.Code.NOT_FOUND, () -> access.decidePrivileged("spector", null, true, null));
        AccessRequest ordinary = access.requestAccess("uma", Set.of("finance"), "month end").request();
        refused(Refused.Code.NOT_FOUND, () -> access.decidePrivileged("spector", ordinary.id(), true, null));
        assertFalse(directory.find("uma").orElseThrow().consoleRoles().contains("ADMIN"), "a refused request creates nothing");
    }

    @Test
    void aRefusalNeedsAReasonAndARequestFromSomeoneWhoIsNoLongerAnAdministratorCannotBeApproved() {
        AccessRequest q = ask("dana", AccessRequest.Kind.ADD_ADMIN, "uma");
        refused(Refused.Code.INVALID, () -> access.decidePrivileged("spector", q.id(), false, null));
        refused(Refused.Code.INVALID, () -> access.decidePrivileged("spector", q.id(), false, "   "));
        // dana's administrator role is taken away (spector asks, dana, the other one, agrees): her earlier request lapses
        AccessRequest out = ask("spector", AccessRequest.Kind.REMOVE_ADMIN, "dana");
        access.decidePrivileged("dana", out.id(), true, null);
        refused(Refused.Code.CONFLICT, () -> access.decidePrivileged("spector", q.id(), true, null));
        refused(Refused.Code.FORBIDDEN, () -> access.decidePrivileged("dana", q.id(), true, null));
        assertFalse(directory.find("uma").orElseThrow().consoleRoles().contains("ADMIN"));
    }

    @Test
    void theLastAdministratorCanNeverBeRemoved() {
        AccessRequest q = ask("dana", AccessRequest.Kind.REMOVE_ADMIN, "spector");
        access.decidePrivileged("spector", q.id(), true, null);
        assertFalse(directory.find("spector").orElseThrow().consoleRoles().contains("ADMIN"));
        refused(Refused.Code.CONFLICT, () -> ask("dana", AccessRequest.Kind.REMOVE_ADMIN, "dana"));
        assertTrue(directory.find("dana").orElseThrow().consoleRoles().contains("ADMIN"));
    }

    @Test
    void anAdministratorsOwnAccessIsAskedForByThemAndGrantedByTheOtherAndNeverCarriesAConsoleRole() {
        refused(Refused.Code.INVALID, () -> access.requestPrivileged("dana", AccessRequest.Kind.OWN_ACCESS, "uma", null, null, null,
                Set.of("console-analyst"), "x"));
        refused(Refused.Code.INVALID, () -> access.requestPrivileged("dana", AccessRequest.Kind.OWN_ACCESS, null, null, null, null,
                Set.of("no-such-item"), "x"));
        refused(Refused.Code.INVALID, () -> access.requestPrivileged("dana", AccessRequest.Kind.OWN_ACCESS, null, null, null, null,
                Set.of(), "x"));
        AccessResult asked = access.requestPrivileged("dana", AccessRequest.Kind.OWN_ACCESS, "uma", null, null, null,
                Set.of("finance", "wiki"), "month end");
        assertEquals("dana", asked.request().subjectId(), "it is always about the one who asks, whatever target was sent");
        assertTrue(access.grantsOf("dana").isEmpty(), "nothing is granted by asking");
        AccessResult done = access.decidePrivileged("spector", asked.request().id(), true, null);
        assertEquals(2, access.grantsOf("dana").stream().filter(g -> g.state() == AccessGrant.State.ACTIVE).count());
        assertEquals(2, done.events().stream().filter(e -> e.type().equals("ACCESS_GRANTED")).count());
    }

    @Test
    void hrCannotRemoveAnAdministratorByTheLeaverRouteEvenAfterTheyHoldOwnAccess() {
        AccessResult asked = access.requestPrivileged("dana", AccessRequest.Kind.OWN_ACCESS, null, null, null, null, Set.of("wiki"), "x");
        access.decidePrivileged("spector", asked.request().id(), true, null);
        refused(Refused.Code.FORBIDDEN, () -> access.leaver("hana", "dana", "no"));
        assertEquals(1, access.grantsOf("dana").stream().filter(g -> g.state() == AccessGrant.State.ACTIVE).count());
    }

    @Test
    void whatAnInjectionStringIsInEveryNewInputIsRefusedOrStoredAsPlainText() {
        String bad = "x'); DROP TABLE access_request; --";
        refused(Refused.Code.INVALID, () -> access.requestPrivileged("dana", AccessRequest.Kind.CREATE_ADMIN, bad, "N", "D", "J", Set.of(), "r"));
        refused(Refused.Code.INVALID, () -> access.requestPrivileged("dana", AccessRequest.Kind.ADD_ADMIN, "uma' OR '1'='1", null, null, null,
                Set.of(), "r"));
        refused(Refused.Code.INVALID, () -> access.requestPrivileged("dana", AccessRequest.Kind.CREATE_ADMIN, "morgan", bad + "\n", "D", "J",
                Set.of(), "r"));
        AccessRequest kept = access.requestPrivileged("dana", AccessRequest.Kind.CREATE_ADMIN, "morgan", "Morgan' OR '1'='1", "Administration",
                "Administrator", Set.of(), "r'; DELETE FROM directory_person; --").request();
        assertTrue(kept.displayName().contains("OR '1'='1") && kept.reason().contains("DELETE FROM"), "stored as plain text");
        assertEquals(5, directory.people().size(), "and nothing was dropped or deleted");
        refused(Refused.Code.INVALID, () -> access.decidePrivileged("spector", kept.id(), false, null));
    }
}

package dev.dwarpal.directory;

import dev.dwarpal.directory.Access.AccessEvent;
import dev.dwarpal.directory.Access.AccessResult;
import dev.dwarpal.directory.Access.Refused;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The access process against the throw-away test database: joiners, more access, simple and hard approval, leavers,
 * and the rules the IAM notes ask to be tested (a leaver ends with zero access, a sensitive item is never granted
 * without every approval, a refused request creates nothing, every grant and removal is an audit event).
 */
class AccessProcessTest {

    private PostgresDirectory directory;
    private PostgresAccess access;

    @BeforeEach
    void freshDatabase() {
        TestDatabase.require();
        TestDatabase.reset();
        directory = new PostgresDirectory(TestDatabase.app());
        access = new PostgresAccess(TestDatabase.app());
        seed("hana", "Hana (HR)", "Human Resources", "HR officer", "HR");
        seed("dana", "Dana (administrator)", "IT Security", "Administrator", "ADMIN");
        seed("cleo", "Cleo (SOC lead)", "SOC", "SOC lead", "ANALYST", "LEAD");
        seed("ana", "Ana (analyst)", "SOC", "Security analyst", "ANALYST");
        seed("uma", "Uma (user)", "Finance", "Finance officer", "USER");
    }

    private void seed(String id, String name, String dept, String job, String... roles) {
        assertTrue(directory.addIfAbsent(new DirectoryPerson(id, name, dept, job, DirectoryPerson.Status.ACTIVE,
                DirectoryPerson.Source.SEED, Instant.parse("2026-11-01T09:00:00Z"), Set.of(roles))));
    }

    private AccessRequest joiner(String id, String job) {
        return access.submitJoiner("hana", id, "Priya Nair", "Engineering", job, "starts on Monday").request();
    }

    private static long count(List<AccessEvent> events, String type) {
        return events.stream().filter(e -> e.type().equals(type)).count();
    }

    private static AccessGrant grantFor(List<AccessGrant> grants, String item) {
        return grants.stream().filter(g -> g.itemId().equals(item)).findFirst().orElseThrow();
    }

    private static void refused(Refused.Code code, Runnable call) {
        assertEquals(code, assertThrows(Refused.class, call::run).code());
    }

    // ---- the catalogue ---------------------------------------------------------------------------------------------

    @Test
    void theCatalogueAndTheRoleDefaultsAreThere() {
        assertTrue(access.catalog().stream().anyMatch(i -> i.id().equals("finance") && i.sensitivity() == AccessItem.Sensitivity.HARD));
        assertTrue(access.catalog().stream().anyMatch(i -> i.id().equals("wiki") && i.sensitivity() == AccessItem.Sensitivity.SIMPLE));
        assertEquals(Set.of("email", "wiki", "vpn", "console"), Set.copyOf(access.templates().get("Software engineer")));
    }

    // ---- joiner ----------------------------------------------------------------------------------------------------------

    @Test
    void aJoinerRequestCreatesNothingUntilTheAdministratorSaves() {
        AccessResult r = access.submitJoiner("hana", "priya", "Priya Nair", "Engineering", "Software engineer", "starts on Monday");
        assertEquals(AccessRequest.Status.PENDING, r.request().status());
        assertTrue(directory.find("priya").isEmpty(), "no person yet");
        assertTrue(access.grantsOf("priya").isEmpty(), "no access yet");
        assertEquals(List.of("ACCESS_REQUESTED"), r.events().stream().map(AccessEvent::type).toList());
        assertEquals(1, access.openJoiners().size());
        refused(Refused.Code.CONFLICT, () -> joiner("priya", "Software engineer"));
    }

    @Test
    void onlyWhatIsTickedIsGrantedOneRecordPerItemAndSensitiveItemsWaitForALead() {
        AccessRequest req = joiner("priya", "Software engineer");
        AccessResult saved = access.saveJoiner("dana", req.id(), Set.of("email", "console", "finance"));

        DirectoryPerson p = directory.find("priya").orElseThrow();
        assertEquals(DirectoryPerson.Status.ACTIVE, p.status());
        assertEquals(DirectoryPerson.Source.HR, p.source());
        assertEquals(Set.of("USER"), p.consoleRoles(), "the console item gave the USER role; the hard item has not given anything yet");

        List<AccessGrant> grants = access.grantsOf("priya");
        assertEquals(Set.of("email", "console", "finance"), grants.stream().map(AccessGrant::itemId).collect(java.util.stream.Collectors.toSet()),
                "wiki and vpn are in the role's defaults but were not ticked: not granted");
        assertEquals(AccessGrant.State.ACTIVE, grantFor(grants, "email").state());
        assertEquals(AccessGrant.State.ACTIVE, grantFor(grants, "console").state());
        AccessGrant finance = grantFor(grants, "finance");
        assertEquals(AccessGrant.State.PENDING, finance.state());
        assertEquals(AccessGrant.Decision.APPROVED, finance.approvals().stream().filter(a -> a.role().equals("ADMIN")).findFirst().orElseThrow().decision());
        assertEquals(AccessGrant.Decision.PENDING, finance.approvals().stream().filter(a -> a.role().equals("LEAD")).findFirst().orElseThrow().decision());
        assertEquals(AccessRequest.Status.APPROVED, saved.request().status(), "waiting only for the lead");

        assertEquals(1, count(saved.events(), "ACCESS_PERSON_ADDED"));
        assertEquals(2, count(saved.events(), "ACCESS_GRANTED"), "one audit event per grant that became active");
        assertEquals(1, count(saved.events(), "ACCESS_PENDING"));
        assertEquals(1, count(saved.events(), "ACCESS_APPROVED"));
    }

    @Test
    void anAdministratorCannotSaveARequestTwiceOrSaveAnUnknownItem() {
        AccessRequest req = joiner("priya", "Support agent");
        refused(Refused.Code.INVALID, () -> access.saveJoiner("dana", req.id(), Set.of("email", "root-shell")));
        assertTrue(directory.find("priya").isEmpty(), "nothing was created by a refused save");
        access.saveJoiner("dana", req.id(), Set.of("email"));
        refused(Refused.Code.CONFLICT, () -> access.saveJoiner("dana", req.id(), Set.of("wiki")));
        assertEquals(1, access.grantsOf("priya").size());
    }

    @Test
    void aSaveThatFailsHalfWayLeavesNothingBehind() {
        AccessRequest req = joiner("priya", "Support agent");
        // a row that makes the third step fail after the person was already inserted
        TestDatabase.migrator().write(c -> {
            try (PreparedStatement s = c.prepareStatement("INSERT INTO access_request_item (request_id, item_id) VALUES (?, ?)")) {
                s.setString(1, req.id());
                s.setString(2, "email");
                s.executeUpdate();
            }
            return null;
        });
        assertThrows(DirectoryException.class, () -> access.saveJoiner("dana", req.id(), Set.of("email", "wiki")));
        assertTrue(directory.find("priya").isEmpty(), "the person was rolled back too");
        assertTrue(access.grantsOf("priya").isEmpty());
        assertEquals(AccessRequest.Status.PENDING, access.request(req.id()).orElseThrow().status());
    }

    @Test
    void aRefusedJoinerCreatesNothingAndKeepsItsReason() {
        AccessRequest req = joiner("priya", "Support agent");
        refused(Refused.Code.INVALID, () -> access.rejectJoiner("dana", req.id(), "  "));
        AccessResult r = access.rejectJoiner("dana", req.id(), "no position was approved");
        assertEquals(AccessRequest.Status.REJECTED, r.request().status());
        assertEquals("no position was approved", r.request().decisionReason());
        assertTrue(directory.find("priya").isEmpty());
        assertTrue(access.grantsOf("priya").isEmpty());
        assertEquals(List.of("ACCESS_REJECTED"), r.events().stream().map(AccessEvent::type).toList());
        refused(Refused.Code.CONFLICT, () -> access.saveJoiner("dana", req.id(), Set.of("email")));
    }

    // ---- who may do what -----------------------------------------------------------------------------------------

    @Test
    void onlyHrRaisesJoinersAndLeaversAndOnlyTheAdministratorSaves() {
        refused(Refused.Code.FORBIDDEN, () -> access.submitJoiner("ana", "priya", "Priya", "Eng", "Support agent", "x"));
        refused(Refused.Code.FORBIDDEN, () -> access.submitJoiner("dana", "priya", "Priya", "Eng", "Support agent", "x"));
        refused(Refused.Code.FORBIDDEN, () -> access.submitJoiner("nobody", "priya", "Priya", "Eng", "Support agent", "x"));
        AccessRequest req = joiner("priya", "Support agent");
        refused(Refused.Code.FORBIDDEN, () -> access.saveJoiner("hana", req.id(), Set.of("email")));
        refused(Refused.Code.FORBIDDEN, () -> access.saveJoiner("cleo", req.id(), Set.of("email")));
        refused(Refused.Code.FORBIDDEN, () -> access.rejectJoiner("ana", req.id(), "no"));
        refused(Refused.Code.FORBIDDEN, () -> access.leaver("dana", "ana", "left"));
        refused(Refused.Code.FORBIDDEN, () -> access.leaver("ana", "uma", "left"));
    }

    @Test
    void aSensitiveItemIsNeverGrantedWithoutTheAdministratorAndALeadAndNobodyApprovesTheirOwn() {
        AccessResult asked = access.requestAccess("ana", Set.of("finance", "wiki"), "I reconcile the SOC budget");
        AccessGrant wiki = grantFor(asked.grants(), "wiki");
        AccessGrant finance = grantFor(asked.grants(), "finance");
        assertEquals(AccessGrant.State.ACTIVE, wiki.state(), "simple: automatic, the directory shows Ana is active");
        assertEquals(AccessGrant.State.PENDING, finance.state());
        assertEquals(1, count(asked.events(), "ACCESS_GRANTED"));
        assertEquals(1, count(asked.events(), "ACCESS_PENDING"));

        refused(Refused.Code.FORBIDDEN, () -> access.decide("ana", "ADMIN", finance.id(), true, null));
        refused(Refused.Code.FORBIDDEN, () -> access.decide("ana", "LEAD", finance.id(), true, null));
        refused(Refused.Code.FORBIDDEN, () -> access.decide("hana", "ADMIN", finance.id(), true, null));
        refused(Refused.Code.FORBIDDEN, () -> access.decide("dana", "LEAD", finance.id(), true, null)); // an administrator is not a lead

        access.decide("cleo", "LEAD", finance.id(), true, "approved");
        assertEquals(AccessGrant.State.PENDING, grantFor(access.grantsOf("ana"), "finance").state(), "the lead alone is not enough");
        AccessResult done = access.decide("dana", "ADMIN", finance.id(), true, null);
        assertEquals(AccessGrant.State.ACTIVE, grantFor(access.grantsOf("ana"), "finance").state());
        assertEquals(1, count(done.events(), "ACCESS_GRANTED"));
        assertEquals(AccessRequest.Status.DONE, done.request().status());
        refused(Refused.Code.CONFLICT, () -> access.decide("dana", "ADMIN", finance.id(), true, null));
    }

    @Test
    void theAdministratorAndALeadCannotApproveTheirOwnRequests() {
        AccessGrant mine = grantFor(access.requestAccess("dana", Set.of("prod-db"), "debugging").grants(), "prod-db");
        refused(Refused.Code.FORBIDDEN, () -> access.decide("dana", "ADMIN", mine.id(), true, null));
        access.decide("cleo", "LEAD", mine.id(), true, null);
        assertEquals(AccessGrant.State.PENDING, grantFor(access.grantsOf("dana"), "prod-db").state(), "no second administrator: it waits");

        AccessGrant leads = grantFor(access.requestAccess("cleo", Set.of("finance"), "quarter close").grants(), "finance");
        refused(Refused.Code.FORBIDDEN, () -> access.decide("cleo", "LEAD", leads.id(), true, null));
        access.decide("dana", "ADMIN", leads.id(), true, null);
        assertEquals(AccessGrant.State.PENDING, grantFor(access.grantsOf("cleo"), "finance").state());
    }

    @Test
    void aRefusedHardGrantCreatesNoAccessAndNeedsAReason() {
        AccessGrant g = grantFor(access.requestAccess("uma", Set.of("console-analyst"), "I would like to help the SOC").grants(), "console-analyst");
        refused(Refused.Code.INVALID, () -> access.decide("cleo", "LEAD", g.id(), false, null));
        AccessResult r = access.decide("cleo", "LEAD", g.id(), false, "no analyst training yet");
        assertEquals(AccessGrant.State.REJECTED, grantFor(access.grantsOf("uma"), "console-analyst").state());
        assertEquals(Set.of("USER"), directory.find("uma").orElseThrow().consoleRoles(), "no role was added");
        assertEquals(List.of("ACCESS_REJECTED"), r.events().stream().map(AccessEvent::type).toList());
        assertEquals(AccessRequest.Status.DONE, r.request().status());
        refused(Refused.Code.CONFLICT, () -> access.decide("dana", "ADMIN", g.id(), true, null));
    }

    @Test
    void anApprovedConsoleItemGivesTheConsoleRoleOnlyOnceEveryApprovalIsIn() {
        AccessGrant g = grantFor(access.requestAccess("uma", Set.of("console-analyst"), "SOC rota").grants(), "console-analyst");
        access.decide("dana", "ADMIN", g.id(), true, null);
        assertEquals(Set.of("USER"), directory.find("uma").orElseThrow().consoleRoles());
        access.decide("cleo", "LEAD", g.id(), true, null);
        assertEquals(Set.of("ANALYST", "USER"), directory.find("uma").orElseThrow().consoleRoles());
    }

    @Test
    void askingForMoreAccessNeedsAnActivePersonAndRefusesWhatIsAlreadyHeld() {
        refused(Refused.Code.FORBIDDEN, () -> access.requestAccess("nobody", Set.of("wiki"), "x"));
        access.requestAccess("uma", Set.of("wiki"), "documentation");
        refused(Refused.Code.CONFLICT, () -> access.requestAccess("uma", Set.of("wiki"), "again"));
        refused(Refused.Code.CONFLICT, () -> access.requestAccess("ana", Set.of("console-analyst"), "I am one already"));
        refused(Refused.Code.INVALID, () -> access.requestAccess("uma", Set.of(), "nothing"));
        refused(Refused.Code.INVALID, () -> access.requestAccess("uma", Set.of("root-shell"), "x"));
        refused(Refused.Code.INVALID, () -> access.requestAccess("uma", Set.of("vpn"), " "));
    }

    // ---- leaver -------------------------------------------------------------------------------------------------------------

    @Test
    void aLeaverEndsWithZeroAccessEveryGrantRemovedFromTheRecordsAndEveryRemovalAudited() {
        AccessRequest req = joiner("priya", "Software engineer");
        access.saveJoiner("dana", req.id(), Set.of("email", "console", "finance"));
        access.requestAccess("priya", Set.of("crm"), "customer calls");                  // a one-off extra, outside her role
        access.requestAccess("priya", Set.of("prod-db"), "look at a bug");                // still waiting for approvals
        assertEquals(5, access.grantsOf("priya").stream().filter(g -> g.state() == AccessGrant.State.ACTIVE
                || g.state() == AccessGrant.State.PENDING).count());

        AccessResult r = access.leaver("hana", "priya", "last day was Friday");

        DirectoryPerson p = directory.find("priya").orElseThrow();
        assertEquals(DirectoryPerson.Status.DISABLED, p.status());
        assertTrue(p.consoleRoles().isEmpty(), "no console role is left");
        assertEquals(0, access.grantsOf("priya").stream().filter(g -> g.state() == AccessGrant.State.ACTIVE
                || g.state() == AccessGrant.State.PENDING).count(), "zero access");
        assertEquals(5, access.grantsOf("priya").stream().filter(g -> g.state() == AccessGrant.State.REMOVED).count());
        assertTrue(access.grantsOf("priya").stream().allMatch(g -> g.removedReason().equals("leaver")), "history stays, marked removed");
        assertEquals(5, count(r.events(), "ACCESS_REMOVED"), "one audit event per grant removed, the one-off extras too");
        assertEquals(1, count(r.events(), "ACCESS_ROLES_REMOVED"));
        assertEquals(1, count(r.events(), "ACCESS_PERSON_DISABLED"));
        assertEquals(AccessRequest.Status.DONE, r.request().status());
        refused(Refused.Code.FORBIDDEN, () -> access.requestAccess("priya", Set.of("wiki"), "I am gone"));
        refused(Refused.Code.CONFLICT, () -> access.leaver("hana", "priya", "twice"));
    }

    @Test
    void aLeaverWithNoGrantRecordsStillLosesTheirConsoleRoles() {
        AccessResult r = access.leaver("hana", "ana", "moved to another company");
        assertTrue(directory.find("ana").orElseThrow().consoleRoles().isEmpty());
        assertEquals(DirectoryPerson.Status.DISABLED, directory.find("ana").orElseThrow().status());
        assertEquals(0, count(r.events(), "ACCESS_REMOVED"));
        assertEquals("ANALYST", r.events().stream().filter(e -> e.type().equals("ACCESS_ROLES_REMOVED")).findFirst().orElseThrow()
                .fields().get("roles"));
    }

    @Test
    void aLeaverCancelsTheirOpenRequests() {
        AccessResult asked = access.requestAccess("uma", Set.of("finance"), "month end");
        access.leaver("hana", "uma", "left");
        assertEquals(AccessRequest.Status.CANCELLED, access.request(asked.request().id()).orElseThrow().status());
        assertTrue(access.awaiting("ADMIN").isEmpty() && access.awaiting("LEAD").isEmpty(), "nothing waits for a person who left");
    }

    @Test
    void hrCannotRemoveItselfTheAdministratorAnUnknownPersonOrAMalformedId() {
        refused(Refused.Code.FORBIDDEN, () -> access.leaver("hana", "hana", "x"));
        refused(Refused.Code.FORBIDDEN, () -> access.leaver("hana", "dana", "x"));
        refused(Refused.Code.NOT_FOUND, () -> access.leaver("hana", "nobody", "x"));
        refused(Refused.Code.NOT_FOUND, () -> access.leaver("hana", "x' OR '1'='1", "x"));
        refused(Refused.Code.INVALID, () -> access.leaver("hana", "uma", ""));
        assertEquals(DirectoryPerson.Status.ACTIVE, directory.find("uma").orElseThrow().status());
        assertEquals(DirectoryPerson.Status.ACTIVE, directory.find("dana").orElseThrow().status());
    }

    // ---- the waiting lists and reads ----------------------------------------------------------------------------------------

    @Test
    void theWaitingListsShowOnlyWhatStillNeedsThatApprover() {
        AccessRequest req = joiner("priya", "Finance officer");
        access.saveJoiner("dana", req.id(), Set.of("email", "finance"));
        assertEquals(1, access.awaiting("LEAD").size(), "the administrator already approved it by saving");
        assertTrue(access.awaiting("ADMIN").isEmpty());
        access.requestAccess("ana", Set.of("prod-db"), "debug");
        assertEquals(2, access.awaiting("LEAD").size());
        assertEquals(1, access.awaiting("ADMIN").size());
        assertTrue(access.awaiting("HR").isEmpty());
        assertEquals(List.of("ana"), access.requestsOf("ana").stream().map(AccessRequest::subjectId).distinct().toList());
        assertTrue(access.requestsOf("x' OR '1'='1").isEmpty());
    }

    // ---- hostile input -------------------------------------------------------------------------------------------------------

    @Test
    void hostileTextIsStoredAsTextAndNeverReachesTheSqlAndBadIdsAreRefused() {
        String hostile = "Robert'); DROP TABLE access_request;--";
        AccessResult r = access.submitJoiner("hana", "robert", hostile, "Eng", "Support agent", hostile);
        assertEquals(hostile, r.request().displayName());
        assertEquals(hostile, access.request(r.request().id()).orElseThrow().reason());
        refused(Refused.Code.INVALID, () -> access.submitJoiner("hana", "x' OR '1'='1", "N", "D", "R", "why"));
        refused(Refused.Code.INVALID, () -> access.submitJoiner("hana", "ok-id", "N\nINJECT", "D", "R", "why"));
        refused(Refused.Code.INVALID, () -> access.submitJoiner("hana", "ok-id", "N", "D", "R", "bidi " + new String(Character.toChars(0x202E)) + " reason"));
        refused(Refused.Code.INVALID, () -> access.submitJoiner("hana", "ok-id", "N", "D", "R", null));
        assertTrue(access.request("req-x' OR '1'='1").isEmpty());
        assertTrue(access.request(null).isEmpty());
        assertEquals(1, access.recent().size(), "the table is still there with its one row");
    }

    // ---- two approvers at the same moment ----------------------------------------------------------------------------------

    @Test
    void twoApproversDecidingTogetherNeverLeaveAnApprovedGrantWaiting() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            for (int round = 0; round < 15; round++) {
                String grant = grantFor(access.requestAccess(round % 2 == 0 ? "ana" : "uma", Set.of(round % 2 == 0 ? "prod-db" : "finance"),
                        "round " + round).grants(), round % 2 == 0 ? "prod-db" : "finance").id();
                Future<AccessResult> admin = pool.submit(() -> access.decide("dana", "ADMIN", grant, true, null));
                Future<AccessResult> lead = pool.submit(() -> access.decide("cleo", "LEAD", grant, true, null));
                List<AccessEvent> events = new ArrayList<>(admin.get().events());
                events.addAll(lead.get().events());
                assertEquals(1, count(events, "ACCESS_GRANTED"), "round " + round + ": granted exactly once");
                String person = round % 2 == 0 ? "ana" : "uma";
                assertEquals(AccessGrant.State.ACTIVE, access.grantsOf(person).stream().filter(x -> x.id().equals(grant))
                        .findFirst().orElseThrow().state(), "round " + round);
                // the next round must ask for something that person does not hold: free the pair
                TestDatabase.migrator().write(c -> {
                    try (PreparedStatement s = c.prepareStatement("UPDATE access_grant SET state = 'REMOVED', removed_at = ?,"
                            + " removed_reason = ? WHERE grant_id = ?")) {
                        s.setObject(1, java.time.OffsetDateTime.now());
                        s.setString(2, "test");
                        s.setString(3, grant);
                        s.executeUpdate();
                    }
                    return null;
                });
            }
        } finally {
            pool.shutdownNow();
        }
    }

    // ---- what the lab's own database user may and may not do -----------------------------------------------------------

    @Test
    void theLabUserCannotChangeTheCatalogueOrDeleteHistory() {
        AccessRequest req = joiner("priya", "Support agent");
        access.saveJoiner("dana", req.id(), Set.of("email"));
        for (String sql : List.of("DELETE FROM access_grant", "DELETE FROM access_request", "DELETE FROM access_approval",
                "UPDATE access_item SET sensitivity = 'SIMPLE'", "INSERT INTO access_item (item_id, label, description, sensitivity)"
                        + " VALUES ('x', 'x', 'x', 'SIMPLE')", "DROP TABLE access_grant")) {
            assertThrows(DirectoryException.class, () -> TestDatabase.app().write(c -> {
                try (Statement s = c.createStatement()) {
                    s.executeUpdate(sql);
                } catch (SQLException e) {
                    throw e;
                }
                return null;
            }), sql);
        }
        assertFalse(access.grantsOf("priya").isEmpty(), "the history is intact");
    }
}

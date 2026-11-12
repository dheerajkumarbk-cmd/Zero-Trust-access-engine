package dev.dwarpal.directory;

import dev.dwarpal.directory.Access.AccessEvent;
import dev.dwarpal.directory.Access.AccessResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * "All or nothing" for the two multi-step flows that start from an existing person: asking for more access and the
 * leaver. Each test makes a LATER step of the flow fail, inside the flow's own transaction, after its first writes have
 * already been made, and then shows that nothing at all was kept: no request, no grant, no approval, no role change,
 * no status change.
 *
 * <p>How the failure is made: the tables hold no row that could collide (every id the flows write is random), so the test
 * signs in as the migrator (the table owner) and puts one trigger on the throw-away test database that refuses the
 * chosen later step. No migration and no table definition is touched; the trigger is dropped at the end of the test, and
 * {@link TestDatabase#reset()} drops the whole schema before the next one anyway. The events of a flow are not stored by
 * it (the caller writes them to the audit trail from the returned result), so a failed flow leaving nothing behind also
 * means no result and therefore no event: the thrown exception is the proof that none was returned.</p>
 */
class AccessRollbackTest {

    private static final String PLANTED = "planted_failure";

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
        assertTrue(directory.addIfAbsent(new DirectoryPerson(id, name, dept, job,
                DirectoryPerson.Status.ACTIVE, DirectoryPerson.Source.SEED, Instant.parse("2026-11-01T09:00:00Z"), Set.of(roles))));
    }

    private static long count(List<AccessEvent> events, String type) {
        return events.stream().filter(e -> e.type().equals(type)).count();
    }

    /** One trigger on the test database that raises an error for every row written to {@code table} by {@code operation}. */
    private static void plantFailure(String table, String operation) {
        TestDatabase.migrator().write(c -> {
            try (Statement s = c.createStatement()) {
                s.execute("CREATE FUNCTION " + PLANTED + "() RETURNS trigger LANGUAGE plpgsql AS"
                        + " 'BEGIN RAISE EXCEPTION ''planted failure''; END'");
                s.execute("CREATE TRIGGER " + PLANTED + " BEFORE " + operation + " ON " + table
                        + " FOR EACH ROW EXECUTE PROCEDURE " + PLANTED + "()");
            }
            return null;
        });
    }

    /** Removes the function and, with it, the trigger. */
    private static void removeFailure() {
        TestDatabase.migrator().write(c -> {
            try (Statement s = c.createStatement()) {
                s.execute("DROP FUNCTION " + PLANTED + "() CASCADE");
            }
            return null;
        });
    }

    /** A row count read as the table owner, so it sees exactly what is committed. */
    private static int rows(String sql) {
        return TestDatabase.migrator().<Integer>read(c -> {
            try (PreparedStatement s = c.prepareStatement(sql); ResultSet r = s.executeQuery()) {
                r.next();
                return r.getInt(1);
            }
        });
    }

    /** The failure must be the planted one (SQLSTATE P0001, raised by the trigger), not some other problem. */
    private static void assertPlanted(DirectoryException e) {
        SQLException cause = assertInstanceOf(SQLException.class, e.getCause());
        assertEquals("P0001", cause.getSQLState());
    }

    // ---- asking for more access ------------------------------------------------------------------------------------------

    @Test
    void aRequestForMoreAccessThatFailsHalfWayLeavesNothingBehind() {
        assertEquals(Set.of("ANALYST"), directory.find("ana").orElseThrow().consoleRoles());
        // "console" is first (items go in alphabetical order): the request, its item, an ACTIVE grant and the USER role are
        // all written before "finance" reaches its approvals, where the planted trigger refuses the very first one
        plantFailure("access_approval", "INSERT");
        try {
            DirectoryException e = assertThrows(DirectoryException.class,
                    () -> access.requestAccess("ana", Set.of("console", "finance"), "I reconcile the SOC budget"));
            assertPlanted(e);
        } finally {
            removeFailure();
        }

        assertEquals(0, rows("SELECT COUNT(*) FROM access_request"), "the request row was rolled back");
        assertEquals(0, rows("SELECT COUNT(*) FROM access_request_item"), "and its items");
        assertEquals(0, rows("SELECT COUNT(*) FROM access_grant"), "and the grants, the ACTIVE one included");
        assertEquals(0, rows("SELECT COUNT(*) FROM access_approval"), "and the approvals");
        assertEquals(0, rows("SELECT COUNT(*) FROM directory_person_role WHERE person_id = 'ana' AND console_role = 'USER'"),
                "the USER role that the console item gave was rolled back");
        DirectoryPerson ana = directory.find("ana").orElseThrow();
        assertEquals(DirectoryPerson.Status.ACTIVE, ana.status());
        assertEquals(Set.of("ANALYST"), ana.consoleRoles(), "the roles are exactly what they were");
        assertEquals(List.of(), access.grantsOf("ana"));
        assertEquals(List.of(), access.requestsOf("ana"));
        assertEquals(List.of(), access.recent());
        assertEquals(List.of(), access.awaiting("ADMIN"));
        assertEquals(List.of(), access.awaiting("LEAD"));

        // the failure was the only thing in the way: the same request now goes through, so nothing was left half-done
        AccessResult again = access.requestAccess("ana", Set.of("console", "finance"), "I reconcile the SOC budget");
        assertEquals(2, again.grants().size());
        assertEquals(1, count(again.events(), "ACCESS_GRANTED"));
        assertEquals(1, count(again.events(), "ACCESS_PENDING"));
        assertEquals(Set.of("ANALYST", "USER"), directory.find("ana").orElseThrow().consoleRoles());
    }

    // ---- the leaver ----------------------------------------------------------------------------------------------------

    @Test
    void aLeaverThatFailsAtTheLastStepKeepsTheWholePersonAsItWas() {
        // ana holds two ACTIVE grants (one gives her the USER role) and one that waits for approvals, so she has an open request
        access.requestAccess("ana", Set.of("console", "wiki", "finance"), "my first month");
        DirectoryPerson personBefore = directory.find("ana").orElseThrow();
        List<AccessGrant> grantsBefore = access.grantsOf("ana");
        List<AccessRequest> requestsBefore = access.requestsOf("ana");
        List<AccessRequest> recentBefore = access.recent();
        assertEquals(Set.of("ANALYST", "USER"), personBefore.consoleRoles());
        assertEquals(3, grantsBefore.size());
        assertEquals(AccessRequest.Status.PENDING, requestsBefore.getFirst().status());

        // the leaver writes in this order: its own request, every grant removed, the roles deleted, the open requests
        // cancelled, and last the person disabled. The planted trigger refuses that last step.
        plantFailure("directory_person", "UPDATE");
        try {
            DirectoryException e = assertThrows(DirectoryException.class, () -> access.leaver("hana", "ana", "moved to another company"));
            assertPlanted(e);
        } finally {
            removeFailure();
        }

        assertEquals(0, rows("SELECT COUNT(*) FROM access_request WHERE kind = 'LEAVER'"), "the leaver request itself was rolled back");
        assertEquals(0, rows("SELECT COUNT(*) FROM access_grant WHERE state = 'REMOVED'"), "no grant stays removed");
        assertEquals(0, rows("SELECT COUNT(*) FROM access_request WHERE status = 'CANCELLED'"), "the open request was not cancelled");
        assertEquals(personBefore, directory.find("ana").orElseThrow(), "still ACTIVE, with the same roles");
        assertEquals(grantsBefore, access.grantsOf("ana"), "every grant exactly as it was: state, dates, approvals");
        assertEquals(requestsBefore, access.requestsOf("ana"));
        assertEquals(recentBefore, access.recent());
        assertEquals(1, access.awaiting("ADMIN").size(), "her pending grant still waits for the administrator");
        assertEquals(1, access.awaiting("LEAD").size(), "and for the lead");
        assertEquals(DirectoryPerson.Status.ACTIVE, directory.find("hana").orElseThrow().status());

        // the failure was the only thing in the way: the leaver now goes through completely
        AccessResult done = access.leaver("hana", "ana", "moved to another company");
        assertEquals(DirectoryPerson.Status.DISABLED, directory.find("ana").orElseThrow().status());
        assertEquals(Set.of(), directory.find("ana").orElseThrow().consoleRoles());
        assertEquals(3, count(done.events(), "ACCESS_REMOVED"));
        assertEquals(1, count(done.events(), "ACCESS_PERSON_DISABLED"));
        assertEquals(AccessRequest.Status.CANCELLED, access.request(requestsBefore.getFirst().id()).orElseThrow().status());
    }
}

package dev.dwarpal.directory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Set;

import static dev.dwarpal.directory.DirectoryPersonTest.AT;
import static dev.dwarpal.directory.DirectoryPersonTest.person;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The directory against a real PostgreSQL (the test database; skipped on a computer with no database passwords). */
class PostgresDirectoryTest {

    private PostgresDirectory directory;

    @BeforeEach
    void freshDatabase() {
        TestDatabase.require();
        TestDatabase.reset();
        directory = new PostgresDirectory(TestDatabase.app());
    }

    @Test
    void aPersonSurvivesTheRoundTripWithEveryField() {
        DirectoryPerson ana = new DirectoryPerson("ana", "Ana (analyst)", "SOC", "Security analyst", DirectoryPerson.Status.ACTIVE,
                DirectoryPerson.Source.SEED, AT, Set.of("ANALYST", "LEAD"));
        assertTrue(directory.addIfAbsent(ana));
        assertEquals(ana, directory.find("ana").orElseThrow());
    }

    @Test
    void peopleComeBackInIdOrderWithTheirRoles() {
        directory.addIfAbsent(person("dana", "Dana", "ADMIN"));
        directory.addIfAbsent(person("ana", "Ana", "ANALYST"));
        directory.addIfAbsent(person("cleo", "Cleo", "LEAD", "ANALYST"));
        List<DirectoryPerson> all = directory.people();
        assertEquals(List.of("ana", "cleo", "dana"), all.stream().map(DirectoryPerson::id).toList());
        assertEquals(Set.of("ANALYST", "LEAD"), all.get(1).consoleRoles());
    }

    @Test
    void anIdThatExistsIsNeverOverwritten() {
        assertTrue(directory.addIfAbsent(person("ana", "Ana the first", "ANALYST")));
        assertFalse(directory.addIfAbsent(person("ana", "Ana the impostor", "ADMIN")));
        DirectoryPerson kept = directory.find("ana").orElseThrow();
        assertEquals("Ana the first", kept.displayName());
        assertEquals(Set.of("ANALYST"), kept.consoleRoles());
    }

    @Test
    void anUnknownOrMalformedIdIsSimplyNotFound() {
        assertTrue(directory.find("nobody").isEmpty());
        assertTrue(directory.find("").isEmpty());
        assertTrue(directory.find(null).isEmpty());
    }

    @Test
    void everyRoleTheConsoleKnowsCanBeStored() {
        for (String role : DirectoryPerson.ROLES) {
            assertTrue(directory.addIfAbsent(person("r" + role.toLowerCase(java.util.Locale.ROOT), "Role " + role, role)), role);
        }
        assertEquals(DirectoryPerson.ROLES.size(), directory.people().size());
    }

    @Test
    void healthNamesTheServerAndTheTableVersion() {
        Directory.Health h = directory.health();
        assertTrue(h.server().startsWith("PostgreSQL"), h.server());
        assertEquals(Migrator.expectedVersion(), h.schemaVersion());
    }

    @Test
    void aWriteThatFailsHalfWayLeavesNothingBehind() {
        assertThrows(IllegalStateException.class, () -> TestDatabase.app().write(c -> {
            try (PreparedStatement s = c.prepareStatement("INSERT INTO directory_person (person_id, display_name, department,"
                    + " business_role, status, source, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")) {
                s.setString(1, "ghost");
                s.setString(2, "Ghost");
                s.setString(3, "none");
                s.setString(4, "none");
                s.setString(5, "ACTIVE");
                s.setString(6, "SEED");
                s.setObject(7, AT.atOffset(java.time.ZoneOffset.UTC));
                s.setObject(8, AT.atOffset(java.time.ZoneOffset.UTC));
                s.executeUpdate();
            }
            throw new IllegalStateException("something went wrong after the first insert");
        }));
        assertTrue(directory.find("ghost").isEmpty(), "the half-done write was rolled back");
    }

    @Test
    void theDatabaseItselfRefusesWhatTheJavaChecksWouldHaveCaught() throws SQLException {
        directory.addIfAbsent(person("ana", "Ana", "ANALYST"));
        // signed in as the migrator, which can write anything, to show the table's own rules hold
        assertEquals("23514", sqlState("INSERT INTO directory_person (person_id, display_name, department, business_role, status,"
                + " source, created_at, updated_at) VALUES ('bad', 'Bad', 'x', 'y', 'WANDERING', 'SEED', now(), now())"));
        assertEquals("23514", sqlState("INSERT INTO directory_person_role (person_id, console_role) VALUES ('ana', 'ROOT')"));
        assertEquals("23503", sqlState("INSERT INTO directory_person_role (person_id, console_role) VALUES ('nobody', 'USER')"));
        assertEquals("23505", sqlState("INSERT INTO directory_person_role (person_id, console_role) VALUES ('ana', 'ANALYST')"));
    }

    private static String sqlState(String sql) throws SQLException {
        try (var c = TestDatabase.migrator().open(); Statement s = c.createStatement()) {
            s.execute(sql);
            return "no error";
        } catch (SQLException e) {
            return e.getSQLState();
        }
    }

    @Test
    void theLabUserCanReadAndWriteRowsButNotChangeTablesOrDeletePeople() throws SQLException {
        directory.addIfAbsent(person("ana", "Ana", "ANALYST"));
        Database app = TestDatabase.app();
        for (String sql : List.of("CREATE TABLE sneaky (a INTEGER)", "DROP TABLE directory_person",
                "ALTER TABLE directory_person ADD COLUMN sneaky INTEGER", "DELETE FROM directory_person",
                "TRUNCATE directory_person_role", "UPDATE directory_person_role SET console_role = 'ADMIN'",
                "UPDATE schema_version SET version = 99", "INSERT INTO schema_version (version, name, checksum, applied_at)"
                        + " VALUES (9, 'x', 'y', now())", "CREATE ROLE sneaky LOGIN")) {
            SQLException e = assertThrows(SQLException.class, () -> {
                try (var c = app.open(); Statement s = c.createStatement()) {
                    s.execute(sql);
                }
            }, sql);
            assertEquals("42501", e.getSQLState(), sql);
        }
        try (var c = app.open(); PreparedStatement s = c.prepareStatement("SELECT version FROM schema_version");
             ResultSet r = s.executeQuery()) {
            assertTrue(r.next(), "the lab user may read the table version");
        }
        // PostgreSQL only warns when a non-owner tries to hand out rights; what counts is that nothing was handed out
        try (var c = app.open(); Statement s = c.createStatement()) {
            s.execute("GRANT ALL ON directory_person TO PUBLIC");
        }
        try (var c = TestDatabase.migrator().open(); PreparedStatement s = c.prepareStatement(
                "SELECT COUNT(*) FROM information_schema.table_privileges WHERE grantee = 'PUBLIC' AND table_name = ?")) {
            s.setString(1, "directory_person");
            try (ResultSet r = s.executeQuery()) {
                r.next();
                assertEquals(0, r.getInt(1), "the lab user could not hand out any right");
            }
        }
        assertTrue(directory.find("ana").isPresent(), "nothing above changed anything");
    }
}

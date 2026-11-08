package dev.dwarpal.directory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The versioned migration scripts, applied to a real (test) database. */
class MigratorTest {

    @BeforeEach
    void freshDatabase() {
        TestDatabase.require();
        TestDatabase.reset();
    }

    private static int count(String sql) {
        return TestDatabase.migrator().read(c -> {
            try (PreparedStatement s = c.prepareStatement(sql); ResultSet r = s.executeQuery()) {
                r.next();
                return r.getInt(1);
            }
        });
    }

    @Test
    void aBuiltDatabaseIsAlreadyAtTheNewestVersionSoMigratingAgainDoesNothing() {
        assertEquals(List.of(), Migrator.migrate(TestDatabase.migrator()));
        assertEquals(Migrator.expectedVersion(), count("SELECT MAX(version) FROM schema_version"));
        assertEquals(Migrator.SCRIPTS.size(), count("SELECT COUNT(*) FROM schema_version"));
    }

    @Test
    void theRecordedChecksumIsTheChecksumOfTheScriptInTheBuild() {
        for (Migrator.Script s : Migrator.SCRIPTS) {
            String stored = TestDatabase.migrator().read(c -> {
                try (PreparedStatement p = c.prepareStatement("SELECT checksum FROM schema_version WHERE version = ?")) {
                    p.setInt(1, s.version());
                    try (ResultSet r = p.executeQuery()) {
                        r.next();
                        return r.getString(1).strip();
                    }
                }
            });
            assertEquals(Migrator.checksum(Migrator.text(s)), stored);
        }
    }

    @Test
    void anOldScriptThatWasEditedAfterItWasAppliedIsRefused() {
        TestDatabase.migrator().write(c -> {
            try (Statement s = c.createStatement()) {
                s.execute("UPDATE schema_version SET checksum = REPEAT('0', 64)");
            }
            return null;
        });
        DirectoryException e = assertThrows(DirectoryException.class, () -> Migrator.migrate(TestDatabase.migrator()));
        assertTrue(e.getMessage().contains("changed after it was applied"), e.getMessage());
    }

    @Test
    void aDatabaseNewerThanTheBuildIsRefused() {
        TestDatabase.migrator().write(c -> {
            try (Statement s = c.createStatement()) {
                s.execute("INSERT INTO schema_version (version, name, checksum, applied_at) VALUES (99, 'future', REPEAT('1', 64),"
                        + " CURRENT_TIMESTAMP)");
            }
            return null;
        });
        DirectoryException e = assertThrows(DirectoryException.class, () -> Migrator.migrate(TestDatabase.migrator()));
        assertTrue(e.getMessage().contains("newer"), e.getMessage());
    }

    @Test
    void theTablesTheLabNeedsAreThere() {
        assertEquals(3, count("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'"));
    }

    @Test
    void theLabUserCannotRunMigrations() {
        // the app user is not the migrator: it cannot create the version table nor change a script's record
        Database app = TestDatabase.app();
        assertThrows(DirectoryException.class, () -> Migrator.migrate(app));
    }

    @Test
    void aScriptHasPlainLineEndsWhateverGitDidToTheFile() {
        for (Migrator.Script s : Migrator.SCRIPTS) {
            assertFalse(Migrator.text(s).contains(String.valueOf((char) 13)), s.resource());
        }
    }
}

package dev.dwarpal.directory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Where the database is and who the lab signs in as: only this computer, no options, and no password ever printed. */
class DbSettingsTest {

    private static final String FILE_PASSWORD = "file-secret-value-one";
    private static final String ENV_PASSWORD = "env-secret-value-two";

    private static Path file(Path dir, String text) throws Exception {
        Path f = dir.resolve("local.properties");
        Files.writeString(f, text);
        return f;
    }

    @Test
    void withNothingSetThereAreDefaultsForEverythingButThePasswords(@TempDir Path dir) {
        DbSettings s = DbSettings.load(Map.of(), dir.resolve("missing.properties"));
        assertFalse(s.hasApp());
        assertFalse(s.hasMigrator());
        DirectoryException e = assertThrows(DirectoryException.class, () -> s.app(DbSettings.Target.LAB));
        assertTrue(e.getMessage().contains("dwarpal_app"));
    }

    @Test
    void theFileFillsInTheSettingsAndTheTestDatabaseIsAnotherOne(@TempDir Path dir) throws Exception {
        DbSettings s = DbSettings.load(Map.of(), file(dir, "app.password=" + FILE_PASSWORD + "\nmigrator.password=" + FILE_PASSWORD + "x\n"));
        assertTrue(s.hasApp());
        assertTrue(s.hasMigrator());
        DbSettings.Login lab = s.app(DbSettings.Target.LAB);
        DbSettings.Login test = s.app(DbSettings.Target.TEST);
        assertEquals("jdbc:postgresql://localhost:5432/dwarpal", lab.url());
        assertEquals("jdbc:postgresql://localhost:5432/dwarpal_test", test.url());
        assertEquals("dwarpal_app", lab.user());
        assertEquals("dwarpal_migrator", s.migrator(DbSettings.Target.LAB).user());
    }

    @Test
    void anEnvironmentVariableBeatsTheFile(@TempDir Path dir) throws Exception {
        DbSettings s = DbSettings.load(Map.of("DWARPAL_DB_APP_PASSWORD", ENV_PASSWORD),
                file(dir, "app.password=" + FILE_PASSWORD + "\n"));
        assertEquals(ENV_PASSWORD, s.app(DbSettings.Target.LAB).password());
    }

    @Test
    void noPasswordEverAppearsInTextForm(@TempDir Path dir) throws Exception {
        DbSettings s = DbSettings.load(Map.of(), file(dir, "app.password=" + FILE_PASSWORD + "\nmigrator.password=" + ENV_PASSWORD + "\n"));
        for (String text : List.of(s.toString(), s.app(DbSettings.Target.LAB).toString(), s.migrator(DbSettings.Target.TEST).toString())) {
            assertFalse(text.contains(FILE_PASSWORD), text);
            assertFalse(text.contains(ENV_PASSWORD), text);
            assertTrue(text.contains("redacted"), text);
        }
    }

    @Test
    void onlyThisComputerAndOnlyThePlainAddressIsAccepted(@TempDir Path dir) {
        for (String bad : List.of(
                "jdbc:postgresql://db.example.com:5432/dwarpal",
                "jdbc:postgresql://192.168.1.20:5432/dwarpal",
                "jdbc:postgresql://localhost:5432/dwarpal?sslmode=disable",
                "jdbc:postgresql://localhost:5432/dwarpal?user=postgres",
                "jdbc:postgresql://evil@localhost:5432/dwarpal",
                "jdbc:postgresql://localhost:5432/dwarpal;DROP",
                "jdbc:postgresql://localhost:5432/",
                "jdbc:postgresql://localhost:99999/dwarpal",
                "jdbc:postgresql:dwarpal",
                "jdbc:mysql://localhost:3306/dwarpal",
                "postgres://localhost/dwarpal")) {
            DbSettings s = DbSettings.load(Map.of("DWARPAL_DB_URL", bad, "DWARPAL_DB_APP_PASSWORD", ENV_PASSWORD),
                    dir.resolve("none"));
            assertThrows(DirectoryException.class, () -> s.app(DbSettings.Target.LAB), bad);
        }
        for (String good : List.of("jdbc:postgresql://localhost:5432/dwarpal", "jdbc:postgresql://127.0.0.1:5433/dwarpal_x",
                "jdbc:postgresql://[::1]:5432/dwarpal", "jdbc:postgresql://localhost/dwarpal")) {
            DbSettings s = DbSettings.load(Map.of("DWARPAL_DB_URL", good, "DWARPAL_DB_APP_PASSWORD", ENV_PASSWORD),
                    dir.resolve("none"));
            assertEquals(good, s.app(DbSettings.Target.LAB).url());
        }
    }

    @Test
    void aStrangeUserNameIsRefused(@TempDir Path dir) {
        for (String bad : List.of("Robert'; DROP TABLE x;--", "dwarpal app", "DWARPAL", "a", "x".repeat(70))) {
            DbSettings s = DbSettings.load(Map.of("DWARPAL_DB_APP_USER", bad, "DWARPAL_DB_APP_PASSWORD", ENV_PASSWORD),
                    dir.resolve("none"));
            assertThrows(DirectoryException.class, () -> s.app(DbSettings.Target.LAB), bad);
        }
    }

    @Test
    void aBlankValueInTheEnvironmentFallsBackToTheFile(@TempDir Path dir) throws Exception {
        DbSettings s = DbSettings.load(Map.of("DWARPAL_DB_APP_PASSWORD", "   "), file(dir, "app.password=" + FILE_PASSWORD + "\n"));
        assertEquals(FILE_PASSWORD, s.app(DbSettings.Target.LAB).password());
    }
}

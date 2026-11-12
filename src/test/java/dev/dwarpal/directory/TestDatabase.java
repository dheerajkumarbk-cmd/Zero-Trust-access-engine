package dev.dwarpal.directory;

import org.junit.jupiter.api.Assumptions;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * The throw-away test database. {@link #require()} skips a test on a computer with no database passwords (a clean
 * checkout, a build server); on this computer the passwords exist, so the tests run, and a database that is configured
 * but not answering fails the test instead of skipping it. {@link #reset()} wipes everything and rebuilds the tables, and
 * refuses to touch any database whose name does not end in {@code _test}, so a wrong address in the settings can never
 * wipe the lab's real people.
 */
public final class TestDatabase {

    private static final DbSettings SETTINGS = DbSettings.fromEnvironment();
    private static final String NAME = "SELECT current_database()";

    private TestDatabase() {
    }

    public static void require() {
        Assumptions.assumeTrue(SETTINGS.hasApp() && SETTINGS.hasMigrator(),
                "no database passwords are configured (see db/local.properties.example): database tests skipped");
    }

    public static Database app() {
        return new Database(SETTINGS.app(DbSettings.Target.TEST));
    }

    public static Database migrator() {
        return new Database(SETTINGS.migrator(DbSettings.Target.TEST));
    }

    /** Empty database, tables built by the real migrations. */
    public static void reset() {
        Database m = migrator();
        m.write(c -> {
            try (PreparedStatement s = c.prepareStatement(NAME); ResultSet r = s.executeQuery()) {
                r.next();
                if (!r.getString(1).endsWith("_test")) {
                    throw new IllegalStateException("refusing to wipe a database that is not a test database");
                }
            }
            try (Statement s = c.createStatement()) {
                s.execute("DROP SCHEMA public CASCADE");
                s.execute("CREATE SCHEMA public");
                s.execute("GRANT USAGE ON SCHEMA public TO dwarpal_app");
            }
            return null;
        });
        Migrator.migrate(m);
    }
}

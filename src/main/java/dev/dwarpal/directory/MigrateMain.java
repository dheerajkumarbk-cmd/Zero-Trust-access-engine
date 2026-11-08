package dev.dwarpal.directory;

import java.io.PrintStream;
import java.util.List;

/**
 * Builds or updates the directory tables. Run it once after the one-time database set-up, and again whenever a new
 * script ships:
 * <pre>
 *   java -cp "target/classes;&lt;postgresql jar&gt;" dev.dwarpal.directory.MigrateMain [--test]
 * </pre>
 * {@code --test} does the same to the throw-away test database. It signs in as the migrator user; its password comes
 * from the environment or {@code db/local.properties} and is never printed.
 */
public final class MigrateMain {

    private MigrateMain() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        DbSettings.Target target = DbSettings.Target.LAB;
        for (String a : args) {
            if ("--test".equals(a)) {
                target = DbSettings.Target.TEST;
            } else {
                err.println("unknown option " + a);
                return 2;
            }
        }
        try {
            DbSettings settings = DbSettings.fromEnvironment();
            List<Integer> applied = Migrator.migrate(new Database(settings.migrator(target)));
            out.println(applied.isEmpty()
                    ? "The " + target.name().toLowerCase(java.util.Locale.ROOT) + " database is already at version " + Migrator.expectedVersion() + "."
                    : "Applied migrations " + applied + "; the " + target.name().toLowerCase(java.util.Locale.ROOT)
                    + " database is now at version " + Migrator.expectedVersion() + ".");
            return 0;
        } catch (DirectoryException e) {
            err.println("Migration stopped: " + e.getMessage());
            return 1;
        }
    }
}

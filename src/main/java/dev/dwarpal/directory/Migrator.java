package dev.dwarpal.directory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Builds and changes the tables, from versioned scripts kept in the repository ({@code db/migrations/V001__*.sql}
 * under the jar's resources). Each script runs in one transaction together with its entry in {@code schema_version},
 * so a script either happened completely or not at all. A script that was already applied must still match the
 * checksum recorded then (an edited old script is refused, because the database would no longer match the repository),
 * and a database newer than this build is refused too.
 *
 * <p>Only the <em>migrator</em> database user runs this, from {@link MigrateMain} or the test set-up. The running lab
 * checks the version with {@link #expectedVersion()} and never builds tables itself.
 */
public final class Migrator {

    /** One script: its number, a short name and its file, in the order they are applied. */
    record Script(int version, String name, String resource) {
    }

    /** The scripts, in order. A new script is added here on purpose; a test compares this list with the folder. */
    static final List<Script> SCRIPTS = List.of(
            new Script(1, "directory", "/db/migrations/V001__directory.sql"));

    private static final String CREATE_VERSION_TABLE = "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL,"
            + " name VARCHAR(100) NOT NULL, checksum CHAR(64) NOT NULL, applied_at TIMESTAMP WITH TIME ZONE NOT NULL,"
            + " CONSTRAINT pk_schema_version PRIMARY KEY (version))";
    private static final String GRANT_VERSION_TABLE = "GRANT SELECT ON schema_version TO dwarpal_app";
    private static final String LIST_APPLIED = "SELECT version, checksum FROM schema_version ORDER BY version";
    private static final String RECORD = "INSERT INTO schema_version (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)";

    private Migrator() {
    }

    /** The newest version this build knows: the lab refuses to start on a database that is not at it. */
    public static int expectedVersion() {
        return SCRIPTS.getLast().version();
    }

    /**
     * Brings the database up to {@link #expectedVersion()}.
     *
     * @return the versions applied by this call (empty when it was already up to date)
     */
    public static List<Integer> migrate(Database migrator) {
        Objects.requireNonNull(migrator, "migrator");
        return migrator.write(c -> {
            try (Statement s = c.createStatement()) {
                s.execute(CREATE_VERSION_TABLE);
                s.execute(GRANT_VERSION_TABLE);
            }
            Map<Integer, String> applied = new HashMap<>();
            try (PreparedStatement s = c.prepareStatement(LIST_APPLIED); ResultSet r = s.executeQuery()) {
                while (r.next()) {
                    applied.put(r.getInt(1), r.getString(2));
                }
            }
            for (Integer version : applied.keySet()) {
                if (version > expectedVersion()) {
                    throw new DirectoryException("the database is at version " + version + ", newer than this build knows ("
                            + expectedVersion() + ")");
                }
            }
            List<Integer> done = new ArrayList<>();
            for (Script script : SCRIPTS) {
                String sql = text(script);
                String checksum = checksum(sql);
                String before = applied.get(script.version());
                if (before != null) {
                    if (!before.strip().equals(checksum)) {
                        throw new DirectoryException("migration V" + script.version() + " was changed after it was applied;"
                                + " write a new migration instead of editing an old one");
                    }
                    continue;
                }
                try (Statement s = c.createStatement()) {
                    s.execute(sql);
                }
                try (PreparedStatement s = c.prepareStatement(RECORD)) {
                    s.setInt(1, script.version());
                    s.setString(2, script.name());
                    s.setString(3, checksum);
                    s.setObject(4, OffsetDateTime.now(ZoneOffset.UTC));
                    s.executeUpdate();
                }
                done.add(script.version());
            }
            return List.copyOf(done);
        });
    }

    /** The script as text with plain line ends, so the checksum is the same on every computer and in the jar. */
    static String text(Script script) {
        try (InputStream in = Migrator.class.getResourceAsStream(script.resource())) {
            if (in == null) {
                throw new DirectoryException("migration script " + script.resource() + " is missing from the build");
            }
            String raw = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            return raw.replace(String.valueOf((char) 13) + (char) 10, String.valueOf((char) 10));
        } catch (IOException e) {
            throw new DirectoryException("migration script " + script.resource() + " cannot be read", e);
        }
    }

    static String checksum(String sql) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(sql.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is part of every JDK", e);
        }
    }

}

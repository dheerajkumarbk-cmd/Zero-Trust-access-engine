package dev.dwarpal.directory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Where the directory database is and who the lab signs in as. Nothing here is a default password: the two passwords
 * come from environment variables ({@code DWARPAL_DB_APP_PASSWORD}, {@code DWARPAL_DB_MIGRATOR_PASSWORD}) or from the
 * untracked file {@code db/local.properties} (path overridable with {@code DWARPAL_DB_CONFIG}); an environment
 * variable wins over the file. A password is never printed: every type that holds one prints "redacted".
 *
 * <p>Two sign-ins, on purpose: the <em>app</em> user is what the running lab uses and can only read and write rows; the
 * <em>migrator</em> user builds the tables and runs the tests, and the running lab never holds its password. Addresses
 * must be on this computer ({@code localhost}, {@code 127.0.0.1} or {@code [::1]}): the lab refuses to talk to a
 * database anywhere else, and the address takes no options (no query part to smuggle settings in).
 */
public final class DbSettings {

    /** Which database: the lab's real data, or the throw-away one the tests wipe on every run. */
    public enum Target { LAB, TEST }

    /** One sign-in to one database. */
    public record Login(String url, String user, String password) {
        public Login {
            checkUrl(url);
            checkName(user);
            if (password == null || password.isEmpty()) {
                throw new DirectoryException("the database password for " + user + " is not set: set the environment variable"
                        + " or fill in db/local.properties (see db/local.properties.example)");
            }
        }

        @Override
        public String toString() {
            return "Login[" + url + ", " + user + ", password redacted]";
        }
    }

    private static final Set<String> HOSTS = Set.of("localhost", "127.0.0.1", "[::1]");
    private static final Pattern DATABASE_PATH = Pattern.compile("/[A-Za-z0-9_]{1,63}");
    private static final Pattern USER_NAME = Pattern.compile("[a-z][a-z0-9_]{1,62}");
    private static final String PREFIX = "jdbc:postgresql:";
    private static final String DEFAULT_LAB = "jdbc:postgresql://localhost:5432/dwarpal";
    private static final String DEFAULT_TEST = "jdbc:postgresql://localhost:5432/dwarpal_test";

    private final String labUrl;
    private final String testUrl;
    private final String appUser;
    private final String appPassword;
    private final String migratorUser;
    private final String migratorPassword;

    private DbSettings(String labUrl, String testUrl, String appUser, String appPassword, String migratorUser,
                       String migratorPassword) {
        this.labUrl = labUrl;
        this.testUrl = testUrl;
        this.appUser = appUser;
        this.appPassword = appPassword;
        this.migratorUser = migratorUser;
        this.migratorPassword = migratorPassword;
    }

    /** The settings of this computer: the real environment, and the file named by DWARPAL_DB_CONFIG or db/local.properties. */
    public static DbSettings fromEnvironment() {
        Map<String, String> env = System.getenv();
        String named = env.get("DWARPAL_DB_CONFIG");
        return load(env, named == null || named.isBlank() ? Path.of("db", "local.properties") : Path.of(named));
    }

    /** Environment first, then the file (which may be missing), then the defaults for everything but the passwords. */
    public static DbSettings load(Map<String, String> env, Path file) {
        Properties p = new Properties();
        if (file != null && Files.isRegularFile(file)) {
            try (InputStream in = Files.newInputStream(file)) {
                p.load(in);
            } catch (IOException e) {
                throw new DirectoryException("the database settings file cannot be read", e);
            }
        }
        return new DbSettings(
                pick(env, "DWARPAL_DB_URL", p, "url", DEFAULT_LAB),
                pick(env, "DWARPAL_DB_TEST_URL", p, "test.url", DEFAULT_TEST),
                pick(env, "DWARPAL_DB_APP_USER", p, "app.user", "dwarpal_app"),
                pick(env, "DWARPAL_DB_APP_PASSWORD", p, "app.password", ""),
                pick(env, "DWARPAL_DB_MIGRATOR_USER", p, "migrator.user", "dwarpal_migrator"),
                pick(env, "DWARPAL_DB_MIGRATOR_PASSWORD", p, "migrator.password", ""));
    }

    private static String pick(Map<String, String> env, String variable, Properties file, String key, String fallback) {
        String fromEnv = env.get(variable);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv.strip();
        }
        String fromFile = file.getProperty(key);
        return fromFile != null && !fromFile.isBlank() ? fromFile.strip() : fallback;
    }

    /** True when the app user's password is known, so a database can be tried at all. */
    public boolean hasApp() {
        return !appPassword.isEmpty();
    }

    /** True when the migrator's password is known too (needed to build tables and to run the tests). */
    public boolean hasMigrator() {
        return !migratorPassword.isEmpty();
    }

    /** What the running lab signs in as. */
    public Login app(Target target) {
        return new Login(url(target), appUser, appPassword);
    }

    /** What builds the tables and runs the tests. */
    public Login migrator(Target target) {
        return new Login(url(target), migratorUser, migratorPassword);
    }

    private String url(Target target) {
        return target == Target.TEST ? testUrl : labUrl;
    }

    @Override
    public String toString() {
        return "DbSettings[" + labUrl + ", " + testUrl + ", passwords redacted]";
    }

    /** Only this computer, only the plain address: no options after the database name. */
    static void checkUrl(String url) {
        if (url == null || !url.startsWith(PREFIX + "//")) {
            throw new DirectoryException("the database address must look like " + DEFAULT_LAB);
        }
        try {
            URI u = new URI(url.substring(PREFIX.length()));
            String host = u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT);
            String path = u.getPath() == null ? "" : u.getPath();
            boolean portOk = u.getPort() == -1 || (u.getPort() >= 1 && u.getPort() <= 65_535);
            if (!HOSTS.contains(host) || u.getQuery() != null || u.getFragment() != null || u.getUserInfo() != null
                    || !DATABASE_PATH.matcher(path).matches() || !portOk) {
                throw new DirectoryException("the database address must be on this computer and have no options");
            }
        } catch (URISyntaxException e) {
            throw new DirectoryException("the database address is not valid");
        }
    }

    private static void checkName(String name) {
        if (name == null || !USER_NAME.matcher(name).matches()) {
            throw new DirectoryException("the database user name is not valid");
        }
    }
}

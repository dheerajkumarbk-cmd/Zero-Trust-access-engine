package dev.dwarpal.console;

import dev.dwarpal.directory.TestDatabase;
import dev.dwarpal.edge.DevPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.PreparedStatement;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The launcher with the directory database switched on (the throw-away test database): the people are moved in, the
 * Directory page lists them, Hana (HR) signs in and sees nothing she should not, and a person disabled in the
 * directory is no longer enrolled at the next start.
 */
class LabConsoleDirectoryEndToEndTest {

    private static final Pattern URL = Pattern.compile("Console: (https://localhost:\\d+)");
    private static final Pattern LOGIN = Pattern.compile("^\\s+(\\w+)\\s+\\[[^]]*]\\s+password (\\S+)\\s+PIN (\\S+)\\s*$",
            Pattern.MULTILINE);

    private record Session(String cookie, String csrf) {
    }

    /** A running launcher: its log, its address, and the demo secrets it printed. */
    private record Run(String log, String base, Map<String, String[]> people, HttpClient http) {
    }

    @BeforeEach
    void freshDatabase() {
        TestDatabase.require();
        TestDatabase.reset();
    }

    private interface Body {
        void run(Run r) throws Exception;
    }

    private static void launch(Path dir, Body body) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(bytes, true, StandardCharsets.UTF_8);
        Thread launcher = new Thread(() -> {
            try {
                ConsoleMain.run(new String[]{"--dir", dir.toString(), "--users", "30", "--warmup-days", "1", "--port", "0",
                        "--db", "test"}, out);
            } catch (Exception e) {
                out.println("launcher failed: " + e);
            }
        });
        launcher.start();
        try {
            long deadline = System.nanoTime() + Duration.ofSeconds(120).toNanos();
            while (!text(bytes).contains("Stop with Ctrl+C") && !text(bytes).contains("launcher failed")
                    && System.nanoTime() < deadline) {
                Thread.sleep(200);
            }
            String log = text(bytes);
            assertFalse(log.contains("launcher failed"), log);
            Matcher u = URL.matcher(log);
            assertTrue(u.find(), log);
            Map<String, String[]> people = new LinkedHashMap<>();
            Matcher l = LOGIN.matcher(log);
            while (l.find()) {
                people.put(l.group(1), new String[]{l.group(2), l.group(3)});
            }
            DevPki pki = DevPki.open(dir.resolve("pki"), Files.readString(dir.resolve("pki/pki.pass")).trim().toCharArray(),
                    List.of("console"));
            SSLContext tls = ConsoleFixture.trustOnlyTheLabCa(pki);
            HttpClient http = HttpClient.newBuilder().sslContext(tls).version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(Duration.ofSeconds(10)).build();
            body.run(new Run(log, u.group(1), people, http));
        } finally {
            launcher.interrupt();
            launcher.join(30_000);
        }
    }

    @Test
    void thePeopleAreMovedIntoTheDirectoryAndHanaIsContainedToHerOwnRole() throws Exception {
        Path dir = Files.createTempDirectory("dwarpal-directory-e2e");
        launch(dir, r -> {
            assertTrue(r.log().contains("Directory: PostgreSQL"), r.log());
            assertTrue(r.log().contains("6 people can sign in (6 moved in by this start"), r.log());
            assertTrue(r.people().keySet().containsAll(List.of("ana", "ben", "cleo", "dana", "uma", "hana")), r.log());

            Session dana = login(r, "dana");
            HttpResponse<String> page = get(r, "/console/api/admin/directory", dana);
            assertEquals(200, page.statusCode(), page.body());
            for (String id : List.of("ana", "ben", "cleo", "dana", "uma", "hana")) {
                assertTrue(page.body().contains("\"id\":\"" + id + "\""), id + " in " + page.body());
            }
            assertTrue(page.body().contains("\"HR\""), "Hana holds the HR role");
            assertFalse(page.body().toLowerCase(java.util.Locale.ROOT).contains("password"), "no secret on the page");

            Session ana = login(r, "ana");
            assertEquals(403, get(r, "/console/api/admin/directory", ana).statusCode(), "an analyst cannot read the directory");

            Session hana = login(r, "hana");
            assertEquals(403, get(r, "/console/api/admin/directory", hana).statusCode(), "HR cannot read the whole directory");
            assertEquals(403, get(r, "/console/api/soc/queue", hana).statusCode(), "HR is no analyst");
            assertEquals(403, get(r, "/console/api/audit/records", hana).statusCode(), "HR cannot read the audit trail");
            assertEquals(403, get(r, "/console/api/lab/scenarios", hana).statusCode());
            HttpResponse<String> modules = get(r, "/console/api/modules", hana);
            assertEquals(200, modules.statusCode(), modules.body());
            assertFalse(modules.body().contains("\"lab\"") || modules.body().contains("\"guide\""), modules.body());
        });
    }

    @Test
    void aPersonDisabledInTheDirectoryIsNotEnrolledAtTheNextStart() throws Exception {
        Path dir = Files.createTempDirectory("dwarpal-directory-e2e");
        launch(dir, r -> {
            assertTrue(r.log().contains("Audit trail on disk: 0 records from earlier runs"), r.log());
            assertEquals(200, loginStatus(r, "ben"), "ben can sign in while he is active");
        });
        TestDatabase.migrator().write(c -> {
            try (PreparedStatement s = c.prepareStatement("UPDATE directory_person SET status = ? WHERE person_id = ?")) {
                s.setString(1, "DISABLED");
                s.setString(2, "ben");
                assertEquals(1, s.executeUpdate());
            }
            return null;
        });
        launch(dir, r -> {
            assertTrue(r.log().contains("5 people can sign in (0 moved in by this start, 1 not enrolled)"), r.log());
            assertFalse(r.log().contains("Audit trail on disk: 0 records"), "the first run's sign-ins were saved: " + r.log());
            assertTrue(r.log().contains("records from earlier runs, checked and intact"), r.log());
            assertNotEquals(200, loginStatus(r, "ben"), "a disabled person cannot finish signing in");
            assertEquals(200, loginStatus(r, "ana"), "everyone else still can");
        });
    }

    // ---- small HTTP helpers --------------------------------------------------------------------------

    private static String text(ByteArrayOutputStream b) {
        return b.toString(StandardCharsets.UTF_8);
    }

    private static HttpResponse<String> get(Run r, String path, Session s) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(r.base() + path)).timeout(Duration.ofSeconds(20))
                .header("User-Agent", "E2E/1");
        if (s != null) {
            b.header("Cookie", ConsoleServer.COOKIE + "=" + s.cookie());
        }
        return r.http().send(b.GET().build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static HttpResponse<String> post(Run r, String path, String body) throws Exception {
        return r.http().send(HttpRequest.newBuilder(URI.create(r.base() + path)).timeout(Duration.ofSeconds(20))
                .header("User-Agent", "E2E/1").header("Origin", r.base()).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    /** The status of the second sign-in step: 200 when the person is let in. */
    private static int loginStatus(Run r, String user) throws Exception {
        String[] secrets = r.people().getOrDefault(user, new String[]{"x".repeat(16), "y".repeat(8)});
        HttpResponse<String> first = post(r, "/console/api/session/login",
                "{\"user\":\"" + user + "\",\"password\":\"" + secrets[0] + "\"}");
        if (first.statusCode() != 200) {
            return first.statusCode();
        }
        return post(r, "/console/api/session/verify",
                "{\"loginId\":\"" + field(first.body(), "loginId") + "\",\"pin\":\"" + secrets[1] + "\"}").statusCode();
    }

    private static Session login(Run r, String user) throws Exception {
        String[] secrets = r.people().get(user);
        HttpResponse<String> first = post(r, "/console/api/session/login",
                "{\"user\":\"" + user + "\",\"password\":\"" + secrets[0] + "\"}");
        assertEquals(200, first.statusCode(), first.body());
        HttpResponse<String> done = post(r, "/console/api/session/verify",
                "{\"loginId\":\"" + field(first.body(), "loginId") + "\",\"pin\":\"" + secrets[1] + "\"}");
        assertEquals(200, done.statusCode(), done.body());
        String cookie = null;
        for (String c : done.headers().allValues("Set-Cookie")) {
            if (c.startsWith(ConsoleServer.COOKIE + "=")) {
                cookie = c.substring(ConsoleServer.COOKIE.length() + 1, c.indexOf(';'));
            }
        }
        assertTrue(cookie != null, "a session cookie was set");
        return new Session(cookie, field(done.body(), "csrf"));
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        assertTrue(m.find(), json);
        return m.group(1);
    }
}

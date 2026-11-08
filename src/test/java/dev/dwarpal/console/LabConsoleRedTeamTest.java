package dev.dwarpal.console;

import dev.dwarpal.edge.DevPki;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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
 * Layer 6 integration red team: attacks that cross the console, the lab, the admin views and the SOC, run over HTTPS
 * against the real launcher ({@link ConsoleMain}). Each test is an attack written as a working probe; a probe that
 * succeeds is a breach and is fixed before the test is kept.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class LabConsoleRedTeamTest {

    private record Session(String cookie, String csrf, String user) {
    }

    private static final Pattern URL = Pattern.compile("Console: (https://localhost:\\d+)");
    private static final Pattern LOGIN = Pattern.compile("^\\s+(\\w+)\\s+\\[[^]]*]\\s+password (\\S+)\\s+PIN (\\S+)\\s*$",
            Pattern.MULTILINE);

    private static Thread launcher;
    private static Path dir;
    private static String base;
    private static HttpClient http;
    private static final Map<String, String[]> people = new LinkedHashMap<>();
    private static String logText;

    @BeforeAll
    static void start() throws Exception {
        dir = Files.createTempDirectory("dwarpal-l6-redteam");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(bytes, true, StandardCharsets.UTF_8);
        launcher = new Thread(() -> {
            try {
                ConsoleMain.run(new String[]{"--dir", dir.toString(), "--users", "30", "--warmup-days", "2", "--port", "0", "--db", "off"},
                        out);
            } catch (Exception e) {
                out.println("launcher failed: " + e);
            }
        });
        launcher.start();
        long deadline = System.nanoTime() + Duration.ofSeconds(150).toNanos();
        while (!bytes.toString(StandardCharsets.UTF_8).contains("Stop with Ctrl+C") && System.nanoTime() < deadline
                && !bytes.toString(StandardCharsets.UTF_8).contains("launcher failed")) {
            Thread.sleep(200);
        }
        logText = bytes.toString(StandardCharsets.UTF_8);
        assertFalse(logText.contains("launcher failed"), logText);
        Matcher u = URL.matcher(logText);
        assertTrue(u.find(), logText);
        base = u.group(1);
        Matcher l = LOGIN.matcher(logText);
        while (l.find()) {
            people.put(l.group(1), new String[]{l.group(2), l.group(3)});
        }
        DevPki pki = DevPki.open(dir.resolve("pki"), Files.readString(dir.resolve("pki/pki.pass")).trim().toCharArray(),
                List.of("console"));
        http = HttpClient.newBuilder().sslContext(ConsoleFixture.trustOnlyTheLabCa(pki)).version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10)).build();
    }

    @AfterAll
    static void stop() throws Exception {
        launcher.interrupt();
        launcher.join(30_000);
    }

    // ---- probes -------------------------------------------------------------------------------------------

    @Test
    @Order(1)
    void aWriteWithTheCookieButWithoutTheTokenOrFromAnotherOriginIsRefused() throws Exception {
        Session ana = login("ana");
        HttpResponse<String> noToken = send("POST", "/console/api/lab/launch/anything", ana, base, false, "{}");
        assertEquals(403, noToken.statusCode(), "no anti-forgery token");
        HttpResponse<String> evil = send("POST", "/console/api/lab/launch/anything", ana, "https://evil.example", true, "{}");
        assertEquals(403, evil.statusCode(), "another origin");
        HttpResponse<String> noOrigin = send("POST", "/console/api/lab/launch/anything", ana, null, true, "{}");
        assertEquals(403, noOrigin.statusCode(), "no origin at all");
    }

    @Test
    @Order(2)
    void hostileTextComesBackAsJsonTextOnlyAndEveryApiAnswerIsJsonWithTheSecurityHeaders() throws Exception {
        Session ana = login("ana");
        String caseId = firstId(send("GET", "/console/api/soc/cases", ana, null, false, null).body());
        String payload = "<img src=x onerror=alert(1)><script>alert(2)</script>";
        HttpResponse<String> note = send("POST", "/console/api/soc/cases/" + caseId + "/notes", ana, base, true,
                "{\"text\":\"" + payload.replace("\"", "\\\"") + "\"}");
        assertTrue(note.statusCode() == 200 || note.statusCode() == 400, "note: " + note.statusCode() + " " + note.body());
        for (String path : List.of("/console/api/soc/cases/" + caseId, "/console/api/soc/queue",
                "/console/api/soc/cases/" + caseId + "/timeline", "/console/api/modules", "/console/api/audit/records?limit=5",
                "/console/api/me")) {
            HttpResponse<String> r = send("GET", path, ana, null, false, null);
            String type = r.headers().firstValue("Content-Type").orElse("");
            assertTrue(type.startsWith("application/json"), path + " answered " + type);
            assertEquals("nosniff", r.headers().firstValue("X-Content-Type-Options").orElse(""), path);
            assertTrue(r.headers().firstValue("Content-Security-Policy").orElse("").contains("script-src 'self'"), path);
            assertEquals("no-store", r.headers().firstValue("Cache-Control").orElse("").replace(", ", ","), path);
        }
    }

    @Test
    @Order(3)
    void aVerdictCannotNameAnotherAnalystAndNeedsAFreshStepUp() throws Exception {
        Session ana = login("ana");
        String alertId = "al-anything-1";
        HttpResponse<String> other = send("POST", "/console/api/soc/verdicts", ana, base, true,
                "{\"alertId\":\"" + alertId + "\",\"outcome\":\"TRUE_POSITIVE\",\"analystId\":\"ben\"}");
        assertEquals(400, other.statusCode(), "the signer is the session's person, never a field: " + other.body());
        HttpResponse<String> stale = send("POST", "/console/api/soc/verdicts", ana, base, true,
                "{\"alertId\":\"" + alertId + "\",\"outcome\":\"TRUE_POSITIVE\"}");
        assertNotEquals(200, stale.statusCode(), "no step-up yet: " + stale.body());
    }

    @Test
    @Order(4)
    void roleEscalationAcrossTheModulesFails() throws Exception {
        Session ana = login("ana");
        for (String path : List.of("/console/api/lab/control/pause", "/console/api/lab/control/resume",
                "/console/api/lab/control/speed", "/console/api/lab/control/fastforward", "/console/api/lab/control/reset",
                "/console/api/admin/lab/reset", "/console/api/admin/policy/propose", "/console/api/admin/pam/request")) {
            HttpResponse<String> r = send("POST", path, ana, base, true, "{}");
            assertEquals(403, r.statusCode(), "analyst on " + path + ": " + r.body());
        }
        assertRefused(send("GET", "/console/api/lab/export", ana, null, false, null), "export is for leads");
        Session uma = login("uma");
        assertRefused(send("GET", "/console/api/admin/policy", uma, null, false, null), "policy is for administrators");
        Session dana = login("dana");
        assertRefused(send("POST", "/console/api/soc/verdicts", dana, base, true,
                "{\"alertId\":\"al-x-1\",\"outcome\":\"TRUE_POSITIVE\"}"), "an administrator signs no verdicts");
        assertRefused(send("POST", "/console/api/lab/launch/anything", dana, base, true, "{}"), "an administrator launches no attacks");
    }

    /** Confidential views need the person's own passkey on the real launcher. */
    private static void openConfidential(Session s, String id) throws Exception {
        String[] who = people.get(id);
        HttpResponse<String> r = send("POST", "/console/api/profile/passkey", s, base, true,
                "{\"password\":\"" + who[0] + "\",\"pin\":\"" + who[1] + "\",\"passkey\":\"red-team-passkey\"}");
        assertEquals(200, r.statusCode(), r.body());
        r = send("POST", "/console/api/session/unlock", s, base, true, "{\"passkey\":\"red-team-passkey\"}");
        assertEquals(200, r.statusCode(), r.body());
    }

    @Test
    @Order(5)
    void theRunExportCarriesNoKeyPasswordOrCertificate() throws Exception {
        Session cleo = login("cleo");
        openConfidential(cleo, "cleo");
        HttpResponse<String> export = send("GET", "/console/api/lab/export", cleo, null, false, null);
        assertEquals(200, export.statusCode(), export.body().substring(0, Math.min(200, export.body().length())));
        String body = export.body();
        String pkiPass = Files.readString(dir.resolve("pki/pki.pass")).trim();
        assertFalse(body.contains(pkiPass), "the key store password");
        for (String[] secrets : people.values()) {
            assertFalse(body.contains(secrets[0]), "a demo password");
            assertFalse(body.contains(secrets[1]), "a demo PIN");
        }
        assertFalse(body.contains("BEGIN"), "a PEM block");
        assertFalse(body.contains("PRIVATE"), "private key text");
        assertFalse(body.contains(dir.toString()), "the lab directory path");
        assertFalse(body.toLowerCase().contains("localhost:"), "a real address");
    }

    @Test
    @Order(6)
    void filesOutsideTheStaticAllowListAreNotServedWhateverTheSpelling() throws Exception {
        String pkiPass = Files.readString(dir.resolve("pki/pki.pass")).trim();
        for (String path : List.of("/console/..%2f..%2fpki%2fpki.pass", "/console/%2e%2e/pki/pki.pass",
                "/console/modules/lab/../../../pki/pki.pass", "/console/people.txt", "/console/console/people.txt",
                "/console/modules/..%5c..%5cpki%5cpki.pass", "/pki/pki.pass", "/lab/pki/pki.pass",
                "/console/index.html%00.js", "/console/%252e%252e/pki/pki.pass")) {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path)).header("User-Agent", "rt")
                    .GET().build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertFalse(r.body().contains(pkiPass), path);
            assertTrue(r.statusCode() >= 400, path + " answered " + r.statusCode());
        }
    }

    @Test
    @Order(7)
    void anAdministratorResetsTheLabAndTheAnalystsSessionAndTheAuditChainStillWork() throws Exception {
        Session ana = login("ana");
        HttpResponse<String> before = send("GET", "/console/api/audit/verify", ana, null, false, null);
        assertTrue(before.body().contains("\"intact\":true"), before.body());
        Session dana = stepUp(login("dana"));
        HttpResponse<String> reset = send("POST", "/console/api/admin/lab/reset", dana, base, true, "{}");
        assertEquals(200, reset.statusCode(), reset.body());
        // the analyst was never told: her session, the SOC channel and the new chain all work
        HttpResponse<String> queue = send("GET", "/console/api/soc/queue", ana, null, false, null);
        assertEquals(200, queue.statusCode(), queue.body());
        HttpResponse<String> after = send("GET", "/console/api/audit/verify", ana, null, false, null);
        assertTrue(after.body().contains("\"intact\":true"), "the new chain verifies: " + after.body());
        assertEquals(200, send("GET", "/console/api/lab", ana, null, false, null).statusCode());
    }

    @Test
    @Order(8)
    void whatTheConsoleDidIsOnTheTrailUnderTheNamesOfThePeopleWhoDidIt() throws Exception {
        // the reset gave the lab a new chain; a login now is the first thing on it that a person did
        Session ana = login("ana");
        openConfidential(ana, "ana");
        HttpResponse<String> head = send("GET", "/console/api/audit/head", ana, null, false, null);
        Matcher h = Pattern.compile("\"head\"[ ]*:[ ]*([0-9]+)").matcher(head.body());
        assertTrue(h.find(), head.body());
        long tail = Math.max(0, Long.parseLong(h.group(1)) - 100);
        HttpResponse<String> r = send("GET", "/console/api/audit/records?after=" + tail + "&limit=200", ana, null, false, null);
        assertEquals(200, r.statusCode());
        assertTrue(r.body().contains("\"actor\":\"ana\""), "the analyst's login is on the trail under her name: " + r.body());
        assertTrue(send("GET", "/console/api/audit/verify", ana, null, false, null).body().contains("\"intact\":true"));
    }

    // ---- helpers ------------------------------------------------------------------------------------------

    /** Refused: 403, or 404 where the host hides what a role may not use. Never an answer with data. */
    private static void assertRefused(HttpResponse<String> r, String what) {
        assertTrue(r.statusCode() == 403 || r.statusCode() == 404, what + ": " + r.statusCode() + " " + r.body());
    }

    private static String firstId(String json) {
        Matcher m = Pattern.compile("\"id\"\\s*:\\s*\"(case-[^\"]+)\"").matcher(json);
        assertTrue(m.find(), json);
        return m.group(1);
    }

    private static HttpResponse<String> send(String method, String path, Session s, String origin, boolean csrf, String body)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).timeout(Duration.ofSeconds(60))
                .header("User-Agent", "rt");
        if (s != null) {
            b.header("Cookie", ConsoleServer.COOKIE + "=" + s.cookie());
            if (csrf) {
                b.header(ConsoleServer.CSRF_HEADER, s.csrf());
            }
        }
        if (origin != null) {
            b.header("Origin", origin);
        }
        if (body != null) {
            b.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(body));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static Session login(String user) throws Exception {
        String[] secrets = people.get(user);
        HttpResponse<String> first = post("/console/api/session/login",
                "{\"user\":\"" + user + "\",\"password\":\"" + secrets[0] + "\"}");
        assertEquals(200, first.statusCode(), first.body());
        HttpResponse<String> done = post("/console/api/session/verify",
                "{\"loginId\":\"" + field(first.body(), "loginId") + "\",\"pin\":\"" + secrets[1] + "\"}");
        assertEquals(200, done.statusCode(), done.body());
        return new Session(cookie(done), field(done.body(), "csrf"), user);
    }

    private static Session stepUp(Session s) throws Exception {
        String[] secrets = people.get(s.user());
        HttpResponse<String> r = send("POST", "/console/api/session/stepup", s, base, true,
                "{\"password\":\"" + secrets[0] + "\",\"pin\":\"" + secrets[1] + "\"}");
        assertEquals(200, r.statusCode(), r.body());
        return new Session(cookie(r), field(r.body(), "csrf"), s.user());
    }

    private static HttpResponse<String> post(String path, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(base + path)).timeout(Duration.ofSeconds(30))
                .header("User-Agent", "rt").header("Origin", base).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static String cookie(HttpResponse<String> r) {
        for (String c : r.headers().allValues("Set-Cookie")) {
            if (c.startsWith(ConsoleServer.COOKIE + "=")) {
                return c.substring(ConsoleServer.COOKIE.length() + 1, c.indexOf(';'));
            }
        }
        throw new IllegalStateException("no session cookie");
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        assertTrue(m.find(), json);
        return m.group(1);
    }
}

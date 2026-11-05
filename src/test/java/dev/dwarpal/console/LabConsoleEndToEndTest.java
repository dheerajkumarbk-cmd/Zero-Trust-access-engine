package dev.dwarpal.console;

import dev.dwarpal.edge.DevPki;
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
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The launcher exactly as a person starts it: {@link ConsoleMain} with the lab session, the console server and the lab,
 * guide and admin modules, driven over HTTPS by a client that trusts only the lab's certificate authority.
 */
class LabConsoleEndToEndTest {

    private static final Pattern URL = Pattern.compile("Console: (https://localhost:\\d+)");
    private static final Pattern LOGIN = Pattern.compile("^\\s+(\\w+)\\s+\\[[^]]*]\\s+password (\\S+)\\s+PIN (\\S+)\\s*$",
            Pattern.MULTILINE);

    private record Session(String cookie, String csrf) {
    }

    @Test
    void theLauncherServesTheWholeLabToAnalystsAndAdministratorsOverTheirRoles() throws Exception {
        Path dir = Files.createTempDirectory("dwarpal-console-e2e");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(bytes, true, StandardCharsets.UTF_8);
        Thread launcher = new Thread(() -> {
            try {
                ConsoleMain.run(new String[]{"--dir", dir.toString(), "--users", "30", "--warmup-days", "1", "--port", "0"},
                        out);
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
            String base = u.group(1);
            Map<String, String[]> people = new LinkedHashMap<>();
            Matcher l = LOGIN.matcher(log);
            while (l.find()) {
                people.put(l.group(1), new String[]{l.group(2), l.group(3)});
            }
            assertTrue(people.keySet().containsAll(List.of("ana", "cleo", "dana", "uma")), log);

            DevPki pki = DevPki.open(dir.resolve("pki"), Files.readString(dir.resolve("pki/pki.pass")).trim().toCharArray(),
                    List.of("console"));
            HttpClient http = HttpClient.newBuilder().sslContext(ConsoleFixture.trustOnlyTheLabCa(pki))
                    .version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(10)).build();

            assertEquals(401, get(http, base, "/console/api/me", null).statusCode(), "nobody is anybody until they log in");

            Session ana = login(http, base, "ana", people.get("ana"));
            HttpResponse<String> modules = get(http, base, "/console/api/modules", ana);
            assertEquals(200, modules.statusCode(), modules.body());
            assertTrue(modules.body().contains("\"guide\"") && modules.body().contains("\"lab\""), modules.body());
            assertEquals(200, get(http, base, "/console/api/soc/queue", ana).statusCode());
            assertEquals(200, get(http, base, "/console/api/lab", ana).statusCode());
            HttpResponse<String> verify = get(http, base, "/console/api/audit/verify", ana);
            assertEquals(200, verify.statusCode(), verify.body());
            assertTrue(verify.body().contains("\"intact\":true"), "the chain verifies from the page: " + verify.body());
            assertEquals(200, get(http, base, "/console/api/lab/scenarios", ana).statusCode());
            assertEquals(403, get(http, base, "/console/api/admin/policy", ana).statusCode(), "admin routes refuse an analyst");

            Session dana = login(http, base, "dana", people.get("dana"));
            HttpResponse<String> adminModules = get(http, base, "/console/api/modules", dana);
            assertTrue(adminModules.body().contains("\"admin\""), adminModules.body());
            assertEquals(403, get(http, base, "/console/api/soc/queue", dana).statusCode(),
                    "an administrator is not an analyst (segregation of duties)");

            Session uma = login(http, base, "uma", people.get("uma"));
            assertEquals(403, get(http, base, "/console/api/soc/queue", uma).statusCode());
            assertEquals(403, get(http, base, "/console/api/lab/scenarios", uma).statusCode());
        } finally {
            launcher.interrupt();
            launcher.join(30_000);
        }
    }

    private static String text(ByteArrayOutputStream b) {
        return b.toString(StandardCharsets.UTF_8);
    }

    private static HttpResponse<String> get(HttpClient http, String base, String path, Session s) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).timeout(Duration.ofSeconds(20))
                .header("User-Agent", "E2E/1");
        if (s != null) {
            b.header("Cookie", ConsoleServer.COOKIE + "=" + s.cookie());
        }
        return http.send(b.GET().build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static HttpResponse<String> post(HttpClient http, String base, String path, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(base + path)).timeout(Duration.ofSeconds(20))
                .header("User-Agent", "E2E/1").header("Origin", base).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static Session login(HttpClient http, String base, String user, String[] secrets) throws Exception {
        HttpResponse<String> first = post(http, base, "/console/api/session/login",
                "{\"user\":\"" + user + "\",\"password\":\"" + secrets[0] + "\"}");
        assertEquals(200, first.statusCode(), first.body());
        HttpResponse<String> done = post(http, base, "/console/api/session/verify",
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

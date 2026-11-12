package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The checks every request meets before any route runs (the request pipeline of {@link ConsoleServer}): CSRF, Origin,
 * content type, Host (DNS rebinding), methods (no CORS), body size, strict JSON, raw paths and query strings.
 */
class ConsoleRequestGuardTest {

    private static ConsoleFixture f;
    private static Sess ana;

    @BeforeAll
    static void start() throws Exception {
        f = ConsoleFixture.start(b -> ProbeModule.only().forEach(b::module), ConsoleSettings.defaults().fastHashing());
        ana = f.login("ana");
    }

    @AfterAll
    static void stop() {
        f.close();
    }

    private Map<String, String> writeHeaders() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("User-Agent", ConsoleFixture.UA);
        h.put("Origin", f.origin);
        h.put("Content-Type", "application/json");
        h.put("Cookie", ConsoleServer.COOKIE + "=" + ana.cookie());
        h.put(ConsoleServer.CSRF_HEADER, ana.csrf());
        return h;
    }

    private static final String NOTE_PATH = "/console/api/probe/change";

    @Test
    void aWriteNeedsTheAntiForgeryTokenTheOriginAndJson() throws Exception {
        assertEquals(200, f.raw("POST", NOTE_PATH, writeHeaders(), "{}").status(), "the well-formed write works");

        Map<String, String> noToken = writeHeaders();
        noToken.remove(ConsoleServer.CSRF_HEADER);
        assertEquals(403, f.raw("POST", NOTE_PATH, noToken, "{}").status());

        Map<String, String> wrongToken = writeHeaders();
        wrongToken.put(ConsoleServer.CSRF_HEADER, "x".repeat(43));
        assertEquals(403, f.raw("POST", NOTE_PATH, wrongToken, "{}").status());

        Map<String, String> noOrigin = writeHeaders();
        noOrigin.remove("Origin");
        assertEquals(403, f.raw("POST", NOTE_PATH, noOrigin, "{}").status(), "no Origin: refused, not guessed");

        for (String bad : List.of("https://evil.example", "null", "http://localhost:" + f.server.port(),
                "https://localhost:" + (f.server.port() + 1), "https://localhost.evil.example:" + f.server.port())) {
            Map<String, String> h = writeHeaders();
            h.put("Origin", bad);
            assertEquals(403, f.raw("POST", NOTE_PATH, h, "{}").status(), "Origin " + bad);
        }

        Map<String, String> crossSite = writeHeaders();
        crossSite.put("Sec-Fetch-Site", "cross-site");
        assertEquals(403, f.raw("POST", NOTE_PATH, crossSite, "{}").status());
        Map<String, String> sameSite = writeHeaders();
        sameSite.put("Sec-Fetch-Site", "same-site");
        assertEquals(403, f.raw("POST", NOTE_PATH, sameSite, "{}").status(), "a sibling site is not the console");

        for (String type : new String[]{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x",
                "application/json5"}) {
            Map<String, String> h = writeHeaders();
            h.put("Content-Type", type);
            assertEquals(415, f.raw("POST", NOTE_PATH, h, "{}").status(), type);
        }
        Map<String, String> utf8 = writeHeaders();
        utf8.put("Content-Type", "application/json; charset=utf-8");
        assertEquals(200, f.raw("POST", NOTE_PATH, utf8, "{}").status());
    }

    @Test
    void aWriteWithoutASessionIsRefusedBeforeAnythingElse() throws Exception {
        Map<String, String> h = writeHeaders();
        h.remove("Cookie");
        h.remove(ConsoleServer.CSRF_HEADER);
        assertEquals(401, f.raw("POST", NOTE_PATH, h, "{}").status());
    }

    @Test
    void onlyGetAndPostExistAndCorsDoesNot() throws Exception {
        for (String m : List.of("PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD")) {
            Resp r = f.raw(m, "/console/api/me", writeHeaders(), null);
            assertEquals(405, r.status(), m);
            assertNull(r.header("Access-Control-Allow-Origin"));
        }
        Map<String, String> preflight = new LinkedHashMap<>();
        preflight.put("Origin", "https://evil.example");
        preflight.put("Access-Control-Request-Method", "POST");
        Resp r = f.raw("OPTIONS", "/console/api/probe/change", preflight, null);
        assertEquals(405, r.status());
        assertNull(r.header("Access-Control-Allow-Origin"));
        assertNull(r.header("Access-Control-Allow-Credentials"));
        assertEquals(405, f.raw("POST", "/console/api/me", writeHeaders(), "{}").status(), "a read route does not take POST");
        assertEquals(405, f.raw("GET", NOTE_PATH, writeHeaders(), null).status(), "a write route does not take GET");
    }

    @Test
    void aForeignHostHeaderIsRefused() throws Exception {
        SSLContext ctx = ConsoleFixture.trustOnlyTheLabCa(f.pki);
        for (String host : List.of("evil.example", "evil.example:" + f.server.port(), "localhost", "localhost:1",
                "127.0.0.1.evil.example:" + f.server.port())) {
            String answer = rawRequest(ctx, "GET /console/api/me HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n");
            assertTrue(answer.startsWith("HTTP/1.1 421"), host + " -> " + answer.lines().findFirst().orElse(""));
        }
        String ok = rawRequest(ctx, "GET /console/app.js HTTP/1.1\r\nHost: 127.0.0.1:" + f.server.port()
                + "\r\nConnection: close\r\n\r\n");
        assertTrue(ok.startsWith("HTTP/1.1 200"), "the loopback address is one of the console's own names");
    }

    private String rawRequest(SSLContext ctx, String request) throws Exception {
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket("localhost", f.server.port())) {
            s.setSoTimeout(10_000);
            OutputStream out = s.getOutputStream();
            out.write(request.getBytes(StandardCharsets.US_ASCII));
            out.flush();
            InputStream in = s.getInputStream();
            ByteArrayOutputStream all = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) {
                all.write(buf, 0, n);
            }
            return all.toString(StandardCharsets.ISO_8859_1);
        }
    }

    @Test
    void bodiesAreBoundedAndJsonIsStrict() throws Exception {
        String big = "{\"x\":\"" + "a".repeat(40_000) + "\"}";
        assertEquals(413, f.raw("POST", NOTE_PATH, writeHeaders(), big).status());
        Map<String, String> login = new LinkedHashMap<>();
        login.put("User-Agent", ConsoleFixture.UA);
        login.put("Origin", f.origin);
        login.put("Content-Type", "application/json");
        for (String bad : List.of("not json", "[]", "{\"user\":\"ana\"}", "{\"user\":\"ana\",\"password\":\"p\",\"extra\":1}",
                "{\"user\":\"ana\",\"user\":\"ben\",\"password\":\"p\"}", "{\"user\":1,\"password\":\"p\"}",
                "{\"user\":\"\",\"password\":\"p\"}", "{\"user\":\"ana\",\"password\":\"p\"} trailing")) {
            Resp r = f.raw("POST", "/console/api/session/login", login, bad);
            assertEquals(400, r.status(), bad);
            assertEquals("{\"error\":\"invalid request\"}", r.body(), "one short error shape, never a reason: " + bad);
        }
    }

    @Test
    void rawPathsAndQueryStringsAreStrict() throws Exception {
        for (String p : List.of("/console/api//me", "/console/api/me/", "/console/api/%6de", "/console/api/me;x=1",
                "/console/api/soc/cases/..", "/console/api/soc/cases/%2e%2e", "/console/api/soc/cases/a%2fb",
                "/console/api/soc/cases/a\\b", "/console/api/soc/cases/" + "a".repeat(129), "/console/api/soc/cases/a b",
                "/console/api/soc/cases/a/timeline/x", "/console/api/" + "x/".repeat(200))) {
            Resp r = f.raw("GET", p.replace(" ", "%20").replace("\\", "%5C"), writeHeaders(), null);
            assertEquals(404, r.status(), p);
        }
        for (String q : List.of("?limit=abc", "?limit=1&limit=2", "?type=a%20b", "?type=x'y", "?=x", "?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9",
                "?after=-1")) {
            Resp r = f.raw("GET", "/console/api/audit/records" + q, writeHeaders(), null);
            assertEquals(400, r.status(), q);
        }
        assertEquals(200, f.raw("GET", "/console/api/audit/records?limit=5&after=0", writeHeaders(), null).status());
    }

    @Test
    void nothingEverRedirects() throws Exception {
        for (String p : List.of("/", "/console", "/console/", "/console/api/me", "/console/api/session/login",
                "/console/api/session/logout", "/index.html", "/console/index.html", "//evil.example/", "/login?next=https://evil.example")) {
            Resp r = f.get(p, ana);
            assertFalse(r.status() >= 300 && r.status() < 400 && r.status() != 304, p + " " + r.status());
            assertNull(r.header("Location"), p);
        }
    }
}

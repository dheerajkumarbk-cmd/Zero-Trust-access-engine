package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Resp;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Standards section 3, "Static files": a fixed allow-list, exact names, correct types, nothing resolved from input. */
class ConsoleStaticTest {

    private static ConsoleFixture f;

    @BeforeAll
    static void start() throws Exception {
        f = ConsoleFixture.start(b -> ProbeModule.only().forEach(b::module), ConsoleSettings.defaults().fastHashing());
    }

    @AfterAll
    static void stop() {
        f.close();
    }

    @Test
    void theShellIsServedAtTheRootAndUnderConsole() throws Exception {
        String root = f.get("/", null).body();
        assertTrue(root.contains("<title>fixture</title>"));
        assertEquals(root, f.get("/console", null).body());
        assertEquals(root, f.get("/console/", null).body());
        assertEquals(root, f.get("/console/index.html", null).body());
        assertEquals(200, f.get("/console/views/overview.js", null).status());
    }

    @Test
    void onlyAllowListedTypesAndNamesAreServed() throws Exception {
        for (String p : List.of("/console/notes.md", "/console/.hidden.js", "/console/api/leak.js", "/console/modules/",
                "/console/views/", "/console/views", "/console/modules/probe/", "/console/data", "/console/APP.JS",
                "/console/app.js/", "/console/app.js.map", "/favicon.ico", "/robots.txt", "/pom.xml", "/console/index")) {
            assertEquals(404, f.get(p, null).status(), p);
        }
        assertEquals(200, f.get("/console/data.txt", null).status());
    }

    @Test
    void noRequestPathIsEverTurnedIntoAFilePath() throws Exception {
        SSLContext ctx = ConsoleFixture.trustOnlyTheLabCa(f.pki);
        for (String p : List.of("/console/../pom.xml", "/console/../../../../windows/win.ini", "/console/%2e%2e/pom.xml",
                "/console/..%2fpom.xml", "/console/%2e%2e%2fpom.xml", "/console/..%5cpom.xml", "/console\\app.js",
                "/console//app.js", "/console/./app.js", "/console/app.js%00.png", "/console/app.js;.png",
                "/console/views/../app.js", "/console/%252e%252e/pom.xml", "/console/....//pom.xml", "/console/app.js%20",
                "/console/é.js", "/./console/app.js", "/console/modules/probe/../../app.js")) {
            String status = rawStatus(ctx, p);
            assertTrue(status.startsWith("HTTP/1.1 404") || status.startsWith("HTTP/1.1 400"), p + " -> " + status);
        }
    }

    private String rawStatus(SSLContext ctx, String path) throws Exception {
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket("localhost", f.server.port())) {
            s.setSoTimeout(10_000);
            OutputStream out = s.getOutputStream();
            out.write(("GET " + path + " HTTP/1.1\r\nHost: localhost:" + f.server.port() + "\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.UTF_8));
            out.flush();
            InputStream in = s.getInputStream();
            ByteArrayOutputStream all = new ByteArrayOutputStream();
            byte[] buf = new byte[2048];
            int n;
            while ((n = in.read(buf)) > 0) {
                all.write(buf, 0, n);
            }
            String text = all.toString(StandardCharsets.ISO_8859_1);
            assertFalse(text.contains("leak") || text.contains("<project") || text.contains("[fonts]"), "no file content: " + path);
            return text.lines().findFirst().orElse("");
        }
    }

    @Test
    void filesRevalidateWithAnEtag() throws Exception {
        Resp first = f.get("/console/app.js", null);
        String etag = first.header("ETag");
        assertTrue(etag != null && etag.startsWith("\""));
        Map<String, String> h = new LinkedHashMap<>();
        h.put("If-None-Match", etag);
        Resp again = f.raw("GET", "/console/app.js", h, null);
        assertEquals(304, again.status());
        assertEquals("", again.body());
        assertEquals("no-cache", again.header("Cache-Control"));
        h.put("If-None-Match", "\"something-else\"");
        assertEquals(200, f.raw("GET", "/console/app.js", h, null).status());
    }

    @Test
    void staticFilesTakeNoPost() throws Exception {
        assertEquals(405, f.raw("POST", "/console/app.js", Map.of("Origin", f.origin, "Content-Type", "application/json"), "{}").status());
    }

    @Test
    void theNameRuleRefusesWhatShouldNeverBeServed() {
        for (String bad : List.of("", ".env", "a/.git/config", "a/../b.js", "api/x.js", "api", "a b.js", "a%2eb.js", "a\\b.js",
                "x".repeat(201), "a//b.js", "é.js")) {
            assertFalse(StaticFiles.safeName(bad), bad);
        }
        for (String good : List.of("index.html", "views/overview.js", "modules/probe/index.js", "a-b_c.1.css")) {
            assertTrue(StaticFiles.safeName(good), good);
        }
    }

    @Test
    void theAllowListLoadsFromAJarAsItDoesInProduction(@TempDir Path dir) throws Exception {
        Path jar = dir.resolve("console.jar");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
            for (String d : new String[]{"cj/", "cj/sub/", "cj/api/"}) {
                out.putNextEntry(new JarEntry(d));
                out.closeEntry();
            }
            for (String[] e : new String[][]{{"cj/index.html", "<html></html>"}, {"cj/app.js", "export {};"},
                    {"cj/secret.pem", "-----BEGIN"}, {"cj/.hidden.js", "x"}, {"cj/sub/view.css", "a{}"}, {"cj/api/x.js", "x"}}) {
                out.putNextEntry(new JarEntry(e[0]));
                out.write(e[1].getBytes(StandardCharsets.UTF_8));
                out.closeEntry();
            }
        }
        try (URLClassLoader loader = new URLClassLoader(new URL[]{jar.toUri().toURL()}, null)) {
            StaticFiles files = StaticFiles.fromClasspath(loader, "cj");
            assertEquals(3, files.size(), "html, js and css only; the pem, the dot file and api/ are not served");
            assertTrue(files.get("sub/view.css").isPresent());
            assertFalse(files.get("secret.pem").isPresent());
            assertFalse(files.get("../cj/index.html").isPresent());
        }
    }
}

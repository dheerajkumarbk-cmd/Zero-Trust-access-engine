package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Standards section 3: transport, the exact response headers on every answer, cookie attributes, no CORS. */
class ConsoleHeadersTest {

    private static ConsoleFixture f;

    @BeforeAll
    static void start() throws Exception {
        f = ConsoleFixture.start(b -> ProbeModule.only().forEach(b::module), ConsoleSettings.defaults().fastHashing());
    }

    @AfterAll
    static void stop() {
        f.close();
    }

    private static void assertBaseline(Resp r, String what) {
        for (Map.Entry<String, String> h : SecurityHeaders.ALL.entrySet()) {
            assertEquals(h.getValue(), r.header(h.getKey()), what + ": " + h.getKey());
        }
        assertNotNull(r.header("Cache-Control"), what + ": Cache-Control");
        assertEquals(null, r.header("Access-Control-Allow-Origin"), what + ": CORS is not enabled");
        assertEquals(null, r.header("Server"), what + ": no server banner");
    }

    @Test
    void theHeadersAreExactlyTheStandardsAndAreOnEveryKindOfAnswer() throws Exception {
        Sess ana = f.login("ana");
        List<Resp> all = List.of(
                f.get("/", null), f.get("/console/app.js", null), f.get("/console/nope.js", null),
                f.get("/console/api/me", null), f.get("/console/api/me", ana), f.get("/console/api/nope", ana),
                f.get("/console/api/soc/queue", ana), f.get("/console/api/audit/head", ana),
                f.raw("DELETE", "/console/api/me", Map.of("User-Agent", ConsoleFixture.UA), null),
                f.post("/console/api/session/login", null, "not json"),
                f.post("/console/api/session/login", null, "{\"user\":\"ana\",\"password\":\"wrong-password-1\"}"));
        for (Resp r : all) {
            assertBaseline(r, "status " + r.status());
        }
        assertEquals("max-age=63072000; includeSubDomains", all.get(0).header("Strict-Transport-Security"));
        assertTrue(SecurityHeaders.CSP.contains("require-trusted-types-for 'script'") && !SecurityHeaders.CSP.contains("unsafe-"));
    }

    @Test
    void apiAnswersAreNeverCachedAndStaticFilesAreAlwaysRevalidated() throws Exception {
        Sess ana = f.login("ana");
        assertEquals("no-store", f.get("/console/api/me", ana).header("Cache-Control"));
        assertEquals("no-store", f.get("/console/api/soc/queue", ana).header("Cache-Control"));
        assertEquals("no-store", f.get("/console/api/me", null).header("Cache-Control"), "even the refusal");
        assertEquals("no-cache", f.get("/console/app.js", null).header("Cache-Control"));
    }

    @Test
    void staticFilesCarryTheirOwnContentTypeAndNosniff() throws Exception {
        assertEquals("text/html; charset=utf-8", f.get("/", null).header("Content-Type"));
        assertEquals("text/javascript; charset=utf-8", f.get("/console/app.js", null).header("Content-Type"));
        assertEquals("text/css; charset=utf-8", f.get("/console/style.css", null).header("Content-Type"));
        assertEquals("nosniff", f.get("/console/app.js", null).header("X-Content-Type-Options"));
    }

    @Test
    void theSessionCookieIsHostPrefixedSecureHttpOnlyStrictAndWholeSite() throws Exception {
        ConsoleAuth.Enrolment e = f.person("ben");
        Resp r = f.login("ben", e.password(), e.pin());
        assertEquals(200, r.status());
        String cookie = r.headers().allValues("Set-Cookie").getFirst();
        assertTrue(cookie.startsWith("__Host-dwarpal="), cookie);
        assertTrue(cookie.contains("; Secure") && cookie.contains("; HttpOnly") && cookie.contains("; SameSite=Strict")
                && cookie.contains("; Path=/"), cookie);
        assertFalse(cookie.toLowerCase().contains("domain="), "a __Host- cookie has no Domain: " + cookie);
        assertEquals(1, r.headers().allValues("Set-Cookie").size());
    }

    @Test
    void onlyTls13Works() throws Exception {
        SSLContext ctx = ConsoleFixture.trustOnlyTheLabCa(f.pki);
        javax.net.ssl.SSLParameters p12 = ctx.getDefaultSSLParameters();
        p12.setProtocols(new String[]{"TLSv1.2"});
        HttpClient old = HttpClient.newBuilder().sslContext(ctx).sslParameters(p12).connectTimeout(Duration.ofSeconds(5)).build();
        assertThrows(IOException.class, () -> old.send(HttpRequest.newBuilder(URI.create(f.base + "/")).build(),
                HttpResponse.BodyHandlers.ofString()), "TLS 1.2 is refused");
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket("localhost", f.server.port())) {
            s.startHandshake();
            assertEquals("TLSv1.3", s.getSession().getProtocol());
            assertTrue(List.of("TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256")
                    .contains(s.getSession().getCipherSuite()));
        }
    }

    @Test
    void thereIsNoPlainHttpListener() {
        HttpClient plain = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        assertThrows(IOException.class, () -> plain.send(HttpRequest.newBuilder(URI.create("http://localhost:"
                + f.server.port() + "/")).timeout(Duration.ofSeconds(5)).build(), HttpResponse.BodyHandlers.ofString()));
    }

    @Test
    void aClientThatDoesNotTrustTheLabCaCannotConnect() {
        HttpClient stranger = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        assertThrows(SSLHandshakeException.class, () -> stranger.send(HttpRequest.newBuilder(URI.create(f.base + "/"))
                .build(), HttpResponse.BodyHandlers.ofString()));
    }
}

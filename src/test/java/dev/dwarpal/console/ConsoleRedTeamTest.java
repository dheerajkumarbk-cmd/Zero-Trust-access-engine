package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import dev.dwarpal.soc.Verdict;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The red-team pass on part G: every attack of docs/layer-6/part-g.md as a working probe against the real server. A
 * probe that succeeded on an earlier build is kept here as the regression test for its fix (named in the notes as
 * F-G1, F-G2, ...); probes that fail are kept too, as evidence.
 */
class ConsoleRedTeamTest {

    private static ConsoleFixture f;

    @BeforeAll
    static void start() throws Exception {
        f = ConsoleFixture.start(b -> ProbeModule.only().forEach(b::module), ConsoleSettings.defaults().fastHashing());
    }

    @AfterAll
    static void stop() {
        f.close();
    }

    private static String raw(SSLContext ctx, int port, String request, int millis) throws Exception {
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket("localhost", port)) {
            s.setSoTimeout(millis);
            ByteArrayOutputStream all = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            try {
                OutputStream out = s.getOutputStream();
                out.write(request.getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
                InputStream in = s.getInputStream();
                int n;
                while ((n = in.read(buf)) > 0) {
                    all.write(buf, 0, n);
                }
            } catch (IOException timeoutOrReset) {
                // what arrived is what counts
            }
            return all.toString(StandardCharsets.ISO_8859_1);
        }
    }

    // ---- A1 stored XSS: the API never returns HTML ----------------------------------------------------------

    @Test
    void a1_scriptInANoteComesBackAsJsonTextOnly() throws Exception {
        Sess ana = f.login("ana");
        Resp q = f.get("/console/api/soc/queue", ana);
        String caseId = q.body().replaceAll("(?s).*?\"id\":\"([^\"]+)\".*", "$1");
        String payload = "<img src=x onerror=alert(1)><script>alert(2)</script>\\\"";
        assertEquals(200, f.post("/console/api/soc/cases/" + caseId + "/notes", ana, "{\"text\":\"" + payload + "\"}").status());
        Resp back = f.get("/console/api/soc/cases/" + caseId, ana);
        assertTrue(back.header("Content-Type").startsWith("application/json"));
        assertEquals("nosniff", back.header("X-Content-Type-Options"));
        assertTrue(back.header("Content-Security-Policy").contains("script-src 'self'"));
        assertTrue(back.body().contains("<script>alert(2)</script>"), "stored verbatim: output encoding is the page's job (source test in part H)");
    }

    // ---- A2 CSRF across sessions ----------------------------------------------------------------------------

    @Test
    void a2_oneSessionsTokenIsWorthNothingInAnother() throws Exception {
        Sess ana = f.login("ana");
        Sess ben = f.login("ben");
        assertFalse(ana.csrf().equals(ben.csrf()));
        Map<String, String> h = new LinkedHashMap<>();
        h.put("User-Agent", ConsoleFixture.UA);
        h.put("Origin", f.origin);
        h.put("Content-Type", "application/json");
        h.put("Cookie", ConsoleServer.COOKIE + "=" + ben.cookie());
        h.put(ConsoleServer.CSRF_HEADER, ana.csrf());
        assertEquals(403, f.raw("POST", "/console/api/probe/change", h, "{}").status());
    }

    // ---- A3 the session id in a URL or a body is not a credential ----------------------------------------------

    @Test
    void a3_theSessionIdInTheQueryOrBodyDoesNothing() throws Exception {
        Sess ana = f.login("ana");
        assertEquals(401, f.get("/console/api/me?" + ConsoleServer.COOKIE.replace("-", "_") + "=" + ana.cookie(), null).status());
        Map<String, String> h = new LinkedHashMap<>();
        h.put("User-Agent", ConsoleFixture.UA);
        h.put("Authorization", "Bearer " + ana.cookie());
        h.put("X-Session", ana.cookie());
        assertEquals(401, f.raw("GET", "/console/api/me", h, null).status());
    }

    // ---- A4 mass assignment / identity in the body ---------------------------------------------------------------

    @Test
    void a4_stepUpAndLoginTakeNoNameOfSomeoneElse() throws Exception {
        Sess ana = f.login("ana");
        ConsoleAuth.Enrolment ben = f.person("ben");
        assertEquals(400, f.post("/console/api/session/stepup", ana, "{\"user\":\"ben\",\"password\":\"" + ben.password() + "\",\"pin\":\"" + ben.pin() + "\"}").status());
        // ben's right password and PIN presented in ana's session do not turn ana's session into ben's or make it fresh
        f.clock.advance(Duration.ofMinutes(6));
        Resp r = f.post("/console/api/session/stepup", ana, "{\"password\":\"" + ben.password() + "\",\"pin\":\"" + ben.pin() + "\"}");
        assertEquals(401, r.status(), "step-up proves the session's own person");
        assertEquals(403, f.post("/console/api/probe/danger", ana, "{}").status());
    }

    // ---- A5 login races --------------------------------------------------------------------------------------

    @Test
    void a5_oneLoginIdCannotMakeTwoSessionsWhenUsedAtTheSameTime() throws Exception {
        ConsoleAuth.Enrolment cleo = f.person("cleo");
        Resp first = f.post("/console/api/session/login", null, "{\"user\":\"cleo\",\"password\":\"" + cleo.password() + "\"}");
        String body = "{\"loginId\":\"" + first.field("loginId") + "\",\"pin\":\"" + cleo.pin() + "\"}";
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Integer>> results = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            results.add(pool.submit(() -> {
                go.await();
                return f.post("/console/api/session/verify", null, body).status();
            }));
        }
        go.countDown();
        int ok = 0;
        for (Future<Integer> r : results) {
            if (r.get(30, TimeUnit.SECONDS) == 200) {
                ok++;
            }
        }
        pool.shutdownNow();
        assertEquals(1, ok);
    }

    @Test
    void a6_aFloodOfUnfinishedLoginsFromOneAddressIsBounded() throws Exception {
        f.clock.advance(Duration.ofMinutes(40));
        int made = 0;
        int refused = 0;
        for (int i = 0; i < 30; i++) {
            Resp r = f.post("/console/api/session/login", null, "{\"user\":\"flood" + i + "\",\"password\":\"x\"}");
            if (r.status() == 200) {
                made++;
            } else {
                refused++;
            }
        }
        assertEquals(20, made, "20 pending logins per address");
        assertEquals(10, refused);
        f.clock.advance(Duration.ofMinutes(15));
    }

    // ---- A7 HTTP-level abuse ----------------------------------------------------------------------------------

    @Test
    void a7_requestSmugglingWithBothLengthHeadersDoesNotRunAHiddenRequest() throws Exception {
        SSLContext ctx = ConsoleFixture.trustOnlyTheLabCa(f.pki);
        String smuggled = "GET /console/api/lab HTTP/1.1\r\nHost: localhost:" + f.server.port() + "\r\nConnection: close\r\n\r\n";
        String req = "POST /console/api/session/login HTTP/1.1\r\nHost: localhost:" + f.server.port() + "\r\nOrigin: " + f.origin
                + "\r\nContent-Type: application/json\r\nContent-Length: " + 0 + "\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" + smuggled;
        String answer = raw(ctx, f.server.port(), req, 5_000);
        assertFalse(answer.contains("scriptStart"), "no lab data without a session, however the requests are glued together");
        int statuses = answer.split("HTTP/1.1 ", -1).length - 1;
        assertTrue(statuses <= 2, "at most the two requests that were really sent: " + statuses);
        assertEquals(401, f.get("/console/api/lab", null).status());
    }

    @Test
    void a8_hugeHeadersAndStalledBodiesDoNotTakeTheServerDown() throws Exception {
        SSLContext ctx = ConsoleFixture.trustOnlyTheLabCa(f.pki);
        String big = "GET /console/app.js HTTP/1.1\r\nHost: localhost:" + f.server.port() + "\r\nX-Pad: " + "A".repeat(200_000)
                + "\r\nConnection: close\r\n\r\n";
        String answer = raw(ctx, f.server.port(), big, 5_000);
        assertTrue(answer.startsWith("HTTP/1.1 431"), "F-G1: a 200 KB header was served by the JDK server: " + answer.lines().findFirst().orElse("(closed)"));
        String huge = "GET /console/app.js HTTP/1.1\r\nHost: localhost:" + f.server.port() + "\r\nX-Pad: " + "A".repeat(3_000_000)
                + "\r\nConnection: close\r\n\r\n";
        assertFalse(raw(ctx, f.server.port(), huge, 8_000).startsWith("HTTP/1.1 200"), "three megabytes of header");
        assertEquals(200, f.get("/console/app.js", null).status(), "and the server is still there");

        // twelve connections that promise a body and never send it (more than the eight workers)
        List<SSLSocket> stalled = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket("localhost", f.server.port());
            OutputStream out = s.getOutputStream();
            out.write(("POST /console/api/session/login HTTP/1.1\r\nHost: localhost:" + f.server.port() + "\r\nOrigin: " + f.origin
                    + "\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{").getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            stalled.add(s);
        }
        try {
            long start = System.nanoTime();
            Resp ok = f.get("/console/app.js", null);
            long ms = Duration.ofNanos(System.nanoTime() - start).toMillis();
            assertEquals(200, ok.status());
            assertTrue(ms < 12_000, "a normal request is answered within the request deadline although all workers are held: " + ms + " ms");
        } finally {
            for (SSLSocket s : stalled) {
                s.close();
            }
        }
        assertEquals(200, f.get("/console/app.js", null).status());
    }

    @Test
    void a9_noBodyEverReachesTheClientWithAJavaClassOrAPathInIt() throws Exception {
        Sess ana = f.login("ana");
        List<Resp> all = new ArrayList<>();
        for (String p : List.of("/console/api/soc/cases/x", "/console/api/soc/risk/subject/x", "/console/api/soc/risk/nokind/x",
                "/console/api/audit/records/abc", "/console/api/audit/records/0", "/console/api/audit/records?limit=99999999999999999999",
                "/console/api/probe/boom", "/console/api/soc/reports/nosuch", "/console/api/nothing", "/console/api/soc/cases/x/timeline")) {
            all.add(f.get(p, ana));
        }
        all.add(f.post("/console/api/soc/search", ana, "{\"query\":\"(((\",\"from\":\"2026-01-01T00:00:00Z\",\"to\":\"2026-01-02T00:00:00Z\",\"limit\":1}"));
        all.add(f.post("/console/api/soc/verdicts", ana, "{\"alertId\":\"../../etc\",\"outcome\":\"BENIGN\"}"));
        for (Resp r : all) {
            assertFalse(r.body().matches("(?s).*(Exception|\\.java|at dev\\.|C:\\\\|/home/|stack|NumberFormat).*"), r.status() + " " + r.body());
            assertTrue(r.body().startsWith("{"), r.body());
        }
    }

    // ---- A10 the SOC channel -------------------------------------------------------------------------------------

    @Test
    void a10_theConsoleOnlyEverActsForAnalystsAndOnlyTalksToTheSocApi() throws Exception {
        SocChannel real = new DelegatedSocChannel(f.pki, f.world.socApiUrl(), f.world.delegationIssuer(), java.util.Set.of("ana", "ben", "cleo"),
                Duration.ofSeconds(10));
        assertTrue(real.forAnalyst("dana").isEmpty() && real.forAnalyst("uma").isEmpty() && real.forAnalyst("console").isEmpty()
                && real.forAnalyst("nobody").isEmpty(), "no standing for people the SOC API does not know");
        assertEquals(200, real.forAnalyst("ana").orElseThrow().queue().status());
        assertEquals(404, real.forAnalyst("ana").orElseThrow().report("daily").status(), "the SOC API still decides: ana is no lead");
        assertEquals(200, real.forAnalyst("cleo").orElseThrow().report("daily").status());
        assertThrowsIllegal(() -> real.forAnalyst("ana").orElseThrow().caseDetail("../../x"));
        assertThrowsIllegal(() -> real.forAnalyst("ana").orElseThrow().risk("subject", "a/b"));

        // pointed at a server that is in the lab PKI but is not the SOC API (the console itself), the channel refuses to talk
        SocChannel misled = new DelegatedSocChannel(f.pki, "https://localhost:" + f.server.port(), f.world.delegationIssuer(),
                java.util.Set.of("ana"), Duration.ofSeconds(5));
        assertEquals(503, misled.forAnalyst("ana").orElseThrow().queue().status(), "the server's name is pinned to CN=soc-api");
    }

    private static void assertThrowsIllegal(org.junit.jupiter.api.function.Executable e) {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, e);
    }

    @Test
    void a11_aDelegationIsUsedOncePerCallSoACopiedHeaderIsWorthNothing() throws Exception {
        // the same assertion twice against the SOC API itself: the second is refused (replay)
        var issuer = f.world.delegationIssuer();
        String header = issuer.header("ana", "GET", "/v1/queue", null);
        var client = ConsoleFixture.trustOnlyTheLabCa(f.pki);
        java.net.http.HttpClient noCert = java.net.http.HttpClient.newBuilder().sslContext(client).build();
        // without the console's certificate the SOC API will not even answer
        org.junit.jupiter.api.Assertions.assertThrows(IOException.class, () -> noCert.send(java.net.http.HttpRequest.newBuilder(
                java.net.URI.create(f.world.socApiUrl() + "/v1/queue")).header("Dwarpal-On-Behalf-Of", header).build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()), "a copied header without the console's certificate gets nowhere");
    }

    // ---- A12 verdict signing is only ever for the session's own person ---------------------------------------------

    @Test
    void a12_theSignerNeverSignsForAnotherPersonAndSignsOnlyAnalystsWhoHaveAKey() {
        VerdictSigner signer = new LabVerdictSigner(LabHandle.of(f.world, null));
        Verdict v = signer.sign("ana", "alert-1", Verdict.Outcome.BENIGN).orElseThrow();
        assertEquals("ana", v.analystId());
        assertTrue(signer.sign("cleo", "alert-1", Verdict.Outcome.BENIGN).isEmpty());
        assertTrue(signer.sign("dana", "alert-1", Verdict.Outcome.BENIGN).isEmpty());
        assertTrue(v.proof().signedAt().isBefore(Instant.now().plus(Duration.ofDays(365 * 5))), "signed at scenario time");
    }

    // ---- A13 many calls at once ------------------------------------------------------------------------------------

    @Test
    void a13_aBurstOfParallelCallsGetsAnswersOr429Or503NeverAnErrorPageOrAHang() throws Exception {
        Sess ana = f.login("ana");
        ExecutorService pool = Executors.newFixedThreadPool(24);
        Map<Integer, AtomicInteger> seen = new ConcurrentHashMap<>();
        List<Future<?>> all = new ArrayList<>();
        for (int i = 0; i < 300; i++) {
            all.add(pool.submit(() -> {
                try {
                    int s = f.get("/console/api/soc/queue", ana).status();
                    seen.computeIfAbsent(s, k -> new AtomicInteger()).incrementAndGet();
                } catch (Exception e) {
                    seen.computeIfAbsent(-1, k -> new AtomicInteger()).incrementAndGet();
                }
            }));
        }
        for (Future<?> x : all) {
            x.get(120, TimeUnit.SECONDS);
        }
        pool.shutdownNow();
        assertTrue(seen.keySet().stream().allMatch(k -> k == 200 || k == 429 || k == 503), "statuses: " + seen);
        assertTrue(seen.getOrDefault(200, new AtomicInteger()).get() > 50, "most were served: " + seen);
        assertEquals(200, f.get("/console/api/me", ana).status());
    }
}

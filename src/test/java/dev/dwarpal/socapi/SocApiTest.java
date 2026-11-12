package dev.dwarpal.socapi;

import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.soar.SoarWorld;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Verdict;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The SOC API over real mutual TLS: who may call, strict input, visibility, writes, limits and audit. */
class SocApiTest {

    private final SocApiKit kit = new SocApiKit();
    private final SoarWorld w = kit.world;

    @AfterEach
    void stop() {
        kit.close();
    }

    static String verdictJson(Verdict v) {
        return "{\"v\":1,\"alertId\":\"" + v.alertId() + "\",\"analystId\":\"" + v.analystId() + "\",\"outcome\":\""
                + v.outcome() + "\",\"proof\":{\"keyId\":\"" + v.proof().keyId() + "\",\"signedAt\":\""
                + v.proof().signedAt() + "\",\"signature\":\"" + v.proof().signature() + "\"}}";
    }

    // ---- who may call -------------------------------------------------------------------------------------------

    @Test
    void onlyConfiguredAnalystsByExactCertificateSubject() throws Exception {
        try (SocApiKit.Client stranger = kit.as("stranger")) {
            SocApiKit.Reply r = stranger.get("/v1/health");
            assertEquals(403, r.status());
            assertEquals("{\"error\":\"forbidden\"}", r.body());
        }
        try (SocApiKit.Client rogue = kit.rogue("ana")) {
            assertThrows(IOException.class, () -> rogue.get("/v1/health"), "another CA's 'ana' fails the handshake");
        }
        try (SocApiKit.Client old = kit.as("old-ana")) {
            assertThrows(IOException.class, () -> old.get("/v1/health"), "expired certificate");
        }
        try (SocApiKit.Client ana = kit.as("ana")) {
            assertEquals(200, ana.get("/v1/health").status());
        }
        // exact, case-sensitive subjects
        assertTrue(kit.server.caller(TlsContexts.component("ana")).isPresent());
        assertTrue(kit.server.caller(new javax.security.auth.x500.X500Principal("CN=ANA")).isEmpty());
    }

    @Test
    void callersMustBeAnalystsOfCaseManagementAndUnique() {
        SocApiServer.Builder b = SocApiServer.builder(w.audit, w.soar).tls(SocApiKit.ctx(SocApiKit.pki(), "soc-api"))
                .search(kit.search).risk(kit.risk);
        assertThrows(IllegalArgumentException.class, () -> b.callers(List.of()).build());
        assertThrows(IllegalArgumentException.class, () -> b.callers(List.of(SocCaller.component("x",
                new dev.dwarpal.soar.Analyst("mallory", dev.dwarpal.soar.Analyst.Role.LEAD)))).build());
        assertThrows(IllegalArgumentException.class, () -> b.callers(List.of(SocCaller.component("x",
                new dev.dwarpal.soar.Analyst("ana", dev.dwarpal.soar.Analyst.Role.LEAD)))).build(), "ana is not a lead");
        assertThrows(IllegalArgumentException.class, () -> b.callers(List.of(SocCaller.component("x", SoarWorld.ANA),
                SocCaller.component("x", SoarWorld.BEN))).build());
        assertThrows(IllegalArgumentException.class, () -> new SocCaller("cn=a,  o=b", SoarWorld.ANA));
    }

    // ---- routes and strict input --------------------------------------------------------------------------------

    @Test
    void pathsMustMatchExactlyAndParametersArePlainIdentifiers() throws Exception {
        String c = w.caseOf(w.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice")));
        try (SocApiKit.Client ana = kit.as("ana")) {
            assertEquals(200, ana.get("/v1/cases/" + c).status());
            for (String bad : List.of("/v1/cases/" + c + "/", "/v1/cases/" + c + "?x=1", "/v1/cases/%63ase-1",
                    "/v1/cases/..%2fadmin", "/v1/Cases/" + c, "/v1//cases", "/v1/cases/" + c + ";x", "/v2/health",
                    "/v1/risk/subject", "/v1/cases/a..b")) {
                SocApiKit.Reply r = ana.get(bad);
                assertEquals(404, r.status(), bad);
                assertEquals("{\"error\":\"not found\"}", r.body());
            }
            assertEquals(405, ana.method("DELETE", "/v1/cases/" + c).status());
            assertEquals(405, ana.post("/v1/queue", "{}").status());
        }
    }

    @Test
    void bodiesAreStrict() throws Exception {
        String c = w.caseOf(w.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice")));
        String path = "/v1/cases/" + c + "/notes";
        try (SocApiKit.Client ana = kit.as("ana")) {
            assertEquals(415, ana.post(path, "text/plain", "{\"v\":1,\"text\":\"x\"}".getBytes(StandardCharsets.UTF_8))
                    .status());
            assertEquals(413, ana.post(path, "{\"v\":1,\"text\":\"" + "x".repeat(17_000) + "\"}").status());
            for (String bad : List.of("{\"v\":1,\"text\":\"a\",\"text\":\"b\"}", "{\"v\":1,\"text\":\"a\",\"admin\":true}",
                    "{\"v\":2,\"text\":\"a\"}", "{\"text\":\"a\"}", "{\"v\":1,\"text\":7}", "[1]", "{\"v\":1,\"text\":\"\"}",
                    "{\"v\":1.0,\"text\":\"a\"}", "{\"v\":1,\"text\":\"a\"", "nul", "{\"v\":1,\"text\":\""
                            + "y".repeat(4001) + "\"}")) {
                SocApiKit.Reply r = ana.post(path, bad);
                assertEquals(400, r.status(), bad.length() > 60 ? bad.substring(0, 60) : bad);
                assertEquals("{\"error\":\"invalid request\"}", r.body());
            }
            assertEquals(200, ana.post(path, "{\"v\":1,\"text\":\"checked with the user\"}").status());
            assertEquals(400, ana.post(path, "{\"v\":1,\"text\":\"" + "z".repeat(2_001) + "\"}").status(),
                    "longer than the case limit");
        }
        assertEquals(1, w.cases.view(c).orElseThrow().notes().size());
    }

    @Test
    void aRefusedOversizedBodyDoesNotHangTheNextCall() throws Exception {
        String c = w.caseOf(w.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice")));
        String path = "/v1/cases/" + c + "/notes";
        try (SocApiKit.Client ana = kit.as("ana")) {
            for (int i = 0; i < 10; i++) {
                assertEquals(413, ana.post(path, "{\"v\":1,\"text\":\"" + "x".repeat(17_000) + "\"}").status());
                assertEquals(400, ana.post(path, "{\"v\":2,\"text\":\"a\"}").status(), "the connection is not reused");
            }
        }
    }

    // ---- reads --------------------------------------------------------------------------------------------------

    @Test
    void theQueueShowsWhatEachAnalystMaySeeMostUrgentFirst() throws Exception {
        w.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice"));
        w.raise("mfa-fatigue", Severity.CRITICAL, Entity.subject("carol"));
        w.raise("dlp-block-spike", Severity.MEDIUM, Entity.subject("ben"));
        try (SocApiKit.Client ana = kit.as("ana"); SocApiKit.Client cleo = kit.as("cleo")) {
            SocApiKit.Reply q = ana.get("/v1/queue");
            assertEquals(200, q.status());
            assertTrue(q.body().indexOf("carol") < q.body().indexOf("alice"), q.body());
            assertFalse(q.body().contains("\"ben\""), "ana does not see the case about ben");
            assertTrue(cleo.get("/v1/queue").body().contains("\"ben\""), "the lead does");
            assertTrue(ana.get("/v1/cases").body().contains("\"P1\""));
        }
    }

    @Test
    void caseDetailAndTimeline() throws Exception {
        String al = w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("alice"), Entity.device("laptop-alice"));
        String c = w.caseOf(al);
        try (SocApiKit.Client ana = kit.as("ana")) {
            SocApiKit.Reply d = ana.get("/v1/cases/" + c);
            assertEquals(200, d.status());
            assertTrue(d.body().contains("\"rankedAlerts\""));
            assertTrue(d.body().contains("\"actionable\":true"));
            assertTrue(d.body().contains("T1078"));
            SocApiKit.Reply t = ana.get("/v1/cases/" + c + "/timeline");
            assertEquals(200, t.status());
            assertTrue(t.body().contains("\"kind\":\"opened\""));
            assertEquals(404, ana.get("/v1/cases/case-404").status());
            assertEquals(404, ana.get("/v1/cases/case-404/timeline").status());
        }
    }

    @Test
    void entityRiskRespectsVisibility() throws Exception {
        kit.risk.scores.put(Entity.subject("alice"), 62.0);
        kit.risk.scores.put(Entity.subject("ben"), 80.0);
        kit.risk.scores.put(Entity.subject("ana"), 40.0);
        try (SocApiKit.Client ana = kit.as("ana"); SocApiKit.Client cleo = kit.as("cleo")) {
            SocApiKit.Reply r = ana.get("/v1/risk/subject/alice");
            assertEquals(200, r.status());
            assertTrue(r.body().contains("\"level\":\"HIGH\""), r.body());
            assertTrue(r.body().contains("\"score\":62.0"));
            assertEquals(404, ana.get("/v1/risk/subject/ana").status(), "not about herself");
            assertEquals(404, ana.get("/v1/risk/subject/ben").status(), "not about a colleague");
            assertEquals(200, cleo.get("/v1/risk/subject/ben").status(), "a lead may");
            assertEquals(404, ana.get("/v1/risk/person/alice").status());
            assertEquals(200, ana.get("/v1/risk/device/laptop-alice").status());
            assertEquals(200, ana.get("/v1/risk/ip/203.0.113.5").status());
            assertEquals(200, ana.get("/v1/risk/session/s-1").status());
            assertEquals(200, ana.get("/v1/risk/resource/wiki").status());
            String top = ana.get("/v1/risk/top").body();
            assertTrue(top.contains("alice"));
            assertFalse(top.contains("\"ben\""));
            assertFalse(top.contains("\"ana\""));
            kit.risk.down.set(true);
            assertEquals(503, ana.get("/v1/risk/subject/alice").status());
            assertEquals(503, ana.get("/v1/risk/top").status());
        }
    }

    @Test
    void searchPassesThroughWithLimits() throws Exception {
        kit.search.add(1, w.now(), Entity.subject("alice"), Entity.device("laptop-alice"));
        String q = "{\"v\":1,\"query\":\"action = process.start\",\"from\":\"" + w.now().minus(Duration.ofHours(1))
                + "\",\"to\":\"" + w.now().plusSeconds(1) + "\",\"limit\":10}";
        try (SocApiKit.Client ana = kit.as("ana")) {
            SocApiKit.Reply r = ana.post("/v1/search", q);
            assertEquals(200, r.status());
            assertTrue(r.body().contains("powershell.exe"));
            assertEquals("action = process.start", kit.search.lastQuery.get(), "passed through unchanged");
            String tooLong = "{\"v\":1,\"query\":\"x\",\"from\":\"" + w.now().minus(Duration.ofDays(40)) + "\",\"to\":\""
                    + w.now() + "\",\"limit\":10}";
            assertEquals(400, ana.post("/v1/search", tooLong).status());
            assertEquals(400, ana.post("/v1/search", q.replace("\"limit\":10", "\"limit\":0")).status());
            assertEquals(400, ana.post("/v1/search", q.replace("\"limit\":10", "\"limit\":\"10\"")).status());
            assertEquals(400, ana.post("/v1/search", q.replace("action = process.start", "x".repeat(2_001))).status());
            assertEquals(400, ana.post("/v1/search", q.replace(w.now().minus(Duration.ofHours(1)).toString(), "yesterday"))
                    .status());
            kit.search.problem.set("parse error at 7\nFORGED LINE");
            SocApiKit.Reply p = ana.post("/v1/search", q);
            assertEquals(200, p.status());
            assertTrue(p.body().contains("\"problem\""));
            assertFalse(p.body().contains("\n"));
            kit.search.problem.set(null);
            kit.search.down.set(true);
            assertEquals(503, ana.post("/v1/search", q).status());
        }
    }

    @Test
    void metricsIsolationsAndReports() throws Exception {
        String al = w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("alice"), Entity.device("laptop-alice"));
        w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE);
        try (SocApiKit.Client ana = kit.as("ana"); SocApiKit.Client cleo = kit.as("cleo")) {
            SocApiKit.Reply m = ana.get("/v1/metrics");
            assertEquals(200, m.status());
            assertTrue(m.body().contains("\"playbookVersion\":\"test-1\""), m.body());
            assertTrue(cleo.get("/v1/isolations").body().contains("laptop-alice"));
            assertEquals(404, ana.get("/v1/reports/daily").status(), "reports are for leads");
            SocApiKit.Reply d = cleo.get("/v1/reports/daily");
            assertEquals(200, d.status());
            assertTrue(d.body().contains("simulated data"));
            assertEquals(404, cleo.get("/v1/reports/weekly").status());
            assertEquals(503, cleo.get("/v1/reports/huge").status());
            assertEquals(503, cleo.get("/v1/reports/broken").status());
        }
    }

    // ---- writes -------------------------------------------------------------------------------------------------

    @Test
    void assignmentsFollowTheRoles() throws Exception {
        String c = w.caseOf(w.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice")));
        String path = "/v1/cases/" + c + "/assignment";
        try (SocApiKit.Client ana = kit.as("ana"); SocApiKit.Client cleo = kit.as("cleo")) {
            assertEquals(403, ana.post(path, "{\"v\":1,\"assignee\":\"ben\"}").status());
            assertEquals(200, ana.post(path, "{\"v\":1,\"assignee\":\"ana\"}").status());
            assertEquals(200, cleo.post(path, "{\"v\":1,\"assignee\":\"ben\"}").status());
            assertEquals(400, cleo.post(path, "{\"v\":1,\"assignee\":\"mallory\"}").status());
            assertEquals(400, cleo.post(path, "{\"v\":1,\"assignee\":\"../x\"}").status());
            assertEquals(404, ana.post(path, "{\"v\":1,\"assignee\":\"ana\"}").status(), "now ben's case");
        }
        assertEquals("ben", w.cases.view(c).orElseThrow().assignee().orElseThrow());
    }

    @Test
    void verdictsMustBeSignedByTheCallingAnalyst() throws Exception {
        String al = w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("alice"), Entity.device("laptop-alice"));
        Verdict bens = w.verdict("ben", al, Verdict.Outcome.TRUE_POSITIVE);
        try (SocApiKit.Client ana = kit.as("ana")) {
            assertEquals(403, ana.post("/v1/verdicts", verdictJson(bens)).status(), "ben's verdict sent by ana");
            Verdict mine = w.verdict("ana", al, Verdict.Outcome.TRUE_POSITIVE);
            String forged = verdictJson(mine).replace(mine.proof().signature(),
                    w.verdict("ana", al, Verdict.Outcome.BENIGN).proof().signature());
            SocApiKit.Reply bad = ana.post("/v1/verdicts", forged);
            assertEquals(403, bad.status());
            assertEquals("{\"error\":\"verdict refused\"}", bad.body(), "no detail leaks");
            SocApiKit.Reply ok = ana.post("/v1/verdicts", verdictJson(mine));
            assertEquals(200, ok.status(), ok.body());
            assertTrue(ok.body().contains("\"status\":\"APPLIED\""));
            assertTrue(ok.body().contains("laptop-alice"));
            assertEquals(403, ana.post("/v1/verdicts", verdictJson(mine)).status(), "single use");
            assertEquals(404, ana.post("/v1/verdicts", verdictJson(w.verdict("ana", "al-none",
                    Verdict.Outcome.BENIGN))).status());
            assertEquals(400, ana.post("/v1/verdicts", verdictJson(mine).replace("TRUE_POSITIVE", "MAYBE")).status());
            assertEquals(400, ana.post("/v1/verdicts", verdictJson(mine).replace("\"proof\":{", "\"proof\":{\"x\":1,"))
                    .status());
        }
        assertTrue(w.sensor.isolated("laptop-alice"));
    }

    // ---- limits and audit ---------------------------------------------------------------------------------------

    @Test
    void callsAreRateLimitedPerAnalyst() throws Exception {
        kit.close();
        try (SocApiKit limited = new SocApiKit(new SoarWorld(), SocApiSettings.defaults().withRates(5, 1, 1));
             SocApiKit.Client ana = limited.as("ana"); SocApiKit.Client ben = limited.as("ben")) {
            String c = limited.world.caseOf(limited.world.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice")));
            assertEquals(200, ana.post("/v1/cases/" + c + "/notes", "{\"v\":1,\"text\":\"one\"}").status());
            assertEquals(429, ana.post("/v1/cases/" + c + "/notes", "{\"v\":1,\"text\":\"two\"}").status());
            for (int i = 0; i < 3; i++) {
                ana.get("/v1/health");
            }
            assertEquals(429, ana.get("/v1/health").status());
            assertEquals(200, ben.get("/v1/health").status(), "per analyst");
            String q = "{\"v\":1,\"query\":\"x\",\"from\":\"" + limited.world.now().minusSeconds(60) + "\",\"to\":\""
                    + limited.world.now() + "\",\"limit\":1}";
            assertEquals(200, ben.post("/v1/search", q).status());
            assertEquals(429, ben.post("/v1/search", q).status());
        }
    }

    @Test
    void everyCallIsAuditedAndDataIsNotSentWithoutIt() throws Exception {
        String c = w.caseOf(w.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice")));
        try (SocApiKit.Client ana = kit.as("ana")) {
            ana.get("/v1/cases/" + c);
            ana.get("/v1/cases/case-404");
            assertEquals(1, w.audited("SOCAPI_CALL"));
            assertEquals(1, w.audited("SOCAPI_REFUSED"));
            String rec = w.records("SOCAPI_CALL").getFirst().payloadJson();
            assertTrue(rec.contains("/v1/cases/{}") && rec.contains(c) && rec.contains("\"caller\":\"ana\""), rec);
            w.auditDown.set(true);
            SocApiKit.Reply r = ana.get("/v1/cases/" + c);
            assertEquals(503, r.status());
            assertFalse(r.body().contains("alice"));
            assertTrue(kit.server.auditFailures() >= 1);
            assertEquals(200, ana.get("/v1/health").status(), "no data, still answered");
        }
    }

    @Test
    void refusalAuditsAreThrottled() throws Exception {
        try (SocApiKit.Client stranger = kit.as("stranger")) {
            for (int i = 0; i < 25; i++) {
                stranger.get("/v1/health");
            }
        }
        assertEquals(20, w.audited("SOCAPI_REFUSED"));
        assertEquals(5, kit.server.suppressedAuditEvents());
    }

    @Test
    void aSlowClientIsCutOffAtTheDeadline() throws Exception {
        kit.close();
        try (SocApiKit slow = new SocApiKit(new SoarWorld(), SocApiSettings.defaults()
                .withRequestDeadline(Duration.ofMillis(800)))) {
            SSLContext c = SocApiKit.ctx(SocApiKit.pki(), "ana");
            try (SSLSocket s = (SSLSocket) c.getSocketFactory().createSocket("localhost", slow.base.getPort())) {
                s.setSSLParameters(TlsContexts.clientParameters(c));
                s.setSoTimeout(10_000);
                s.startHandshake();
                OutputStream out = s.getOutputStream();
                out.write(("POST /v1/search HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
                        + "Content-Length: 100\r\n\r\n{").getBytes(StandardCharsets.US_ASCII));
                out.flush();
                InputStream in = s.getInputStream();
                long start = System.nanoTime();
                try {
                    while (in.read() >= 0) {
                        // drain until the server gives up
                    }
                } catch (IOException closed) {
                    // closed by the server
                }
                assertTrue(System.nanoTime() - start < 8_000_000_000L, "cut off well before the client's own timeout");
            }
            long deadline = System.currentTimeMillis() + 5_000;
            while (slow.server.timedOut() == 0 && System.currentTimeMillis() < deadline) {
                Thread.onSpinWait();
            }
            assertTrue(slow.server.timedOut() >= 1);
        }
    }

    @Test
    void settingsAreBounded() {
        assertThrows(IllegalArgumentException.class, () -> SocApiSettings.defaults().withRates(0, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> SocApiSettings.defaults().withRequestDeadline(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> SocApiSettings.defaults().withRequestDeadline(Duration.ofMinutes(2)));
        assertThrows(IllegalArgumentException.class, () -> new SocApiSettings(8, 32, 16, 1 << 20, Duration.ofSeconds(5),
                1, 1, 1, 1, Duration.ofDays(1)));
        assertThrows(IllegalArgumentException.class, () -> new SocApiSettings(8, 32, 16, 1024, Duration.ofSeconds(5),
                1, 1, 1, 1, Duration.ofDays(91)));
    }
}

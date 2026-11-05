package dev.dwarpal.console;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.AuditSink;
import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** "Audit of the console" (standards section 3) and the audit explorer's read API. */
class ConsoleAuditTest {

    private static ConsoleFixture f;

    @BeforeAll
    static void start() throws Exception {
        f = ConsoleFixture.start();
    }

    @AfterAll
    static void stop() {
        f.close();
    }

    private static List<AuditRecord> since(long seq) {
        return f.world.org.sink.snapshot().stream().filter(r -> r.sequence() > seq).toList();
    }

    private static long head() {
        return f.world.org.audit.head().sequence();
    }

    @Test
    void loginFailureStepUpAndLogoutAreInTheChainUnderThePersonWithoutTheSessionSecret() throws Exception {
        long before = head();
        ConsoleAuth.Enrolment ana = f.person("ana");
        f.login("ana", ana.password(), "BADPIN99");
        Sess s = f.login("ana");
        f.clock.advance(Duration.ofMinutes(6));
        Sess fresh = f.stepUp(s);
        f.post("/console/api/session/logout", fresh, "{}");
        List<AuditRecord> records = since(before);
        assertTrue(records.stream().anyMatch(r -> r.type().equals("CONSOLE_LOGIN_FAILED") && r.payloadJson().contains("\"user\":\"ana\"")));
        assertTrue(records.stream().anyMatch(r -> r.type().equals("CONSOLE_LOGIN") && r.actor().equals("ana")));
        assertTrue(records.stream().anyMatch(r -> r.type().equals("CONSOLE_STEPUP") && r.actor().equals("ana")));
        assertTrue(records.stream().anyMatch(r -> r.type().equals("CONSOLE_LOGOUT") && r.actor().equals("ana")));
        String all = String.join("\n", records.stream().map(AuditRecord::payloadJson).toList());
        for (String secret : List.of(s.cookie(), s.csrf(), fresh.cookie(), fresh.csrf(), ana.password(), ana.pin())) {
            assertFalse(all.contains(secret), "no cookie, token, password or PIN in the trail");
        }
        assertTrue(all.matches("(?s).*\"session\":\"[0-9a-f]{16}\".*"), "a hashed session tag is there");
    }

    @Test
    void whatTheBrowserSendsCannotForgeARecord() throws Exception {
        long before = head();
        for (String user : List.of("ana\\\",\\\"actor\\\":\\\"cleo", "ana\\nCONSOLE_LOGIN cleo ok", "ana\\u202Eevil", "x".repeat(100))) {
            f.post("/console/api/session/login", null, "{\"user\":\"" + user + "\",\"password\":\"whatever-123\"}");
        }
        for (AuditRecord r : since(before)) {
            JsonValue p = new JsonReader().read(r.payloadJson());
            assertTrue(p instanceof JsonValue.JObject o && o.size() <= 6, "still one flat JSON object: " + r.payloadJson());
            assertEquals("console", r.actor(), "a failed login has no person to blame");
            assertFalse(r.payloadJson().contains("\n") || r.payloadJson().contains(String.valueOf((char) 0x202E)));
        }
        assertTrue(since(before).stream().noneMatch(r -> r.type().equals("CONSOLE_LOGIN")));
    }

    @Test
    void everyWriteIsRecordedBeforeAndAfterAndEverySensitiveReadOnce() throws Exception {
        Sess ana = f.login("ana");
        String caseId = ((JsonValue.JString) ((JsonValue.JObject) ((JsonValue.JArray) ((JsonValue.JObject) f.get("/console/api/soc/queue",
                ana).json()).get("queue").orElseThrow()).get(0)).get("id").orElseThrow()).value();
        long before = head();
        assertEquals(200, f.get("/console/api/soc/cases/" + caseId, ana).status());
        assertEquals(200, f.post("/console/api/soc/cases/" + caseId + "/notes", ana, "{\"text\":\"audit me\"}").status());
        List<AuditRecord> records = since(before).stream().filter(r -> r.type().startsWith("CONSOLE_")).toList();
        List<AuditRecord> reads = records.stream().filter(r -> r.type().equals("CONSOLE_READ")).toList();
        List<AuditRecord> writes = records.stream().filter(r -> r.type().equals("CONSOLE_WRITE")).toList();
        assertEquals(1, reads.size());
        assertTrue(reads.getFirst().payloadJson().contains(caseId) && reads.getFirst().actor().equals("ana"));
        assertEquals(2, writes.size(), "intent first, outcome after");
        assertTrue(writes.get(0).payloadJson().contains("\"phase\":\"attempt\"") && writes.get(1).payloadJson().contains("\"phase\":\"result\""));
        assertTrue(writes.get(1).payloadJson().contains("\"status\":\"200\""));
        assertFalse(String.join("", writes.stream().map(AuditRecord::payloadJson).toList()).contains("audit me"),
                "the note's text is in the case, not in the audit record: its length is");
    }

    @Test
    void refusalsAreAuditedAndTheirFloodIsLimited() throws Exception {
        Sess uma = f.login("uma");
        long before = head();
        for (int i = 0; i < 60; i++) {
            assertEquals(403, f.get("/console/api/soc/queue", uma).status());
        }
        // a role refusal is not a write or a sensitive read: it is one audit line per window, not sixty
        assertTrue(since(before).stream().filter(r -> r.type().equals("CONSOLE_REFUSED")).count() <= 21);
        long before2 = head();
        for (int i = 0; i < 30; i++) {
            f.raw("POST", "/console/api/session/logout", java.util.Map.of("Origin", "https://evil.example", "Content-Type",
                    "application/json", "Cookie", ConsoleServer.COOKIE + "=" + uma.cookie(), "User-Agent", ConsoleFixture.UA), "{}");
        }
        assertEquals(200, f.get("/console/api/me", uma).status(), "a forged logout did nothing");
        long refused = since(before2).stream().filter(r -> r.type().equals("CONSOLE_REFUSED")).count();
        assertTrue(refused >= 1 && refused <= 21, "refused CSRF attempts are recorded, but capped: " + refused);
    }

    // ---- the explorer ---------------------------------------------------------------------------------------

    @Test
    void theExplorerPagesTheChainShowsARecordAndVerifiesIt() throws Exception {
        Sess cleo = f.login("cleo");
        Resp page = f.get("/console/api/audit/records?limit=3", cleo);
        assertEquals(200, page.status());
        JsonValue.JObject o = (JsonValue.JObject) page.json();
        assertEquals(3, ((JsonValue.JArray) o.get("entries").orElseThrow()).size());
        assertTrue(page.body().contains("\"more\":true"));
        Resp one = f.get("/console/api/audit/records/1", cleo);
        assertEquals(200, one.status());
        assertTrue(one.body().contains("\"previousMac\":\"" + "0".repeat(64) + "\""), "record 1 links to the genesis MAC");
        assertEquals(404, f.get("/console/api/audit/records/99999999", cleo).status());
        Resp filtered = f.get("/console/api/audit/records?type=CONSOLE_LOGIN&limit=50", cleo);
        assertTrue(filtered.body().contains("CONSOLE_LOGIN") && !filtered.body().contains("ACCESS_DECISION"));

        Resp verify = f.get("/console/api/audit/verify", cleo);
        assertEquals(200, verify.status(), verify.body());
        assertTrue(verify.body().contains("\"intact\":true"), verify.body());
        assertTrue(verify.body().contains("\"firstBad\":-1"));
        long seq = ((JsonValue.JNumber) ((JsonValue.JObject) f.get("/console/api/audit/head", cleo).json()).get("head").orElseThrow()).asLong();
        assertTrue(seq > 1000, "a lab that ran the whole script has a long chain: " + seq);
    }

    @Test
    void anAnalystSeesTheConsolesRecordsInFullAndTheRestOnlyAsHeaders() throws Exception {
        Sess ana = f.login("ana");
        Sess cleo = f.login("cleo");
        long accessSeq = f.world.org.sink.snapshot().stream().filter(r -> !r.type().startsWith("CONSOLE_") && !r.type().startsWith("SOCAPI_"))
                .findFirst().orElseThrow().sequence();
        Resp forAna = f.get("/console/api/audit/records/" + accessSeq, ana);
        assertTrue(forAna.body().contains("withheld"), forAna.body());
        assertFalse(f.get("/console/api/audit/records/" + accessSeq, cleo).body().contains("withheld"));
        Resp mine = f.get("/console/api/audit/records?type=CONSOLE_LOGIN&limit=5", ana);
        assertFalse(mine.body().contains("for leads"), "the console's own records are open to analysts");
        Resp theirs = f.get("/console/api/audit/records?limit=5&after=" + (accessSeq - 1), ana);
        assertTrue(theirs.body().contains("for leads"));
    }

    @Test
    void verifyingIsRateLimitedAndRecorded() throws Exception {
        Sess ben = f.login("ben");
        long before = head();
        int ok = 0;
        int limited = 0;
        for (int i = 0; i < 8; i++) {
            int status = f.get("/console/api/audit/verify", ben).status();
            if (status == 200) {
                ok++;
            } else if (status == 429) {
                limited++;
            }
        }
        assertEquals(6, ok);
        assertEquals(2, limited);
        assertTrue(since(before).stream().anyMatch(r -> r.type().equals("CONSOLE_READ") && r.payloadJson().contains("audit/verify")));
    }

    // ---- fail closed ----------------------------------------------------------------------------------------

    @Test
    void ifTheTrailCannotBeWrittenNoDataIsSentNoWriteHappensAndNobodyLogsIn() throws Exception {
        AtomicBoolean failing = new AtomicBoolean();
        AtomicInteger written = new AtomicInteger();
        AuditSink flaky = rec -> {
            if (failing.get()) {
                throw new IllegalStateException("disk full");
            }
            written.incrementAndGet();
        };
        AuditLog log = new AuditLog(new SecretKeySpec(new byte[32], "HmacSHA256"), flaky);
        try (ConsoleFixture g = ConsoleFixture.start(b -> b.auditLog(log), ConsoleSettings.defaults().fastHashing())) {
            Sess ana = g.login("ana");
            String caseId = ((JsonValue.JString) ((JsonValue.JObject) ((JsonValue.JArray) ((JsonValue.JObject) g.get("/console/api/soc/queue",
                    ana).json()).get("queue").orElseThrow()).get(0)).get("id").orElseThrow()).value();
            failing.set(true);
            Resp read = g.get("/console/api/soc/cases/" + caseId, ana);
            assertEquals(503, read.status());
            assertFalse(read.body().contains("rankedAlerts"), "the data is not sent");
            int notesBefore = g.get("/console/api/soc/cases/" + caseId, ana).status();
            Resp write = g.post("/console/api/soc/cases/" + caseId + "/notes", ana, "{\"text\":\"must not be saved\"}");
            assertEquals(503, write.status());
            ConsoleAuth.Enrolment ben = g.person("ben");
            Resp login = g.login("ben", ben.password(), ben.pin());
            assertEquals(503, login.status());
            assertEquals(0, login.headers().allValues("Set-Cookie").stream().filter(c -> c.contains("=") && !c.contains("Max-Age=0")).count(),
                    "no session cookie");
            assertTrue(g.server.auditFailures() >= 3);
            failing.set(false);
            assertEquals(200, g.get("/console/api/soc/cases/" + caseId, ana).status());
            assertFalse(g.get("/console/api/soc/cases/" + caseId, ana).body().contains("must not be saved"));
            assertTrue(g.get("/console/api/lab", ana).body().contains("\"auditFailures\":" + g.server.auditFailures()),
                    "the failure is visible on the status bar");
            assertTrue(notesBefore == 503 && written.get() > 0);
        }
    }
}

package dev.dwarpal.console;

import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import dev.dwarpal.console.ConsoleRoutes.Gate;
import dev.dwarpal.wire.JsonValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The passkey windows: one entry opens cases, entities and hunt together for 15 real minutes (no prompt inside it, a
 * prompt after it); the audit explorer needs a fresher entry (5 minutes) that renews the window; response actions,
 * exports and administration ask every time. The clock is the console's real (wall) clock, never the scenario's.
 */
class ConsolePasskeyWindowTest {

    private static final String PASSKEY = "gate-keeper-passkey";
    private static final String VERDICT = "{\"alertId\":\"al-x-1\",\"outcome\":\"TRUE_POSITIVE\"}";

    private ConsoleFixture f;

    @BeforeEach
    void start() throws Exception {
        f = ConsoleFixture.start(b -> b.passkeyLock(Duration.ofMinutes(15), Duration.ofMinutes(5)),
                ConsoleSettings.defaults().fastHashing());
    }

    @AfterEach
    void stop() {
        f.close();
    }

    private Sess signedIn(String id) throws Exception {
        Sess s = f.login(id);
        ConsoleAuth.Enrolment e = f.person(id);
        assertEquals(200, f.post("/console/api/profile/passkey", s, "{\"password\":\"" + e.password() + "\",\"pin\":\"" + e.pin()
                + "\",\"passkey\":\"" + PASSKEY + "\"}").status());
        return s;
    }

    private Resp unlock(Sess s, String scope) throws Exception {
        return f.post("/console/api/session/unlock", s, "{\"passkey\":\"" + PASSKEY + "\",\"scope\":\"" + scope + "\"}");
    }

    private Resp search(Sess s) throws Exception {
        return f.post("/console/api/soc/search", s,
                "{\"query\":\"*\",\"from\":\"2026-11-01T00:00:00Z\",\"to\":\"2026-11-08T00:00:00Z\",\"limit\":5}");
    }

    /** An entity view: guarded by the shared window, and cheap for the lab's own rate limits. */
    private Resp probe(Sess s) throws Exception {
        return f.get("/console/api/soc/risk/subject/ana", s);
    }

    private long seconds(Sess s, String field) throws Exception {
        return Long.parseLong(((JsonValue.JNumber) ((JsonValue.JObject) f.get("/console/api/me", s).json()).get(field)
                .orElseThrow()).text());
    }

    private List<String> caseIds(Sess s) throws Exception {
        JsonValue.JArray queue = (JsonValue.JArray) ((JsonValue.JObject) f.get("/console/api/soc/queue", s).json()).get("queue")
                .orElseThrow();
        List<String> ids = new ArrayList<>();
        for (int i = 0; i < queue.size(); i++) {
            ids.add(((JsonValue.JString) ((JsonValue.JObject) queue.get(i)).get("id").orElseThrow()).value());
        }
        return ids;
    }

    private long head() {
        return f.world.org.audit.head().sequence();
    }

    private List<AuditRecord> since(long seq) {
        return f.world.org.sink.snapshot().stream().filter(r -> r.sequence() > seq).toList();
    }

    // ---- the shared window ----------------------------------------------------------------------------------

    @Test
    void oneEntryOpensCasesEntitiesAndHuntTogetherAndNothingAsksAgainInsideTheWindow() throws Exception {
        Sess ana = signedIn("ana");
        List<String> ids = caseIds(ana);
        assertTrue(ids.size() >= 2, "the lab has cases to open");
        assertEquals(423, f.get("/console/api/soc/cases/" + ids.get(0), ana).status(), "closed until the passkey");
        assertEquals(200, unlock(ana, "window").status());
        for (int minute = 0; minute < 14; minute += 2) {
            for (String id : ids.subList(0, Math.min(3, ids.size()))) {
                assertEquals(200, f.get("/console/api/soc/cases/" + id, ana).status(), "a case, minute " + minute);
            }
            assertNotEquals(423, (minute == 0 ? search(ana) : probe(ana)).status(), "hunt and entity share the window");
            assertNotEquals(423, f.get("/console/api/soc/risk/subject/ana", ana).status(), "entity shares the window");
            f.clock.advance(Duration.ofMinutes(2));
        }
    }

    @Test
    void theWindowIsFifteenRealMinutesAndUseDoesNotExtendIt() throws Exception {
        Sess ana = signedIn("ana");
        assertEquals(200, unlock(ana, "window").status());
        assertEquals(900, seconds(ana, "unlockedSeconds"), "the footer's countdown starts at fifteen minutes");
        f.clock.advance(Duration.ofMinutes(10));
        assertNotEquals(423, probe(ana).status());
        assertEquals(300, seconds(ana, "unlockedSeconds"), "using it did not renew it");
        f.clock.advance(Duration.ofMinutes(5).minusSeconds(1));
        assertNotEquals(423, probe(ana).status(), "the last second of the window");
        f.clock.advance(Duration.ofSeconds(2));
        Resp closed = search(ana);
        assertEquals(423, closed.status(), "after the window the passkey is asked for again");
        assertTrue(closed.body().contains("\"scope\":\"window\""), closed.body());
        assertEquals(0, seconds(ana, "unlockedSeconds"));
    }

    @Test
    void aBackgroundRefreshNeitherExtendsTheWindowNorIsBlockedInsideIt() throws Exception {
        Sess ana = signedIn("ana");
        assertEquals(200, unlock(ana, "window").status());
        f.clock.advance(Duration.ofMinutes(14));
        f.get("/console/api/me", ana);
        assertNotEquals(423, f.backgroundGet("/console/api/soc/risk/subject/ana", ana).status(), "still open");
        f.clock.advance(Duration.ofMinutes(2));
        assertEquals(423, probe(ana).status());
    }

    @Test
    void everyCaseReadIsStillWrittenToTheAuditTrailInsideTheWindow() throws Exception {
        Sess ana = signedIn("ana");
        List<String> ids = caseIds(ana).subList(0, 2);
        assertEquals(200, unlock(ana, "window").status());
        long before = head();
        for (String id : ids) {
            assertEquals(200, f.get("/console/api/soc/cases/" + id, ana).status());
        }
        List<AuditRecord> reads = since(before).stream().filter(r -> r.type().equals("CONSOLE_READ")).toList();
        assertEquals(ids.size(), reads.size(), "one record per case opened, with no prompt in between");
        for (String id : ids) {
            assertTrue(reads.stream().anyMatch(r -> r.payloadJson().contains(id) && r.actor().equals("ana")), id);
        }
        assertTrue(since(before).stream().noneMatch(r -> r.type().equals("CONSOLE_UNLOCK")), "no second passkey entry");
    }

    // ---- the audit explorer ---------------------------------------------------------------------------------

    @Test
    void theAuditExplorerNeedsItsOwnFresherUnlockThatAlsoRenewsTheWindow() throws Exception {
        Sess ana = signedIn("ana");
        assertEquals(200, unlock(ana, "window").status());
        f.clock.advance(Duration.ofMinutes(10));
        Resp refused = f.get("/console/api/audit/records?after=0&limit=5", ana);
        assertEquals(423, refused.status(), "the window does not open the audit explorer");
        assertTrue(refused.body().contains("\"scope\":\"audit\""), refused.body());
        assertEquals(200, unlock(ana, "audit").status());
        assertEquals(900, seconds(ana, "unlockedSeconds"), "entering the passkey for the audit renews the 15 minutes");
        assertEquals(300, seconds(ana, "auditSeconds"), "and opens the audit for 5");
        assertEquals(200, f.get("/console/api/audit/records?after=0&limit=5", ana).status());
        f.clock.advance(Duration.ofMinutes(4));
        assertEquals(200, f.get("/console/api/audit/records?after=0&limit=5", ana).status(), "inside the five minutes");
        f.clock.advance(Duration.ofMinutes(2));
        assertEquals(423, f.get("/console/api/audit/records?after=0&limit=5", ana).status(), "after five minutes it asks again");
        assertEquals(423, f.get("/console/api/audit/verify", ana).status(), "verify is part of the explorer");
        assertNotEquals(423, probe(ana).status(), "while the shared window, renewed, is still open");
    }

    @Test
    void aPasskeyGivenForTheWindowDoesNotOpenTheAuditAndOneGivenForTheAuditStartsTheWindow() throws Exception {
        Sess ana = signedIn("ana");
        assertEquals(200, unlock(ana, "audit").status());
        assertNotEquals(423, probe(ana).status(), "the audit entry opened the shared window too");
        Sess ben = signedIn("ben");
        assertEquals(200, unlock(ben, "window").status());
        assertEquals(423, f.get("/console/api/audit/records?after=0&limit=5", ben).status());
        assertEquals(0, seconds(ben, "auditSeconds"));
    }

    // ---- risky actions always ask ------------------------------------------------------------------------------

    @Test
    void aResponseActionAsksForThePasskeyEveryTimeWhateverTheWindowSays() throws Exception {
        Sess ana = signedIn("ana");
        assertEquals(200, unlock(ana, "window").status());
        Resp asked = f.post("/console/api/soc/verdicts", ana, VERDICT);
        assertEquals(423, asked.status(), "the open window is not enough for a response action");
        assertTrue(asked.body().contains("\"scope\":\"once\""), asked.body());
        assertEquals(200, unlock(ana, "once").status());
        assertEquals(900, seconds(ana, "unlockedSeconds"), "a one-action entry does not renew the window");
        assertNotEquals(423, f.post("/console/api/soc/verdicts", ana, VERDICT).status(), "the action goes through once");
        assertEquals(423, f.post("/console/api/soc/verdicts", ana, VERDICT).status(), "and the next one asks again");
        assertNotEquals(423, probe(ana).status(), "the window was not disturbed");
    }

    @Test
    void aReportExportAsksEveryTimeToo() throws Exception {
        Sess cleo = signedIn("cleo");
        assertEquals(200, unlock(cleo, "window").status());
        assertEquals(423, f.get("/console/api/soc/reports/daily", cleo).status());
        assertEquals(200, unlock(cleo, "once").status());
        assertNotEquals(423, f.get("/console/api/soc/reports/daily", cleo).status());
        assertEquals(423, f.get("/console/api/soc/reports/daily", cleo).status(), "the second export asks again");
    }

    @Test
    void aSingleEntryIsUsedUpByExactlyOneActionEvenWhenManyArriveTogether() throws Exception {
        Sess ana = signedIn("ana");
        assertEquals(200, unlock(ana, "once").status());
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<Integer>> results = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                results.add(pool.submit(() -> f.post("/console/api/soc/verdicts", ana, VERDICT).status()));
            }
            int through = 0;
            for (Future<Integer> r : results) {
                if (r.get() != 423) {
                    through++;
                }
            }
            assertEquals(1, through, "one passkey entry, one action");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void anUnusedSingleEntryExpiresAfterAMinuteAndBackgroundRequestsNeverUseItUp() throws Exception {
        Sess cleo = signedIn("cleo");
        assertEquals(200, unlock(cleo, "once").status());
        assertEquals(423, f.backgroundGet("/console/api/soc/reports/daily", cleo).status(), "a page refreshing itself cannot use it");
        assertNotEquals(423, f.get("/console/api/soc/reports/daily", cleo).status(), "it was still there for the person");
        assertEquals(200, unlock(cleo, "once").status());
        f.clock.advance(Duration.ofSeconds(61));
        assertEquals(423, f.get("/console/api/soc/reports/daily", cleo).status(), "an entry left unused does not wait for ever");
    }

    @Test
    void lockNowClosesTheWindowTheAuditUnlockAndAnyUnusedEntry() throws Exception {
        Sess cleo = signedIn("cleo");
        assertEquals(200, unlock(cleo, "audit").status());
        assertEquals(200, unlock(cleo, "once").status());
        assertEquals(200, f.post("/console/api/session/lock", cleo, "{}").status());
        assertEquals(423, probe(cleo).status());
        assertEquals(423, f.get("/console/api/audit/records?after=0&limit=5", cleo).status());
        assertEquals(423, f.get("/console/api/soc/reports/daily", cleo).status(), "the unused single entry is gone");
        assertEquals(0, seconds(cleo, "unlockedSeconds"));
    }

    @Test
    void aWrongScopeIsRefusedAndAWrongPasskeyOpensNothing() throws Exception {
        Sess ana = signedIn("ana");
        assertEquals(400, f.post("/console/api/session/unlock", ana, "{\"passkey\":\"" + PASSKEY + "\",\"scope\":\"forever\"}").status());
        assertEquals(401, f.post("/console/api/session/unlock", ana, "{\"passkey\":\"not-it\",\"scope\":\"once\"}").status());
        assertEquals(423, f.post("/console/api/soc/verdicts", ana, VERDICT).status());
        assertEquals(200, f.post("/console/api/session/unlock", ana, "{\"passkey\":\"" + PASSKEY + "\"}").status(),
                "the old form without a scope still means the shared window");
        assertNotEquals(423, probe(ana).status());
    }

    // ---- which route is guarded how -------------------------------------------------------------------------------

    @Test
    void theRouteTableSaysWhichRoutesUseTheWindowTheAuditUnlockOrAskEveryTime() {
        for (String p : List.of("soc/cases/{}", "soc/cases/{}/timeline", "soc/risk/{}/{}", "soc/search")) {
            assertEquals(Gate.WINDOW, ConsoleRoutes.gate(p, false), p);
        }
        for (String p : List.of("audit/records", "audit/records/{}", "audit/verify")) {
            assertEquals(Gate.AUDIT, ConsoleRoutes.gate(p, false), p);
        }
        for (String p : List.of("soc/reports/{}", "lab/export")) {
            assertEquals(Gate.EVERY_TIME, ConsoleRoutes.gate(p, false), p);
        }
        for (String p : List.of("soc/verdicts", "admin/proposals/{}/approve", "admin/proposals/{}/install", "admin/pam/request",
                "admin/pam/approve/{}", "admin/pam/revoke/{}", "admin/pam/review/{}", "admin/lab/reset")) {
            assertEquals(Gate.EVERY_TIME, ConsoleRoutes.gate(p, true), "every change that needs a fresh step-up: " + p);
        }
        assertEquals(Gate.NONE, ConsoleRoutes.gate("soc/queue", false), "the queue list shows no confidential detail");
        assertEquals(Gate.NONE, ConsoleRoutes.gate("me", false));
    }
}

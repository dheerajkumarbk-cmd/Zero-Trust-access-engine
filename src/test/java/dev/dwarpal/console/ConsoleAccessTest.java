package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Authorisation and the SOC proxy, through the real console, the real delegation and the real SOC API: roles on every
 * route, leads-only reports, the person never named by the browser, step-up for verdicts, modules guarded by the host.
 */
class ConsoleAccessTest {

    private static ConsoleFixture f;

    @BeforeAll
    static void start() throws Exception {
        f = ConsoleFixture.start(b -> ProbeModule.only().forEach(b::module), ConsoleSettings.defaults().fastHashing());
    }

    @AfterAll
    static void stop() {
        f.close();
    }

    // ---- small JSON helpers
    private static JsonValue.JObject obj(JsonValue v) {
        return (JsonValue.JObject) v;
    }

    private static List<JsonValue> arr(JsonValue v) {
        return ((JsonValue.JArray) v).elements();
    }

    private static String str(JsonValue v) {
        return ((JsonValue.JString) v).value();
    }

    private List<String> queueCaseIds(Sess s) throws Exception {
        Resp q = f.get("/console/api/soc/queue", s);
        assertEquals(200, q.status(), q.body());
        List<String> ids = new ArrayList<>();
        for (JsonValue c : arr(obj(q.json()).get("queue").orElseThrow())) {
            ids.add(str(obj(c).get("id").orElseThrow()));
        }
        return ids;
    }

    @Test
    void anAnalystWorksTheQueueAndSeesCasesThroughTheirOwnRights() throws Exception {
        Sess ana = f.login("ana");
        List<String> ids = queueCaseIds(ana);
        assertFalse(ids.isEmpty(), "the lab has a queue to work");
        Resp c = f.get("/console/api/soc/cases/" + ids.getFirst(), ana);
        assertEquals(200, c.status());
        assertTrue(c.body().contains("rankedAlerts") && c.body().contains("reasons"), "every alert says why it has its rank");
        assertEquals(200, f.get("/console/api/soc/cases/" + ids.getFirst() + "/timeline", ana).status());
        assertEquals(200, f.get("/console/api/soc/risk/top", ana).status());
        assertEquals(200, f.get("/console/api/soc/metrics", ana).status());
        assertEquals(200, f.get("/console/api/soc/isolations", ana).status());
        assertEquals(404, f.get("/console/api/soc/cases/no-such-case", ana).status(), "a case that does not exist");
    }

    @Test
    void reportsAreForLeadsAndTheSocApiSaysSoNotTheConsole() throws Exception {
        assertEquals(404, f.get("/console/api/soc/reports/daily", f.login("ana")).status());
        Resp lead = f.get("/console/api/soc/reports/daily", f.login("cleo"));
        assertEquals(200, lead.status());
        assertTrue(lead.body().contains("\"text\""));
    }

    @Test
    void peopleWhoAreNotAnalystsGetNothingFromTheSocRoutesOrTheAuditExplorer() throws Exception {
        for (String who : List.of("dana", "uma")) {
            Sess s = f.login(who);
            for (String p : List.of("/console/api/soc/queue", "/console/api/soc/cases", "/console/api/soc/metrics",
                    "/console/api/soc/risk/top", "/console/api/soc/reports/daily", "/console/api/audit/head",
                    "/console/api/audit/records", "/console/api/audit/verify")) {
                assertEquals(403, f.get(p, s).status(), who + " " + p);
            }
            assertEquals(200, f.get("/console/api/me", s).status());
        }
    }

    @Test
    void theModuleListShowsOnlyWhatARoleMaySee() throws Exception {
        Resp ana = f.get("/console/api/modules", f.login("ana"));
        assertTrue(ana.body().contains("\"id\":\"overview\"") && ana.body().contains("\"id\":\"probe\""), ana.body());
        Resp uma = f.get("/console/api/modules", f.login("uma"));
        assertFalse(uma.body().contains("overview") || uma.body().contains("probe"), uma.body());
    }

    @Test
    void theBrowserNeverNamesWhoIsActing() throws Exception {
        Sess ana = f.login("ana");
        String caseId = queueCaseIds(ana).getFirst();
        // a note or an assignment or a verdict that carries an analyst id is a malformed request, not an instruction
        assertEquals(400, f.post("/console/api/soc/cases/" + caseId + "/notes", ana, "{\"text\":\"x\",\"author\":\"ben\"}").status());
        assertEquals(400, f.post("/console/api/soc/verdicts", ana, "{\"alertId\":\"a1\",\"outcome\":\"BENIGN\",\"analystId\":\"ben\"}")
                .status());
        // and the audit trail says ana did what ana did
        Resp ok = f.post("/console/api/soc/cases/" + caseId + "/notes", ana, "{\"text\":\"looked at this, nothing yet\"}");
        assertEquals(200, ok.status(), ok.body());
        Resp detail = f.get("/console/api/soc/cases/" + caseId, ana);
        assertTrue(detail.body().contains("\"author\":\"ana\"") && detail.body().contains("looked at this, nothing yet"));
    }

    @Test
    void noteTextWithControlOrDirectionCharactersIsRefusedBeforeItReachesTheSocApi() throws Exception {
        Sess ana = f.login("ana");
        String caseId = queueCaseIds(ana).getFirst();
        for (String text : List.of("bell\\u0007here", "nul\\u0000here", "rlo \\u202Eevil", "line\\u2028sep", "isolate \\u2066x")) {
            Resp r = f.post("/console/api/soc/cases/" + caseId + "/notes", ana, "{\"text\":\"" + text + "\"}");
            assertEquals(400, r.status(), text);
        }
        assertEquals(400, f.post("/console/api/soc/cases/" + caseId + "/notes", ana, "{\"text\":\"" + "a".repeat(2_001) + "\"}")
                .status());
        assertEquals(200, f.post("/console/api/soc/cases/" + caseId + "/notes", ana,
                "{\"text\":\"two lines\\nand <b>markup</b> stays text\"}").status());
    }

    @Test
    void searchAndCountsGoThroughAndTheQueryIsNotWrittenToTheAuditTrail() throws Exception {
        Sess ana = f.login("ana");
        String to = f.world.now().toString();
        String from = f.world.now().minus(Duration.ofHours(12)).toString();
        String secretQuery = "dataset = firewall AND action = \"secret-marker-8c1f\"";
        Resp r = f.post("/console/api/soc/search", ana, "{\"query\":\"" + secretQuery.replace("\"", "\\\"") + "\",\"from\":\"" + from
                + "\",\"to\":\"" + to + "\",\"limit\":5}");
        assertEquals(200, r.status(), r.body());
        Resp c = f.post("/console/api/soc/counts", ana, "{\"query\":\"dataset = firewall | count by action\",\"from\":\"" + from
                + "\",\"to\":\"" + to + "\"}");
        assertEquals(200, c.status(), c.body());
        assertTrue(c.body().contains("groups"));
        String trail = String.join("\n", f.world.org.sink.snapshot().stream().map(x -> x.payloadJson()).toList());
        assertFalse(trail.contains("secret-marker-8c1f"), "only a hash of the query is recorded");
        assertEquals(400, f.post("/console/api/soc/search", ana, "{\"query\":\"x\",\"from\":\"yesterday\",\"to\":\"" + to
                + "\",\"limit\":5}").status());
        assertEquals(400, f.post("/console/api/soc/search", ana, "{\"query\":\"x\",\"from\":\"" + from + "\",\"to\":\"" + to
                + "\",\"limit\":5000}").status());
    }

    @Test
    void aVerdictNeedsAFreshStepUpIsSignedWithTheLabKeyAndSaysSo() throws Exception {
        Sess ana = f.login("ana");
        f.clock.advance(Duration.ofMinutes(6));
        Optional<String> alert = actionableAlert(ana);
        String alertId = alert.orElseThrow(() -> new AssertionError("the lab has a P1 to decide"));
        String body = "{\"alertId\":\"" + alertId + "\",\"outcome\":\"TRUE_POSITIVE\"}";
        Resp stale = f.post("/console/api/soc/verdicts", ana, body);
        assertEquals(403, stale.status());
        assertEquals("{\"error\":\"step-up required\"}", stale.body());

        Sess fresh = f.stepUp(ana);
        Resp signed = f.post("/console/api/soc/verdicts", fresh, body);
        assertEquals(200, signed.status(), signed.body());
        assertTrue(signed.body().contains("lab's analyst key"), "the page is told who held the key: " + signed.body());
        assertTrue(signed.body().contains("\"signedBy\":\"ana\"") && signed.body().contains("\"socStatus\":200"));

        // the same alert, an unknown outcome, a lead without a key, an administrator
        assertEquals(400, f.post("/console/api/soc/verdicts", fresh, "{\"alertId\":\"" + alertId + "\",\"outcome\":\"MAYBE\"}").status());
        Sess cleo = f.login("cleo");
        Resp lead = f.post("/console/api/soc/verdicts", cleo, body);
        assertEquals(403, lead.status());
        assertTrue(lead.body().contains("no signing key"));
        assertEquals(403, f.post("/console/api/soc/verdicts", f.login("dana"), body).status());
    }

    private Optional<String> actionableAlert(Sess s) {
        return f.world.rankedNow().stream().filter(r -> r.priority() == dev.dwarpal.soc.Priority.P1 && r.actionable())
                .map(r -> r.alert().id()).findFirst();
    }

    // ---- the host guards modules

    @Test
    void theHostChecksRoleCsrfAndStepUpBeforeAModuleRuns() throws Exception {
        Sess ana = f.login("ana");
        assertEquals("{\"who\":\"ana\",\"stepUp\":true}", f.get("/console/api/probe/ping", ana).body());
        assertEquals(403, f.get("/console/api/probe/admin-only", ana).status(), "role");
        assertEquals(403, f.get("/console/api/probe/ping", f.login("uma")).status(), "a user is below the route's minimum");
        assertEquals(200, f.get("/console/api/probe/item/abc", f.login("uma")).status());
        assertEquals(404, f.get("/console/api/probe/item/a%2fb", ana).status());
        assertEquals(401, f.get("/console/api/probe/ping", null).status());

        Resp noCsrf = f.raw("POST", "/console/api/probe/change", java.util.Map.of("Origin", f.origin, "Content-Type",
                "application/json", "User-Agent", ConsoleFixture.UA, "Cookie", ConsoleServer.COOKIE + "=" + ana.cookie()), "{}");
        assertEquals(403, noCsrf.status());
        Resp changed = f.post("/console/api/probe/change", ana, "{\"a\":1}");
        assertEquals("{\"changed\":\"ana\",\"body\":{\"a\":1}}", changed.body());

        f.clock.advance(Duration.ofMinutes(6));
        assertEquals(403, f.post("/console/api/probe/danger", ana, "{}").status(), "step-up for a privileged write");
        Sess fresh = f.stepUp(ana);
        assertEquals("{\"danger\":\"done by ana\"}", f.post("/console/api/probe/danger", fresh, "{}").body());
    }

    @Test
    void aModuleThatThrowsLeaksNothing() throws Exception {
        Resp r = f.get("/console/api/probe/boom", f.login("ben"));
        assertEquals(503, r.status());
        assertEquals("{\"error\":\"unavailable\"}", r.body());
        assertFalse(r.body().contains("secret") || r.body().contains("IllegalState"));
    }

    @Test
    void moduleFilesGoOnlyToPeopleWhoMaySeeTheModule() throws Exception {
        assertEquals(401, f.get("/console/modules/probe/index.js", null).status());
        assertEquals(403, f.get("/console/modules/probe/index.js", f.login("uma")).status());
        assertEquals(200, f.get("/console/modules/probe/index.js", f.login("ana")).status());
        assertEquals(404, f.get("/console/modules/other/index.js", f.login("ana")).status(), "a module the server does not host");
    }

    @Test
    void aModuleCannotTakeAReservedOrMalformedId() {
        for (String id : List.of("soc", "session", "audit", "stream", "Bad", "x", "a/b")) {
            ConsoleModule m = new ConsoleModule() {
                @Override
                public String id() {
                    return id;
                }

                @Override
                public String title() {
                    return "t";
                }

                @Override
                public Role minimum() {
                    return Role.ANALYST;
                }

                @Override
                public void routes(Routes routes) {
                }
            };
            assertThrows(IllegalArgumentException.class, () -> ConsoleFixture.start(b -> b.module(m),
                    ConsoleSettings.defaults().fastHashing()), id);
        }
    }

    @Test
    void aModulesMinimumIsHierarchicalButTheBuiltInSocRoutesStayWithAnalystsAndLeads() throws Exception {
        Sess dana = f.login("dana");
        assertEquals(200, f.get("/console/api/probe/ping", dana).status(), "an administrator is above ANALYST for a module");
        assertEquals(200, f.get("/console/api/probe/admin-only", dana).status());
        assertTrue(f.get("/console/api/modules", dana).body().contains("\"id\":\"probe\""));
        assertEquals(200, f.get("/console/modules/probe/index.js", dana).status());
        assertEquals(403, f.get("/console/api/soc/queue", dana).status(), "but not SOC data: no segregation of duties without this");
        assertEquals(403, f.get("/console/api/audit/head", dana).status());
        Sess cleo = f.login("cleo");
        assertEquals(200, f.get("/console/api/probe/ping", cleo).status(), "a lead is above ANALYST");
        assertEquals(403, f.get("/console/api/probe/admin-only", cleo).status(), "a lead is below ADMIN");
        assertEquals(403, f.get("/console/api/probe/ping", f.login("uma")).status());
    }
}

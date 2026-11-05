package dev.dwarpal.socapi;

import dev.dwarpal.soar.SoarWorld;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Verdict;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Red team of the SOC API: reading other analysts' data, acting on one's own case, and using the API to act beyond
 * an analyst's role. Probes F-R3 and F-R4 reproduced leaks in the first version; the others held from the start.
 */
class SocApiRedTeamTest {

    private final SocApiKit kit = new SocApiKit();
    private final SoarWorld w = kit.world;

    @AfterEach
    void stop() {
        kit.close();
    }

    /**
     * F-R3 (leak in the first version): a search hid events about other analysts but still reported how many
     * matched in total and how many were hidden, so ana could count ben's activity ("process.start where subject =
     * ben": matched 3, hidden 3). Fix: hidden events are left out of every number in the answer.
     */
    @Test
    void searchDoesNotRevealHowManyEventsAboutColleaguesMatched() throws Exception {
        for (int i = 1; i <= 3; i++) {
            kit.search.add(i, w.now(), Entity.subject("ben"), Entity.device("laptop-ben"));
        }
        kit.search.add(4, w.now(), Entity.subject("alice"));
        String q = "{\"v\":1,\"query\":\"subject = ben\",\"from\":\"" + w.now().minus(Duration.ofHours(1)) + "\",\"to\":\""
                + w.now().plusSeconds(1) + "\",\"limit\":100}";
        try (SocApiKit.Client ana = kit.as("ana"); SocApiKit.Client cleo = kit.as("cleo")) {
            String body = ana.post("/v1/search", q).body();
            assertFalse(body.contains("laptop-ben"), body);
            assertTrue(body.contains("\"matched\":1"), body);
            assertFalse(body.contains("\"hidden\""), body);
            assertTrue(body.contains("\"truncated\":false"), body);
            String lead = cleo.post("/v1/search", q).body();
            assertTrue(lead.contains("\"matched\":4"), "a lead sees them all: " + lead);
        }
        assertTrue(w.records("SOCAPI_CALL").stream().anyMatch(r -> r.payloadJson().contains("hidden")),
                "the audit trail keeps how many were hidden");
    }

    /**
     * F-R5 (found building the console's hunt page, before count-by was exposed): a count-by that grouped over every
     * event would show "ben: 3" to ana. The counts are taken over only the events the caller may see, so neither a
     * group nor the total gives a colleague's activity away.
     */
    @Test
    void countByDoesNotRevealColleaguesGroupsOrTotals() throws Exception {
        for (int i = 1; i <= 3; i++) {
            kit.search.add(i, w.now(), Entity.subject("ben"));
        }
        kit.search.add(4, w.now(), Entity.subject("alice"));
        kit.search.add(5, w.now(), Entity.subject("alice"));
        String q = "{\"v\":1,\"query\":\"dataset = endpoint | count by subject\",\"from\":\"" + w.now().minus(Duration.ofHours(1))
                + "\",\"to\":\"" + w.now().plusSeconds(1) + "\"}";
        try (SocApiKit.Client ana = kit.as("ana"); SocApiKit.Client cleo = kit.as("cleo")) {
            SocApiKit.Reply r = ana.post("/v1/counts", q);
            assertEquals(200, r.status(), r.body());
            assertFalse(r.body().contains("ben"), r.body());
            assertTrue(r.body().contains("\"alice\"") && r.body().contains("\"count\":2"), r.body());
            assertTrue(r.body().contains("\"matched\":2"), "the total leaves the hidden events out too: " + r.body());
            String lead = cleo.post("/v1/counts", q).body();
            assertTrue(lead.contains("\"matched\":5") && lead.contains("ben"), "a lead sees them all: " + lead);
            assertEquals(400, ana.post("/v1/counts", q.replace("\"v\":1", "\"v\":1,\"limit\":5")).status(),
                    "unknown fields are refused");
            kit.search.problem.set("add '| count by <field>'");
            assertTrue(ana.post("/v1/counts", q).body().contains("problem"));
            kit.search.problem.set(null);
            kit.search.down.set(true);
            assertEquals(503, ana.post("/v1/counts", q).status());
            kit.search.down.set(false);
        }
    }

    /**
     * F-R4 (leak in the first version): a case's links listed every case about the same entities, including cases
     * the reader may not see (a case about her colleague ben that shares an address), so their ids leaked. Fix: links
     * are filtered by the reader's visibility.
     */
    @Test
    void caseLinksDoNotRevealCasesTheReaderCannotSee() throws Exception {
        String hidden = w.caseOf(w.raise("dlp-block-spike", Severity.MEDIUM, Entity.subject("ben"),
                Entity.ip("203.0.113.5")));
        String visible = w.caseOf(w.raise("deny-storm-ip", Severity.HIGH, Entity.subject("alice"),
                Entity.ip("203.0.113.5")));
        assertEquals(java.util.List.of(hidden), w.cases.view(visible).orElseThrow().links());
        try (SocApiKit.Client ana = kit.as("ana"); SocApiKit.Client cleo = kit.as("cleo")) {
            String body = ana.get("/v1/cases/" + visible).body();
            assertFalse(body.contains(hidden), body);
            assertTrue(cleo.get("/v1/cases/" + visible).body().contains(hidden));
            assertFalse(ana.get("/v1/cases/" + visible + "/timeline").body().contains(hidden),
                    "nor through the timeline");
        }
    }

    /** Held: nothing about a colleague's case reaches an analyst, whichever endpoint she tries. */
    @Test
    void anAnalystCannotReadAColleaguesCaseThroughAnyEndpoint() throws Exception {
        String al = w.raise("impossible-travel-allow", Severity.HIGH, Entity.subject("ben"));
        String c = w.caseOf(al);
        try (SocApiKit.Client ana = kit.as("ana")) {
            assertEquals(404, ana.get("/v1/cases/" + c).status());
            assertEquals(404, ana.get("/v1/cases/" + c + "/timeline").status());
            assertEquals(404, ana.post("/v1/cases/" + c + "/notes", "{\"v\":1,\"text\":\"x\"}").status());
            assertEquals(404, ana.post("/v1/cases/" + c + "/assignment", "{\"v\":1,\"assignee\":\"ana\"}").status());
            assertEquals(404, ana.post("/v1/verdicts", SocApiTest.verdictJson(w.verdict("ana", al,
                    Verdict.Outcome.FALSE_POSITIVE))).status());
            assertFalse(ana.get("/v1/cases").body().contains(c));
            assertFalse(ana.get("/v1/queue").body().contains(c));
            // the answer for "exists but not yours" is the answer for "does not exist"
            assertEquals(ana.get("/v1/cases/case-999").body(), ana.get("/v1/cases/" + c).body());
        }
    }

    /** Held: the analyst a case is about cannot clear it through the API, nor read it. */
    @Test
    void anAnalystCannotActOnTheirOwnCaseThroughTheApi() throws Exception {
        String al = w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("ana"), Entity.device("laptop-alice"));
        String c = w.caseOf(al);
        try (SocApiKit.Client ana = kit.as("ana"); SocApiKit.Client cleo = kit.as("cleo")) {
            assertEquals(404, ana.post("/v1/verdicts", SocApiTest.verdictJson(w.verdict("ana", al,
                    Verdict.Outcome.BENIGN))).status());
            assertEquals(404, ana.get("/v1/cases/" + c).status());
            assertEquals(403, cleo.post("/v1/cases/" + c + "/assignment", "{\"v\":1,\"assignee\":\"ana\"}").status());
        }
        assertTrue(w.cases.view(c).orElseThrow().state() != dev.dwarpal.response.Case.State.CLOSED);
    }

    /** Held: through the API, a forged syslog line confirmed by an analyst does not touch the CEO's laptop. */
    @Test
    void theApiCannotIsolateTheCeosLaptopFromAForgedSyslogLine() throws Exception {
        Alert forged = w.alert(SoarWorld.MIXED_RULE, Severity.CRITICAL, Entity.subject("ceo"), Entity.device("laptop-ceo"));
        w.ranker.collectedAlerts.add(forged.id());
        assertTrue(w.cases.raise(forged));
        try (SocApiKit.Client ana = kit.as("ana")) {
            String r = ana.post("/v1/verdicts", SocApiTest.verdictJson(w.verdict("ana", forged.id(),
                    Verdict.Outcome.TRUE_POSITIVE))).body();
            assertTrue(r.contains("\"mode\":\"WATCH_ONLY\""), r);
        }
        assertFalse(w.sensor.isolated("laptop-ceo"));
        assertTrue(w.isolation.all().isEmpty());
    }

    /** Held: there is no endpoint that revokes, denies, isolates or releases directly. */
    @Test
    void noEndpointActsWithoutAVerdict() throws Exception {
        try (SocApiKit.Client cleo = kit.as("cleo")) {
            for (String p : new String[]{"/v1/isolate", "/v1/isolations", "/v1/release", "/v1/revoke", "/v1/deny",
                    "/v1/playbooks"}) {
                int s = cleo.post(p, "{\"v\":1,\"device\":\"laptop-ceo\"}").status();
                assertTrue(s == 404 || s == 405, p + " answered " + s);
            }
        }
        assertFalse(w.sensor.isolated("laptop-ceo"));
    }
}

package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import dev.dwarpal.lab.LabAudit;
import dev.dwarpal.wire.JsonValue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The console writing into its saved trail: real time next to the scenario time, the two sources of the explorer, vault
 * events hidden from analysts and limited for leads, and reads kept compact.
 */
class ConsoleTrailAuditTest {

    @TempDir
    static Path dir;

    private static ConsoleFixture f;
    private static ConsoleTrail trail;

    @BeforeAll
    static void start() throws Exception {
        trail = ConsoleTrail.open(dir, Clock.systemUTC());
        f = ConsoleFixture.start(b -> b.trail(trail), ConsoleSettings.defaults().fastHashing());
    }

    @AfterAll
    static void stop() throws Exception {
        f.close();
        trail.close();
    }

    private static List<LabAudit.Entry> of(String type) {
        return trail.view().page(0, LabAudit.MAX_PAGE, Optional.of(type)).entries();
    }

    private static String payload(long seq) {
        return trail.view().record(seq).orElseThrow().payloadJson();
    }

    private static String firstCaseId(Sess ana) throws Exception {
        return ((JsonValue.JString) ((JsonValue.JObject) ((JsonValue.JArray) ((JsonValue.JObject) f.get("/console/api/soc/queue",
                ana).json()).get("queue").orElseThrow()).get(0)).get("id").orElseThrow()).value();
    }

    @Test
    void theConsoleWritesIntoTheSavedTrailWithRealTimeAndTheScenarioTimeAsAField() throws Exception {
        long labBefore = f.world.org.audit.head().sequence();
        long before = trail.records();
        Sess ana = f.login("ana");
        assertTrue(trail.records() > before, "the sign-in is in the saved trail");
        assertEquals(labBefore, f.world.org.audit.head().sequence(), "and not in the simulated chain");
        LabAudit.Entry login = of("CONSOLE_LOGIN").getLast();
        assertEquals("ana", login.actor());
        assertEquals(f.clock.instant(), login.at(), "a record's time is the real clock's");
        assertTrue(payload(login.sequence()).contains("\"scenario\":\""), "the scenario clock's time is a field");
        assertEquals("ana", ana.user());
    }

    @Test
    void theExplorerReadsEitherSourceAndRefusesAnythingElse() throws Exception {
        Sess ana = f.login("ana");
        Resp head = f.get("/console/api/audit/head?source=console", ana);
        assertEquals(200, head.status(), head.body());
        assertTrue(head.body().contains("\"sources\":[\"lab\",\"console\"]"), head.body());
        Resp page = f.get("/console/api/audit/records?source=console&limit=50", ana);
        assertEquals(200, page.status());
        assertTrue(page.body().contains("CONSOLE_LOGIN"));
        assertTrue(f.get("/console/api/audit/head", ana).body().contains("\"head\":" + f.world.org.audit.head().sequence()),
                "the default is still the simulated chain");
        assertEquals(404, f.get("/console/api/audit/records?source=nonsense", ana).status());
        Resp verify = f.get("/console/api/audit/verify?source=console", ana);
        assertEquals(200, verify.status());
        assertTrue(verify.body().contains("\"intact\":true"), verify.body());
    }

    @Test
    void vaultEventsAreHiddenFromAnalystsAndLimitedForLeads() throws Exception {
        trail.log().append("VAULT_OPENED", "dana", Instant.now(), Map.of("action", "opened a person's credentials",
                "target", "uma", "secret", "TOPSECRET-123", "reason", "REASON-XYZ"));
        long seq = trail.records();
        Sess ana = f.login("ana");
        Sess cleo = f.login("cleo");

        Resp list = f.get("/console/api/audit/records?source=console&limit=200", ana);
        assertEquals(200, list.status());
        assertFalse(list.body().contains("VAULT_"), "an analyst cannot even see that vault events exist");
        assertFalse(f.get("/console/api/audit/records?source=console&type=VAULT_OPENED", ana).body().contains("VAULT_"));
        Resp hidden = f.get("/console/api/audit/records/" + seq + "?source=console", ana);
        Resp missing = f.get("/console/api/audit/records/" + (seq + 1000) + "?source=console", ana);
        assertEquals(404, hidden.status());
        assertEquals(missing.status(), hidden.status());
        assertEquals(missing.body(), hidden.body(), "the same answer as for a record that does not exist");

        Resp leadList = f.get("/console/api/audit/records?source=console&type=VAULT_OPENED", cleo);
        assertEquals(200, leadList.status());
        assertTrue(leadList.body().contains("VAULT_OPENED") && leadList.body().contains("\"actor\":\"dana\""), leadList.body());
        assertTrue(leadList.body().contains("uma") && leadList.body().contains("opened a person"), "who, when and on whom");
        assertTrue(leadList.body().contains("\"at\":\""));
        Resp leadOne = f.get("/console/api/audit/records/" + seq + "?source=console", cleo);
        assertEquals(200, leadOne.status());
        for (Resp r : List.of(leadList, leadOne)) {
            assertFalse(r.body().contains("TOPSECRET"), "never the secret");
            assertFalse(r.body().contains("REASON-XYZ"), "and nothing but what a lead may see");
        }
        assertTrue(f.get("/console/api/audit/verify?source=console", ana).body().contains("\"intact\":true"),
                "the vault records are part of the chain the analyst verifies");
    }

    @Test
    void sensitiveReadsAreCompactAndBackgroundRefreshesAreNotRecorded() throws Exception {
        Sess ana = f.login("ana");
        String caseId = firstCaseId(ana);
        int reads = of("CONSOLE_READ").size();
        for (int i = 0; i < 3; i++) {
            assertEquals(200, f.get("/console/api/soc/cases/" + caseId, ana).status());
        }
        assertEquals(reads + 1, of("CONSOLE_READ").size(), "three reads in a minute are one record");
        for (int i = 0; i < 3; i++) {
            assertEquals(200, f.backgroundGet("/console/api/soc/cases/" + caseId, ana).status());
        }
        assertEquals(reads + 1, of("CONSOLE_READ").size(), "a page refreshing itself is not a read");

        f.clock.advance(Duration.ofSeconds(61));
        assertEquals(200, f.get("/console/api/soc/cases/" + caseId, ana).status());
        List<LabAudit.Entry> now = of("CONSOLE_READ");
        assertEquals(reads + 2, now.size());
        assertTrue(payload(now.getLast().sequence()).contains("\"repeats\":\"2\""), "the next record carries the count");
    }

    @Test
    void ordinaryViewsAreOneRecordPerWindowAndOwnAccountPagesAreLeftOut() throws Exception {
        Sess ana = f.login("ana");
        int before = of("CONSOLE_VIEW").size();
        for (int i = 0; i < 5; i++) {
            assertEquals(200, f.get("/console/api/soc/metrics", ana).status());
        }
        assertEquals(before + 1, of("CONSOLE_VIEW").size());
        assertEquals(200, f.backgroundGet("/console/api/soc/isolations", ana).status());
        assertEquals(before + 1, of("CONSOLE_VIEW").size(), "a background refresh is not recorded");
        assertEquals(200, f.get("/console/api/me", ana).status());
        assertEquals(200, f.get("/console/api/modules", ana).status());
        assertEquals(before + 1, of("CONSOLE_VIEW").size(), "the person's own account pages are not working views");
        assertTrue(payload(of("CONSOLE_VIEW").getLast().sequence()).contains("\"route\":\"soc/metrics\""));
    }
}

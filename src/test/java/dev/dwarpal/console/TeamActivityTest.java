package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The read-only "Team activity" view of the monitoring page: who sees whom, filters, paging, redaction. */
class TeamActivityTest {

    private static final String TEAM = "/console/api/monitor/team";

    @TempDir
    Path dir;

    private ConsoleTrail trail;
    private ConsoleFixture f;

    @BeforeEach
    void start() throws Exception {
        trail = ConsoleTrail.open(dir, Clock.systemUTC());
        f = ConsoleFixture.start(b -> b.trail(trail).module(new MonitorModule(() -> Set.of("dana", "spector"), () -> Set.of("ana", "ben", "cleo", "dana", "spector", "uma"))),
                ConsoleSettings.defaults().fastHashing());
        for (int i = 0; i < 130; i++) {
            add("CONSOLE_WRITE", "ana", Map.of("route", "soc/verdicts", "status", "200", "n", Integer.toString(i), "session", "hidden-tag"));
        }
        add("CONSOLE_REFUSED", "ana", Map.of("route", "vault/x"));
        add("CONSOLE_VIEW", "ana", Map.of("route", "lab/status"));
        add("ELEVATION_STARTED", "spector", Map.of("elevation", "el-9"));
        add("ELEVATION_STARTED", "dana", Map.of("elevation", "el-2"));
        add("CONSOLE_WRITE", "cleo", Map.of("route", "lead/own"));
        add("VAULT_REVEAL", "ana", Map.of("action", "reveal", "target", "uma", "secret", "hunter2-the-secret", "reason", "locked out"));
    }

    @AfterEach
    void stop() throws Exception {
        f.close();
        trail.close();
    }

    private void add(String type, String actor, Map<String, String> payload) {
        trail.log().append(type, actor, Clock.systemUTC().instant(), payload);
    }

    private static JsonValue.JObject obj(Resp r) {
        return (JsonValue.JObject) new JsonReader().read(r.body());
    }

    private static List<Long> sequences(JsonValue.JObject o) {
        List<Long> out = new ArrayList<>();
        for (JsonValue v : ((JsonValue.JArray) o.get("rows").orElseThrow()).elements()) {
            out.add(((JsonValue.JNumber) ((JsonValue.JObject) v).get("sequence").orElseThrow()).asLong());
        }
        return out;
    }

    private List<Long> all(Sess s, String extra) throws Exception {
        List<Long> out = new ArrayList<>();
        String before = null;
        for (int guard = 0; guard < 20; guard++) {
            Resp r = f.get(TEAM + "?" + extra + (before == null ? "" : "&before=" + before), s);
            assertEquals(200, r.status(), r.body());
            JsonValue.JObject o = obj(r);
            out.addAll(sequences(o));
            JsonValue next = o.get("next").orElseThrow();
            if (!(next instanceof JsonValue.JNumber n)) {
                return out;
            }
            before = Long.toString(n.asLong());
        }
        throw new AssertionError("paging did not end");
    }

    @Test
    void anAdministratorSeesAnalystsAndTheOtherAdministratorButNotThemself() throws Exception {
        Resp r = f.get(TEAM, f.login("dana"));
        assertEquals(200, r.status(), r.body());
        assertTrue(r.body().contains("\"actor\":\"ana\"") && r.body().contains("\"actor\":\"spector\"") && r.body().contains("\"actor\":\"cleo\""), r.body());
        assertFalse(r.body().contains("el-2"), "dana's own action is not shown to her");
        assertTrue(r.body().contains("\"window\":2000"), r.body());
        assertFalse(r.body().contains("hidden-tag"), "housekeeping fields are left out");
        assertFalse(r.body().contains("lab/status"), "plain page views are not shown");
        assertFalse(r.body().contains("\"dana\""), "not even in the filter menus");
    }

    @Test
    void aLeadSeesAnalystsButNoAdministratorAndNotThemself() throws Exception {
        Resp r = f.get(TEAM, f.login("cleo"));
        assertEquals(200, r.status(), r.body());
        assertTrue(r.body().contains("\"actor\":\"ana\""), r.body());
        assertFalse(r.body().contains("spector") || r.body().contains("dana") || r.body().contains("lead/own"), r.body());
    }

    @Test
    void anAnalystIsRefusedLikeOnTheOtherRoutes() throws Exception {
        Sess ana = f.login("ana");
        assertEquals(f.get("/console/api/monitor/admins", ana).status(), f.get(TEAM, ana).status());
        assertEquals(403, f.get(TEAM, ana).status());
    }

    @Test
    void filtersByPersonAndType() throws Exception {
        Sess dana = f.login("dana");
        Resp p = f.get(TEAM + "?person=spector", dana);
        assertEquals(200, p.status(), p.body());
        assertTrue(p.body().contains("el-9") && !p.body().contains("\"actor\":\"ana\""), p.body());
        Resp t = f.get(TEAM + "?type=CONSOLE_REFUSED", dana);
        assertTrue(t.body().contains("vault/x") && !t.body().contains("\"type\":\"CONSOLE_WRITE\""), t.body());
        Resp both = f.get(TEAM + "?type=CONSOLE_REFUSED&person=spector", dana);
        assertEquals(0, sequences(obj(both)).size(), both.body());
    }

    @Test
    void pagesAreDisjointAndTogetherEqualTheUnpagedList() throws Exception {
        Sess dana = f.login("dana");
        Resp first = f.get(TEAM, dana);
        JsonValue.JObject o = obj(first);
        assertEquals(100, sequences(o).size());
        assertTrue(o.get("next").orElseThrow() instanceof JsonValue.JNumber, "more rows remain");
        List<Long> paged = all(dana, "person=ana");
        assertEquals(paged.size(), new java.util.HashSet<>(paged).size(), "no row twice");
        List<Long> sorted = new ArrayList<>(paged);
        sorted.sort(java.util.Comparator.reverseOrder());
        assertEquals(sorted, paged, "newest first across pages");
        assertEquals(130 + 1 + 1, paged.size(), "130 writes, the refusal and the vault record; the page view is left out");
    }

    @Test
    void malformedParametersAreRefused() throws Exception {
        Sess dana = f.login("dana");
        for (String q : new String[]{"person=a%20b", "person=", "person=..%2F..", "type=lower", "type=", "type=A%3BB", "before=abc",
                "before=-1", "before=", "before=99999999999999999999", "limit=5", "person=" + "a".repeat(65)}) {
            assertEquals(400, f.get(TEAM + "?" + q, dana).status(), q);
        }
    }

    @Test
    void aVaultRecordNeverShowsASecretOrReason() throws Exception {
        Resp r = f.get(TEAM + "?type=VAULT_REVEAL", f.login("dana"));
        assertEquals(200, r.status(), r.body());
        assertTrue(r.body().contains("action: reveal; target: uma"), r.body());
        assertFalse(r.body().contains("hunter2") || r.body().contains("locked out"), r.body());
        Resp lead = f.get(TEAM, f.login("cleo"));
        assertFalse(lead.body().contains("hunter2") || lead.body().contains("locked out"), lead.body());
    }

    @Test
    void thereIsNoWayToWriteThroughTheRoute() throws Exception {
        Sess dana = f.login("dana");
        assertTrue(f.post(TEAM, dana, "{}").status() >= 400);
        for (String m : new String[]{"PUT", "DELETE", "PATCH"}) {
            int s = f.raw(m, TEAM, Map.of("Cookie", ConsoleServer.COOKIE + "=" + dana.cookie(), "User-Agent", ConsoleFixture.UA), null).status();
            assertTrue(s == 404 || s == 405 || s == 403 || s == 400, m + " answered " + s);
        }
    }

    @Test
    void machineActorsAreNeverShown() throws Exception {
        add("ACCESS_DECISION", "pdp", Map.of("verdict", "ALLOW"));
        add("SOCAPI_CALL", "soc-api", Map.of("route", "v1/search"));
        for (String who : new String[]{"dana", "cleo"}) {
            Resp r = f.get(TEAM, f.login(who));
            assertEquals(200, r.status(), r.body());
            assertFalse(r.body().contains("pdp") || r.body().contains("soc-api") || r.body().contains("ACCESS_DECISION")
                    || r.body().contains("SOCAPI_CALL"), who + ": " + r.body());
        }
    }

    @Test
    void theOneArgumentConstructorShowsOnlyAdministrators() throws Exception {
        f.close();
        f = ConsoleFixture.start(b -> b.trail(trail).module(new MonitorModule(() -> Set.of("dana", "spector"))),
                ConsoleSettings.defaults().fastHashing());
        Resp r = f.get(TEAM, f.login("dana"));
        assertEquals(200, r.status(), r.body());
        assertTrue(r.body().contains("\"actor\":\"spector\""), r.body());
        assertFalse(r.body().contains("\"actor\":\"ana\"") || r.body().contains("\"actor\":\"cleo\""), r.body());
        Resp lead = f.get(TEAM, f.login("cleo"));
        assertEquals(0, sequences(obj(lead)).size(), lead.body());
    }
}

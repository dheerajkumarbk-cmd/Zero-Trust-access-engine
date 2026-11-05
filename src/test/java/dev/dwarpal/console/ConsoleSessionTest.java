package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Standards section 3, "Session and cookies": lifetimes, fixation, binding, step-up rotation, limits, logout. */
class ConsoleSessionTest {

    private static ConsoleFixture f;

    @BeforeAll
    static void start() throws Exception {
        f = ConsoleFixture.start();
    }

    @AfterAll
    static void stop() {
        f.close();
    }

    @Test
    void loginIsTwoStepsAndTheSessionKnowsWhoItIs() throws Exception {
        Sess ana = f.login("ana");
        Resp me = f.get("/console/api/me", ana);
        assertEquals(200, me.status());
        assertTrue(me.body().contains("\"id\":\"ana\"") && me.body().contains("ANALYST"), me.body());
        assertEquals(ana.csrf(), me.field("csrf") , "the page can fetch its anti-forgery token again after a reload");
        assertEquals(401, f.get("/console/api/me", null).status());
    }

    @Test
    void aWrongPasswordAnAnUnknownUserAndAWrongPinAreIndistinguishable() throws Exception {
        ConsoleAuth.Enrolment ana = f.person("ana");
        Resp wrongPassword = f.login("ana", "wrong-password-xyz", ana.pin());
        Resp wrongPin = f.login("ana", ana.password(), "BADPIN99");
        Resp unknown = f.login("nobody", "wrong-password-xyz", "BADPIN99");
        for (Resp r : new Resp[]{wrongPassword, wrongPin, unknown}) {
            assertEquals(401, r.status());
            assertEquals("{\"error\":\"login failed\"}", r.body());
            assertEquals(0, r.headers().allValues("Set-Cookie").size());
        }
        // the first step answers the same for a user that exists and one that does not
        Resp a = f.post("/console/api/session/login", null, "{\"user\":\"ana\",\"password\":\"x\"}");
        Resp b = f.post("/console/api/session/login", null, "{\"user\":\"nobody\",\"password\":\"x\"}");
        assertEquals(a.status(), b.status());
        assertEquals(a.json().getClass(), b.json().getClass());
        assertEquals(a.body().length(), b.body().length());
    }

    @Test
    void aLoginIdWorksOnlyOnce() throws Exception {
        ConsoleAuth.Enrolment ben = f.person("ben");
        Resp first = f.post("/console/api/session/login", null, "{\"user\":\"ben\",\"password\":\"" + ben.password() + "\"}");
        String id = first.field("loginId");
        String body = "{\"loginId\":\"" + id + "\",\"pin\":\"" + ben.pin() + "\"}";
        assertEquals(200, f.post("/console/api/session/verify", null, body).status());
        assertEquals(401, f.post("/console/api/session/verify", null, body).status(), "single use");
    }

    @Test
    void aSessionIdPlantedBeforeLoginIsNotKept() throws Exception {
        ConsoleAuth.Enrolment cleo = f.person("cleo");
        String planted = "A".repeat(43);
        Map<String, String> h = new LinkedHashMap<>();
        h.put("User-Agent", ConsoleFixture.UA);
        h.put("Origin", f.origin);
        h.put("Content-Type", "application/json");
        h.put("Cookie", ConsoleServer.COOKIE + "=" + planted);
        Resp one = f.raw("POST", "/console/api/session/login", h, "{\"user\":\"cleo\",\"password\":\"" + cleo.password() + "\"}");
        Resp two = f.raw("POST", "/console/api/session/verify", h, "{\"loginId\":\"" + one.field("loginId") + "\",\"pin\":\""
                + cleo.pin() + "\"}");
        assertEquals(200, two.status());
        assertNotEquals(planted, ConsoleFixture.cookieValue(two), "a new identifier at login (no fixation)");
        assertEquals(401, f.get("/console/api/me", new Sess(planted, "x", "cleo")).status());
    }

    @Test
    void idleTimeoutIsFifteenMinutesAndOnlyRealActivityCountsAsActivity() throws Exception {
        Sess s = f.login("ana");
        f.clock.advance(Duration.ofMinutes(14));
        assertEquals(200, f.get("/console/api/me", s).status());
        f.clock.advance(Duration.ofMinutes(14));
        assertEquals(200, f.get("/console/api/me", s).status(), "activity extends the idle time");
        f.clock.advance(Duration.ofMinutes(16));
        assertEquals(401, f.get("/console/api/me", s).status(), "16 idle minutes end the session");

        Sess t = f.login("ana");
        f.clock.advance(Duration.ofMinutes(10));
        Map<String, String> h = new LinkedHashMap<>();
        h.put("User-Agent", ConsoleFixture.UA);
        h.put("Cookie", ConsoleServer.COOKIE + "=" + t.cookie());
        h.put(ConsoleServer.BACKGROUND_HEADER, "1");
        assertEquals(200, f.raw("GET", "/console/api/me", h, null).status());
        f.clock.advance(Duration.ofMinutes(6));
        assertEquals(401, f.get("/console/api/me", t).status(), "a background refresh does not keep a session alive");
    }

    @Test
    void absoluteLifetimeIsEightHoursWhateverTheActivity() throws Exception {
        Sess s = f.login("ben");
        for (int i = 0; i < 34; i++) {
            f.clock.advance(Duration.ofMinutes(14));
            assertEquals(200, f.get("/console/api/me", s).status(), "minute " + (i + 1) * 14);
        }
        f.clock.advance(Duration.ofMinutes(14));
        assertEquals(401, f.get("/console/api/me", s).status(), "after 8 hours the session is over although it was busy");
    }

    @Test
    void logoutDestroysTheSessionOnTheServer() throws Exception {
        Sess s = f.login("ana");
        Resp out = f.post("/console/api/session/logout", s, "{}");
        assertEquals(200, out.status());
        assertTrue(out.headers().allValues("Set-Cookie").getFirst().contains("Max-Age=0"));
        assertEquals(401, f.get("/console/api/me", s).status(), "the old cookie is worth nothing");
    }

    @Test
    void stepUpIsFreshForFiveMinutesAndGivesANewIdentifier() throws Exception {
        Sess s = f.login("ana");
        assertTrue(f.get("/console/api/me", s).body().contains("\"stepUpFresh\":true"), "login itself proved both factors");
        f.clock.advance(Duration.ofMinutes(6));
        assertTrue(f.get("/console/api/me", s).body().contains("\"stepUpFresh\":false"));
        Sess fresh = f.stepUp(s);
        assertNotEquals(s.cookie(), fresh.cookie());
        assertNotEquals(s.csrf(), fresh.csrf());
        assertEquals(401, f.get("/console/api/me", s).status(), "the identifier from before the step-up is dead");
        assertTrue(f.get("/console/api/me", fresh).body().contains("\"stepUpFresh\":true"));
        f.clock.advance(Duration.ofMinutes(4));
        assertTrue(f.get("/console/api/me", fresh).body().contains("\"stepUpFresh\":true"));
        f.clock.advance(Duration.ofMinutes(2));
        assertTrue(f.get("/console/api/me", fresh).body().contains("\"stepUpFresh\":false"));
    }

    @Test
    void aWrongStepUpIsRefusedAndKeepsTheOldFreshness() throws Exception {
        Sess s = f.login("ben");
        f.clock.advance(Duration.ofMinutes(6));
        Resp bad = f.post("/console/api/session/stepup", s, "{\"password\":\"" + f.person("ben").password() + "\",\"pin\":\"BADPIN99\"}");
        assertEquals(401, bad.status());
        assertEquals(200, f.get("/console/api/me", s).status(), "the session itself survives a failed step-up");
        assertTrue(f.get("/console/api/me", s).body().contains("\"stepUpFresh\":false"));
    }

    @Test
    void aPersonHasAtMostThreeSessionsAndCanSeeAndEndTheOthers() throws Exception {
        Sess one = f.login("cleo");
        Sess two = f.login("cleo");
        Sess three = f.login("cleo");
        Resp list = f.get("/console/api/session/list", three);
        assertEquals(3, count(list.body(), "\"current\""));
        Sess four = f.login("cleo");
        assertEquals(401, f.get("/console/api/me", one).status(), "the oldest was ended");
        assertEquals(200, f.get("/console/api/me", two).status());
        // revoke another session from the list
        Resp l = f.get("/console/api/session/list", four);
        String otherTag = null;
        for (String part : l.body().split("\\{")) {
            if (part.contains("\"current\":false")) {
                otherTag = part.replaceAll(".*\"id\":\"([0-9a-f]+)\".*", "$1");
                break;
            }
        }
        assertEquals(200, f.post("/console/api/session/revoke", four, "{\"id\":\"" + otherTag + "\"}").status());
        assertEquals(2, count(f.get("/console/api/session/list", four).body(), "\"current\""));
        assertFalse(f.get("/console/api/session/list", four).body().contains(four.cookie()), "the cookie value is never shown");
    }

    @Test
    void aStolenCookieUsedFromAnotherBrowserIsRefusedAndEndsTheSession() throws Exception {
        Sess s = f.login("ana");
        Map<String, String> thief = new LinkedHashMap<>();
        thief.put("User-Agent", "SomeOtherBrowser/9");
        thief.put("Cookie", ConsoleServer.COOKIE + "=" + s.cookie());
        assertEquals(401, f.raw("GET", "/console/api/me", thief, null).status());
        assertEquals(401, f.get("/console/api/me", s).status(), "the real owner is logged out too: the cookie is burnt");
    }

    @Test
    void malformedOrDuplicatedSessionCookiesAreIgnored() throws Exception {
        Sess s = f.login("ana");
        for (String bad : new String[]{ConsoleServer.COOKIE + "=short", ConsoleServer.COOKIE + "=" + s.cookie() + "; "
                + ConsoleServer.COOKIE + "=" + "B".repeat(43), ConsoleServer.COOKIE + "=" + s.cookie() + "'; DROP"}) {
            Map<String, String> h = new LinkedHashMap<>();
            h.put("User-Agent", ConsoleFixture.UA);
            h.put("Cookie", bad);
            assertEquals(401, f.raw("GET", "/console/api/me", h, null).status(), bad);
        }
        assertEquals(200, f.get("/console/api/me", s).status());
    }

    private static int count(String text, String needle) {
        int n = 0;
        for (int i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + 1)) {
            n++;
        }
        return n;
    }
}

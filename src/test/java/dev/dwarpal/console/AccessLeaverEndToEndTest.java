package dev.dwarpal.console;

import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import dev.dwarpal.console.access.AccessApi;
import dev.dwarpal.console.access.AccessModule;
import dev.dwarpal.directory.CredentialLifecycle;
import dev.dwarpal.directory.DirectoryPerson;
import dev.dwarpal.directory.PostgresAccess;
import dev.dwarpal.directory.PostgresDirectory;
import dev.dwarpal.directory.TestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The access process on the real console server: HR removes a leaver and the leaver's open session ends at once and
 * their next sign-in fails; the host asks for a fresh second factor; every change is in the audit chain under the
 * person who did it.
 */
class AccessLeaverEndToEndTest {

    private ConsoleFixture f;
    private PostgresDirectory directory;

    @BeforeEach
    void start() throws Exception {
        TestDatabase.require();
        TestDatabase.reset();
        directory = new PostgresDirectory(TestDatabase.app());
        AccessApi api = new AccessApi(new PostgresAccess(TestDatabase.app()), directory, CredentialLifecycle.NONE);
        f = ConsoleFixture.start(b -> b.module(new AccessModule(api)), ConsoleSettings.defaults().fastHashing());
        DirectoryPeople.sync(directory, f.people, Clock.systemUTC());
    }

    @AfterEach
    void stop() {
        f.close();
    }

    private static final String LEAVER = "{\"id\":\"uma\",\"reason\":\"last day was Friday\"}";

    private List<AuditRecord> since(long seq) {
        return f.world.org.sink.snapshot().stream().filter(r -> r.sequence() > seq).toList();
    }

    @Test
    void aLeaverIsLockedOutAtOnceTheirSessionEndsAndTheyCannotSignInAgain() throws Exception {
        Sess uma = f.login("uma");
        Sess hana = f.login("hana");
        assertEquals(200, f.get("/console/api/me", uma).status());
        long before = f.world.org.audit.head().sequence();

        Resp r = f.post("/console/api/access/hr/leaver", hana, LEAVER);
        assertEquals(200, r.status(), r.body());

        assertEquals(401, f.get("/console/api/me", uma).status(), "the open session is gone");
        ConsoleAuth.Enrolment e = f.person("uma");
        assertNotEquals(200, f.login("uma", e.password(), e.pin()).status(), "and so is the way back in");
        assertEquals(DirectoryPerson.Status.DISABLED, directory.find("uma").orElseThrow().status());
        assertTrue(directory.find("uma").orElseThrow().consoleRoles().isEmpty());

        List<AuditRecord> written = since(before);
        assertTrue(written.stream().anyMatch(a -> a.type().equals("ACCESS_PERSON_DISABLED") && a.actor().equals("hana")
                && a.payloadJson().contains("\"person\":\"uma\"")), "the removal is in the audit chain under HR");
        assertTrue(written.stream().anyMatch(a -> a.type().equals("ACCESS_ROLES_REMOVED")));
        assertTrue(written.stream().anyMatch(a -> a.type().equals("CONSOLE_WRITE") && a.payloadJson().contains("hr/leaver")),
                "the host recorded the attempt and the result too");
    }

    @Test
    void theHostAsksForAFreshSecondFactorAndOnlyHrMayCall() throws Exception {
        Sess hana = f.login("hana");
        Sess ana = f.login("ana");
        assertEquals(403, f.post("/console/api/access/hr/leaver", ana, LEAVER).status(), "an analyst is not HR");
        f.clock.advance(Duration.ofMinutes(10));
        Resp stale = f.post("/console/api/access/hr/leaver", hana, LEAVER);
        assertEquals(403, stale.status(), "the second factor is older than five minutes: " + stale.body());
        assertEquals(DirectoryPerson.Status.ACTIVE, directory.find("uma").orElseThrow().status(), "nothing happened");
        assertEquals(401, f.post("/console/api/access/hr/leaver", null, LEAVER).status());
        Sess fresh = f.stepUp(hana);
        assertEquals(200, f.post("/console/api/access/hr/leaver", fresh, LEAVER).status());
    }

    @Test
    void aJoinerAsksThroughTheConsoleAndStaysUnseenByEveryoneButTheAdministrator() throws Exception {
        Sess hana = f.login("hana");
        Resp asked = f.post("/console/api/access/hr/joiner", hana, "{\"id\":\"priya\",\"name\":\"Priya Nair\",\"department\":\"Engineering\","
                + "\"businessRole\":\"Software engineer\",\"reason\":\"starts on Monday\"}");
        assertEquals(200, asked.status(), asked.body());
        assertTrue(directory.find("priya").isEmpty());
        Sess ana = f.login("ana");
        assertEquals(403, f.get("/console/api/access/approvals", ana).status());
        Sess uma = f.login("uma");
        assertEquals(200, f.get("/console/api/access/mine", uma).status());
        assertEquals(403, f.get("/console/api/access/hr", uma).status());
        assertTrue(f.get("/console/api/modules", uma).body().contains("\"id\":\"access\""), "everybody sees their own access page");
    }
}

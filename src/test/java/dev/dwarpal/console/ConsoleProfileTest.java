package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleAuth.Change;
import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.wire.JsonValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The Profile page's promises: changing one's own secrets, the weekly change, backup codes and the passkey lock. */
class ConsoleProfileTest {

    private static final String NEW_PASSWORD = "a-much-longer-secret-9";
    private static final String NEW_PIN = "Kj7mQ2xP";
    private static final String PASSKEY = "gate-keeper-passkey";
    private static final String FAILED = "wrong password or PIN";

    private ConsoleFixture f;

    @BeforeEach
    void start() throws Exception {
        f = ConsoleFixture.start(b -> b.passkeyLock(Duration.ofMinutes(15)), ConsoleSettings.defaults().fastHashing());
    }

    @AfterEach
    void stop() {
        f.close();
    }

    private String proof(String id) {
        ConsoleAuth.Enrolment e = f.person(id);
        return "\"password\":\"" + e.password() + "\",\"pin\":\"" + e.pin() + "\"";
    }

    private Resp setPasskey(Sess s) throws Exception {
        return f.post("/console/api/profile/passkey", s, "{" + proof(s.user()) + ",\"passkey\":\"" + PASSKEY + "\"}");
    }

    private Resp unlock(Sess s) throws Exception {
        return f.post("/console/api/session/unlock", s, "{\"passkey\":\"" + PASSKEY + "\"}");
    }

    private Resp lock(Sess s) throws Exception {
        return f.post("/console/api/session/lock", s, "{}");
    }

    private Resp recoverCode(String user, String code) throws Exception {
        return f.post("/console/api/session/recover/code", null, "{\"user\":\"" + user + "\",\"code\":\"" + code + "\"}");
    }

    private Resp recover(String ticket, String password, String pin) throws Exception {
        return f.post("/console/api/session/recover", null, "{\"ticket\":\"" + ticket + "\",\"newPassword\":\"" + password
                + "\",\"newPin\":\"" + pin + "\"}");
    }

    private Resp changePassword(Sess s) throws Exception {
        return f.post("/console/api/profile/password", s, "{" + proof(s.user()) + ",\"newPassword\":\"" + NEW_PASSWORD + "\"}");
    }

    private Resp search(Sess s) throws Exception {
        return f.post("/console/api/soc/search", s, "{\"query\":\"*\",\"from\":\"2026-11-01T00:00:00Z\",\"to\":\"2026-11-08T00:00:00Z\",\"limit\":5}");
    }

    private List<String> codes(Sess s) throws Exception {
        Resp r = f.post("/console/api/profile/backup-codes", s, "{" + proof(s.user()) + "}");
        assertEquals(200, r.status(), r.body());
        List<String> out = new ArrayList<>();
        JsonValue v = ((JsonValue.JObject) r.json()).get("codes").orElseThrow();
        for (JsonValue c : ((JsonValue.JArray) v).elements()) {
            out.add(((JsonValue.JString) c).value());
        }
        return out;
    }

    @Test
    void aNewPasswordReplacesTheOldOneAndEndsOtherSessions() throws Exception {
        Sess here = f.login("ana");
        Sess elsewhere = f.login("ana");
        assertEquals(200, changePassword(here).status());
        assertEquals(200, f.get("/console/api/me", here).status(), "the person who changed it stays in");
        assertEquals(401, f.get("/console/api/me", elsewhere).status(), "whoever else was in is out");
        assertEquals(401, f.login("ana", f.person("ana").password(), f.person("ana").pin()).status());
        assertEquals(200, f.login("ana", NEW_PASSWORD, f.person("ana").pin()).status());
    }

    @Test
    void aChangeNeedsTheRealPasswordAndPinAndAStrongNewValue() throws Exception {
        Sess s = f.login("ben");
        Resp wrong = f.post("/console/api/profile/password", s, "{\"password\":\"not-the-password\",\"pin\":\"" + f.person("ben").pin()
                + "\",\"newPassword\":\"" + NEW_PASSWORD + "\"}");
        assertEquals(401, wrong.status());
        assertTrue(wrong.body().contains(FAILED), wrong.body());
        for (String weak : new String[]{"short", "ben-ben-ben-ben", "aaaaaaaaaaaaaaaa", f.person("ben").password()}) {
            Resp r = f.post("/console/api/profile/password", s, "{" + proof("ben") + ",\"newPassword\":\"" + weak + "\"}");
            assertEquals(400, r.status(), weak);
        }
        assertEquals(200, f.login("ben", f.person("ben").password(), f.person("ben").pin()).status(), "nothing changed");
    }

    @Test
    void aNewPinReplacesTheOldOne() throws Exception {
        Sess s = f.login("cleo");
        assertEquals(200, f.post("/console/api/profile/pin", s, "{" + proof("cleo") + ",\"newPin\":\"" + NEW_PIN + "\"}").status());
        assertEquals(401, f.login("cleo", f.person("cleo").password(), f.person("cleo").pin()).status());
        assertEquals(200, f.login("cleo", f.person("cleo").password(), NEW_PIN).status());
    }

    @Test
    void confidentialViewsStayClosedUntilThePasskey() throws Exception {
        Sess s = f.login("ana");
        assertEquals(423, search(s).status());
        assertEquals(423, f.get("/console/api/audit/records?after=0&limit=5", s).status());
        assertEquals(200, f.get("/console/api/soc/queue", s).status(), "the queue shows no confidential detail");
        assertEquals(200, f.post("/console/api/soc/counts", s, "{\"query\":\"* | count by dataset\",\"from\":\"2026-11-01T00:00:00Z\",\"to\":\"2026-11-08T00:00:00Z\"}").status());

        assertEquals(200, setPasskey(s).status());
        assertEquals(423, search(s).status(), "setting a passkey opens nothing by itself");
        assertEquals(200, unlock(s).status());
        assertEquals(200, search(s).status());
        f.clock.advance(Duration.ofMinutes(14));
        assertEquals(200, search(s).status(), "still inside the fifteen minutes");
        f.clock.advance(Duration.ofMinutes(2));
        assertEquals(423, search(s).status(), "using it did not extend it: the window ends fifteen minutes after the passkey");
        assertEquals(200, unlock(s).status());
        assertEquals(200, search(s).status());

        Sess other = f.login("ana");
        assertEquals(423, search(other).status(), "a passkey opens one session, not the person's others");
        assertEquals(401, f.post("/console/api/session/unlock", other, "{\"passkey\":\"not-the-passkey\"}").status());
        assertEquals(423, search(other).status());
        assertEquals(200, unlock(other).status());
        assertEquals(200, search(other).status());
    }

    @Test
    void closingAViewLocksItAgainAtOnce() throws Exception {
        Sess s = f.login("ana");
        assertEquals(200, setPasskey(s).status());
        for (int opening = 0; opening < 3; opening++) {
            assertEquals(423, search(s).status(), "every opening needs the passkey, opening " + opening);
            assertEquals(200, unlock(s).status());
            assertEquals(200, search(s).status());
            assertEquals(200, lock(s).status());
        }
        assertEquals(200, lock(s).status(), "locking twice is harmless");
        assertTrue(f.get("/console/api/me", s).body().contains("\"unlocked\":false"));
    }

    @Test
    void neitherARefreshingPageNorUseKeepsTheWindowOpenPastItsEnd() throws Exception {
        Sess s = f.login("ben");
        assertEquals(200, setPasskey(s).status());
        assertEquals(200, unlock(s).status());
        f.clock.advance(Duration.ofMinutes(14));
        f.get("/console/api/me", s);
        assertNotEquals(423, f.backgroundGet("/console/api/soc/risk/subject/ben", s).status(), "still open");
        f.clock.advance(Duration.ofMinutes(2));
        assertEquals(423, search(s).status(), "neither a background refresh nor use extends the fifteen minutes");
    }

    @Test
    void aRoleThatOpensNothingConfidentialHasNoPasskey() throws Exception {
        Sess uma = f.login("uma");
        assertTrue(f.get("/console/api/me", uma).body().contains("\"passkeyNeeded\":false"));
        assertEquals(403, setPasskey(uma).status());
        assertTrue(f.get("/console/api/modules", uma).body().contains("\"id\":\"home\""), "a page of their own");
        Sess ana = f.login("ana");
        assertTrue(f.get("/console/api/me", ana).body().contains("\"passkeyNeeded\":true"));
        assertFalse(f.get("/console/api/modules", ana).body().contains("\"id\":\"home\""));
    }

    @Test
    void aPersonSeesOnlyTheirOwnAccountActivity() throws Exception {
        Sess uma = f.login("uma");
        Sess ana = f.login("ana");
        assertEquals(200, changePassword(uma).status());
        assertEquals(401, f.post("/console/api/profile/pin", ana, "{\"password\":\"not-the-password\",\"pin\":\"000000\",\"newPin\":\"" + NEW_PIN + "\"}").status());
        String mine = f.get("/console/api/me/activity", uma).body();
        assertTrue(mine.contains("CONSOLE_LOGIN") && mine.contains("profile/password"), mine);
        String other = f.get("/console/api/me/activity", ana).body();
        assertTrue(other.contains("CONSOLE_LOGIN"), other);
        assertFalse(other.contains("profile/"), "neither another person's change nor a refused one of one's own is listed");
    }

    @Test
    void aPasskeyWindowClosesByItself() throws Exception {
        Sess s = f.login("ben");
        assertEquals(200, setPasskey(s).status());
        assertEquals(200, unlock(s).status());
        f.clock.advance(Duration.ofMinutes(14));
        f.get("/console/api/me", s);
        f.clock.advance(Duration.ofMinutes(2));
        assertEquals(423, search(s).status());
    }

    @Test
    void repeatedWrongPasskeysAreSlowedDown() throws Exception {
        Sess s = f.login("cleo");
        assertEquals(200, setPasskey(s).status());
        int last = 0;
        for (int i = 0; i < 6; i++) {
            last = f.post("/console/api/session/unlock", s, "{\"passkey\":\"wrong-guess-" + i + "\"}").status();
        }
        assertEquals(429, last);
        assertEquals(429, f.post("/console/api/session/unlock", s, "{\"passkey\":\"" + PASSKEY + "\"}").status(), "even the right one must wait");
    }

    @Test
    void afterAWeekNothingOpensUntilPasswordAndPinChange() throws Exception {
        f.clock.advance(ConsoleAuth.WEEKLY);
        Sess s = f.login("ana");
        assertTrue(f.get("/console/api/me", s).body().contains("\"changeDue\":true"));
        assertEquals(428, f.get("/console/api/soc/queue", s).status());
        assertEquals(200, f.get("/console/api/profile", s).status());
        assertEquals(200, changePassword(s).status());
        assertEquals(428, f.get("/console/api/soc/queue", s).status(), "the PIN has run out too");
        assertEquals(200, f.post("/console/api/profile/pin", s, "{\"password\":\"" + NEW_PASSWORD + "\",\"pin\":\"" + f.person("ana").pin()
                + "\",\"newPin\":\"" + NEW_PIN + "\"}").status());
        assertEquals(200, f.get("/console/api/soc/queue", s).status());
    }

    @Test
    void aBackupCodeSetsNewSecretsEndsSessionsAndWorksOnce() throws Exception {
        Sess s = f.login("ben");
        List<String> codes = codes(s);
        assertEquals(ConsoleAuth.BACKUP_CODES, codes.size());
        assertEquals(ConsoleAuth.BACKUP_CODES, Set.copyOf(codes).size());

        assertEquals(401, recoverCode("ben", "AAAAA-BBBBB-CCCCC").status());
        Resp checked = recoverCode("ben", codes.get(3));
        assertEquals(200, checked.status());
        String ticket = checked.field("ticket");
        assertEquals(200, f.login("ben", f.person("ben").password(), f.person("ben").pin()).status(), "a right code changes nothing yet");
        assertEquals(400, recover(ticket, "short", NEW_PIN).status());
        assertEquals(200, recover(ticket, NEW_PASSWORD, NEW_PIN).status(), "a weak choice can be tried again");
        assertEquals(401, f.get("/console/api/me", s).status(), "whoever held the old password is out");
        assertEquals(401, f.login("ben", f.person("ben").password(), f.person("ben").pin()).status());
        Resp in = f.login("ben", NEW_PASSWORD, NEW_PIN);
        assertEquals(200, in.status());
        assertEquals(401, recover(ticket, NEW_PASSWORD + "x", NEW_PIN).status(), "a ticket works once");
        assertEquals(401, recoverCode("ben", codes.get(3)).status(), "a code works once");
        assertTrue(f.get("/console/api/profile", new Sess(ConsoleFixture.cookieValue(in), in.field("csrf"), "ben")).body()
                .contains("\"backupCodesLeft\":9"));
    }

    @Test
    void aBackupCodeFromOneAccountOpensNoOther() throws Exception {
        Sess s = f.login("ana");
        String code = codes(s).get(0);
        assertEquals(401, recoverCode("ben", code).status());
        assertEquals(200, f.login("ben", f.person("ben").password(), f.person("ben").pin()).status());
    }

    @Test
    void anOldRecoveryTicketDoesNothingAndKeepsTheCode() throws Exception {
        String code = codes(f.login("ana")).get(0);
        String ticket = recoverCode("ana", code).field("ticket");
        f.clock.advance(ConsoleAuth.RECOVERY_VALID.plusSeconds(1));
        assertEquals(401, recover(ticket, NEW_PASSWORD, NEW_PIN).status());
        assertEquals(200, f.login("ana", f.person("ana").password(), f.person("ana").pin()).status());
        assertEquals(200, recoverCode("ana", code).status(), "the code was not used up");
    }

    @Test
    void newCodesCancelARecoveryAlreadyUnderWay() throws Exception {
        Sess s = f.login("ana");
        String ticket = recoverCode("ana", codes(s).get(0)).field("ticket");
        codes(s);
        assertEquals(401, recover(ticket, NEW_PASSWORD, NEW_PIN).status());
        assertEquals(401, recover("rc-not-a-ticket", NEW_PASSWORD, NEW_PIN).status());
    }

    @Test
    void severalPageReloadsAMinuteAreNotRefused() throws Exception {
        for (int i = 0; i < 300; i++) {
            assertNotEquals(429, f.get("/console/style.css", null).status(), "request " + i);
        }
    }

    @Test
    void secretsSurviveARestartAndAreNeverKeptInTheClear(@TempDir Path dir) throws Exception {
        Path console = dir.resolve("console");
        Files.createDirectories(console);
        ConsoleAuth.Person person = new ConsoleAuth.Person("ana", "Ana", Set.of(Role.ANALYST));
        ConsoleAuth.Enrolment e = new ConsoleAuth.Enrolment(person, "first-password-1", "first-pin-1");
        Files.writeString(console.resolve("people.txt"), "ana|Ana|ANALYST|first-password-1|first-pin-1\n");
        Path store = console.resolve("credentials.txt");
        String source = "127.0.0.1";

        ConsoleAuth one = new ConsoleAuth(List.of(e), f.clock, 10_000, 1_000, store, ConsoleAuth.WEEKLY);
        assertEquals(Change.OK, one.changePassword("ana", "first-password-1", "first-pin-1", NEW_PASSWORD, source).status());
        assertEquals(Change.OK, one.changePin("ana", NEW_PASSWORD, "first-pin-1", NEW_PIN, source).status());
        assertEquals(Change.OK, one.setPasskey("ana", NEW_PASSWORD, NEW_PIN, PASSKEY, source).status());
        ConsoleAuth.Changed[] result = new ConsoleAuth.Changed[1];
        Optional<List<String>> codes = one.newBackupCodes("ana", NEW_PASSWORD, NEW_PIN, source, result);
        assertTrue(codes.isPresent());

        String kept = Files.readString(store);
        for (String secret : List.of(NEW_PASSWORD, NEW_PIN, PASSKEY, codes.get().getFirst())) {
            assertFalse(kept.contains(secret), "the file holds hashes only");
        }
        String people = Files.readString(console.resolve("people.txt"));
        assertFalse(people.contains("first-password-1") || people.contains("first-pin-1"), "the printed first secrets are gone");

        ConsoleAuth two = new ConsoleAuth(List.of(e), f.clock, 10_000, 1_000, store, ConsoleAuth.WEEKLY);
        assertEquals(ConsoleAuth.Status.OK, two.stepUp("ana", NEW_PASSWORD, NEW_PIN, source).status());
        assertNotEquals(ConsoleAuth.Status.OK, two.stepUp("ana", "first-password-1", "first-pin-1", source).status());
        assertEquals(ConsoleAuth.Status.OK, two.unlock("ana", PASSKEY, source).status());
        assertEquals(ConsoleAuth.BACKUP_CODES, two.standing("ana").backupCodesLeft());
        assertTrue(two.hasOwnSecrets("ana"));
    }
}

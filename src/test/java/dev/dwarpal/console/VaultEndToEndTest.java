package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import dev.dwarpal.console.vault.Vault;
import dev.dwarpal.console.vault.VaultModule;
import dev.dwarpal.lab.LabAudit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The vault over the console's real routes: invisible to everybody but the administrators, behind an elevation and a fresh
 * password and PIN, every action on the audit trail without its secret, the other administrator and the leads told, and the
 * emergency password working exactly once, in the recovery, for the right person, including an administrator who is locked out.
 */
class VaultEndToEndTest {

    private static final String PASSKEY = "correct-horse-battery";
    private static final String NEW_PASSWORD = "Brand-new-Password-77";
    private static final String NEW_PIN = "4829175";

    @TempDir
    Path dir;

    private ConsoleFixture f;
    private ConsoleTrail trail;
    private Vault vault;

    @BeforeEach
    void start() throws Exception {
        trail = ConsoleTrail.open(dir.resolve("trail"), Clock.systemUTC());
        vault = Vault.open(dir.resolve("vault"), dir.resolve("key"), Clock.systemUTC());
        List<VaultModule.Person> everyone = new ArrayList<>();
        DemoPeople.fresh().forEach(e -> everyone.add(new VaultModule.Person(e.person().id(), e.person().display(), "Somewhere")));
        vault.ensure(everyone.stream().map(VaultModule.Person::id).toList());
        f = ConsoleFixture.startWithAuth((b, auth) -> {
            auth.emergency(vault);
            b.trail(trail).noticesFile(dir.resolve("notices.txt"));
            b.module(new MonitorModule(() -> Set.of("dana", "spector")));
            b.module(new VaultModule(vault, () -> everyone, () -> Set.of("dana", "spector"), () -> Set.of("cleo")));
        }, ConsoleSettings.defaults().fastHashing());
    }

    @AfterEach
    void stop() throws Exception {
        f.close();
        trail.close();
    }

    // ---- helpers ------------------------------------------------------------------------------------------------------------

    private Sess admin(String id) throws Exception {
        Sess s = f.login(id);
        ConsoleAuth.Enrolment e = f.person(id);
        assertEquals(200, f.post("/console/api/profile/passkey", s, "{\"password\":\"" + e.password() + "\",\"pin\":\"" + e.pin()
                + "\",\"passkey\":\"" + PASSKEY + "\"}").status());
        return s;
    }

    private Sess elevated(String id) throws Exception {
        Sess s = admin(id);
        Resp r = f.post("/console/api/session/elevate", s, "{\"pin\":\"" + f.person(id).pin() + "\",\"passkey\":\"" + PASSKEY
                + "\",\"reason\":\"working in the vault\"}");
        assertEquals(200, r.status(), r.body());
        return s;
    }

    private Resp vaultPost(Sess s, String path, String reason) throws Exception {
        return f.post("/console/api/vault/" + path, s, "{\"reason\":\"" + reason + "\"}");
    }

    private String password(Resp r) {
        return r.field("password");
    }

    private String notices(String person) {
        return f.server.notices.of(person, 50).stream().map(NoticeBoard.Notice::text).reduce("", (a, b) -> a + " | " + b);
    }

    /** Every payload in the saved trail, as one text. */
    private String trailText() {
        LabAudit view = trail.view();
        StringBuilder sb = new StringBuilder();
        for (LabAudit.Entry e : view.page(0, 200, Optional.empty()).entries()) {
            sb.append(e.type()).append(' ').append(view.record(e.sequence()).map(LabAudit.Detail::payloadJson).orElse("")).append('\n');
        }
        return sb.toString();
    }

    // ---- hidden ---------------------------------------------------------------------------------------------------------------

    @Test
    void everybodyButAnAdministratorGetsAPlainNotFoundAndNeverSeesItInAList() throws Exception {
        String missing = f.get("/console/api/vault-is-not-here/people", f.login("ana")).body();
        for (String who : new String[]{"ana", "cleo", "uma", "hana"}) {
            Sess s = f.login(who);
            Resp get = f.get("/console/api/vault/people", s);
            assertEquals(404, get.status(), who + " " + get.body());
            assertEquals(missing, get.body(), "the same words as for a route that does not exist");
            assertEquals(404, vaultPost(s, "people/ana/reveal", "looking around").status(), who);
            assertEquals(404, f.get("/console/api/vault/own", s).status(), who);
            assertFalse(f.get("/console/api/modules", s).body().contains("vault"), who + " must not see it in the list");
        }
        assertTrue(f.get("/console/api/modules", f.login("dana")).body().contains("\"id\":\"vault\""), "an administrator does");
    }

    // ---- behind an elevation, with a reason ------------------------------------------------------------------------------------

    @Test
    void theListNeedsAnElevationAndShowsNoPasswordAndEveryActionNeedsAReason() throws Exception {
        Sess dana = admin("dana");
        Resp closed = f.get("/console/api/vault/people", dana);
        assertEquals(423, closed.status());
        assertTrue(closed.body().contains("elevation required"));
        assertEquals(423, vaultPost(dana, "people/ana/reveal", "needed it for a check").status());

        Sess open = elevated("spector");
        Resp list = f.get("/console/api/vault/people", open);
        assertEquals(200, list.status(), list.body());
        assertTrue(list.body().contains("\"id\":\"ana\"") && list.body().contains("\"state\":\"OFF\""), list.body());
        assertFalse(list.body().contains("\"password\""), "the list says where each stands and never a password");

        assertEquals(400, vaultPost(open, "people/ana/reveal", "no").status(), "a reason of 5 characters or more");
        assertEquals(400, f.post("/console/api/vault/people/ana/reveal", open, "{}").status());
        assertEquals(403, vaultPost(open, "people/spector/reveal", "my own one").status(), "the other administrator does that for you");
        assertEquals(404, vaultPost(open, "people/nobody/reveal", "who is this").status());
    }

    // ---- reveal: recorded, announced, no secret in either ----------------------------------------------------------------------

    @Test
    void aRevealIsOnTheTrailWithoutTheSecretAndTheOtherAdministratorAndTheLeadAreTold() throws Exception {
        Sess dana = elevated("dana");
        Resp r = vaultPost(dana, "people/ana/reveal", "ana is locked out of the lab");
        assertEquals(200, r.status(), r.body());
        String secret = password(r);
        assertTrue(secret.matches("[A-Z2-9]{4}(-[A-Z2-9]{4}){3}"), "a readable one-off password: " + secret);
        assertEquals("OFF", r.field("state"));

        String t = trailText();
        assertTrue(t.contains("VAULT_REVEAL") && t.contains("reveal emergency password") && t.contains("\"target\":\"ana\"")
                && t.contains("ana is locked out of the lab") && t.contains("\"elevation\":\"elv-"), t);
        assertFalse(t.contains(secret), "the secret is in no record");
        assertFalse(f.server.notices.of("spector", 50).isEmpty());
        assertTrue(notices("spector").contains("dana viewed the emergency password of ana"), notices("spector"));
        assertTrue(notices("cleo").contains("dana viewed the emergency password of ana"));
        assertEquals("", notices("dana"), "the one who acted is not told about their own action");
        assertEquals("", notices("ana"), "a reveal does not tell the person");
        assertFalse((notices("spector") + notices("cleo")).contains(secret), "no notice carries the secret");
    }

    @Test
    void theLeadSeesWhoWhenAndOnWhomAndNeverTheSecretOrTheReasonAndAnAnalystSeesNothing() throws Exception {
        Sess dana = elevated("dana");
        String secret = password(vaultPost(dana, "people/uma/reveal", "uma forgot everything"));
        Resp cleo = f.get("/console/api/monitor/vault", f.login("cleo"));
        assertEquals(200, cleo.status());
        assertTrue(cleo.body().contains("\"who\":\"dana\"") && cleo.body().contains("\"target\":\"uma\"")
                && cleo.body().contains("reveal emergency password"), cleo.body());
        assertFalse(cleo.body().contains(secret) || cleo.body().contains("uma forgot everything"), cleo.body());
        Resp ana = f.get("/console/api/audit/records?source=console&limit=200", f.login("ana"));
        assertFalse(ana.body().contains("VAULT_"), "an analyst does not even see that vault records exist");
        Resp other = f.get("/console/api/monitor/admins", f.login("spector"));
        assertTrue(other.body().contains("VAULT_REVEAL") && other.body().contains("action: reveal emergency password; target: uma"), other.body());
        assertFalse(other.body().contains(secret) || other.body().contains("uma forgot everything"));
    }

    // ---- activation and the recovery ---------------------------------------------------------------------------------------------

    private Resp recoverCode(String user, String code) throws Exception {
        return f.post("/console/api/session/recover/code", null, "{\"user\":\"" + user + "\",\"code\":\"" + code + "\"}");
    }

    private Resp recover(String ticket) throws Exception {
        return f.post("/console/api/session/recover", null, "{\"ticket\":\"" + ticket + "\",\"newPassword\":\"" + NEW_PASSWORD + "\",\"newPin\":\""
                + NEW_PIN + "\"}");
    }

    @Test
    void anEmergencyPasswordDoesNothingUntilSwitchedOnThenWorksOnceInTheRecoveryAndIsReplaced() throws Exception {
        Sess dana = elevated("dana");
        String secret = password(vaultPost(dana, "people/ana/reveal", "ana lost her password and PIN"));
        assertEquals(401, recoverCode("ana", secret).status(), "switched off: it opens nothing");

        Sess anaBefore = f.login("ana");
        Resp on = vaultPost(dana, "people/ana/activate", "ana lost her password and PIN");
        assertEquals(200, on.status(), on.body());
        assertEquals(secret, password(on));
        assertEquals("ACTIVE", on.field("state"));
        assertTrue(notices("ana").contains("dana switched on an emergency password for your account"), notices("ana"));
        assertTrue(notices("spector").contains("dana switched on an emergency password for ana"));
        assertTrue(notices("cleo").contains("dana switched on an emergency password for ana"));

        assertEquals(401, recoverCode("ana", secret + "X").status(), "only the right one");
        assertEquals(401, recoverCode("ben", secret).status(), "and only for the person it belongs to");
        Resp ticket = recoverCode("ana", secret);
        assertEquals(200, ticket.status(), ticket.body());
        Resp weak = f.post("/console/api/session/recover", null, "{\"ticket\":\"" + ticket.field("ticket") + "\",\"newPassword\":\"short\",\"newPin\":\"1\"}");
        assertEquals(400, weak.status(), "new secrets must be strong; nothing is used up yet");
        assertEquals(200, recover(ticket.field("ticket")).status());

        assertEquals(401, f.get("/console/api/me", anaBefore).status(), "her open session ended");
        assertEquals(200, f.login("ana", NEW_PASSWORD, NEW_PIN).status(), "she signs in with what she just chose");
        assertNotEquals(200, f.login("ana", f.person("ana").password(), f.person("ana").pin()).status(), "the old password is gone");
        assertEquals(401, recoverCode("ana", secret).status(), "single use");

        Vault.Credential now = vault.credential("ana");
        assertEquals(Vault.State.OFF, now.state(), "switched off again");
        assertNotEquals(secret, now.password(), "and replaced by a new one");
        assertTrue(notices("ana").contains("Your emergency password was used"));
        assertTrue(notices("spector").contains("ana used an emergency password"));
        assertTrue(notices("cleo").contains("ana used an emergency password"));
        String t = trailText();
        assertTrue(t.contains("VAULT_ACTIVATE") && t.contains("VAULT_USED") && t.contains("emergency password used"), t);
        assertFalse(t.contains(secret) || t.contains(NEW_PASSWORD) || t.contains(NEW_PIN), "no secret in any record");
    }

    @Test
    void switchingItOffStopsItAndAnAdministratorMayChooseTheirOwnWhichStaysReadableUntilUsed() throws Exception {
        Sess dana = elevated("dana");
        String first = password(vaultPost(dana, "people/ben/activate", "ben is away and locked out"));
        assertEquals(200, vaultPost(dana, "people/ben/off", "ben found his password").status());
        assertEquals(401, recoverCode("ben", first).status(), "switched off again");

        Resp weak = f.post("/console/api/vault/people/ben/set", dana, "{\"reason\":\"choosing one\",\"password\":\"short\"}");
        assertEquals(400, weak.status());
        Resp chosen = f.post("/console/api/vault/people/ben/set", dana, "{\"reason\":\"choosing one for ben\",\"password\":\"my-own-choice-99\"}");
        assertEquals(200, chosen.status(), chosen.body());
        assertEquals("my-own-choice-99", password(chosen));
        Resp shown = vaultPost(dana, "people/ben/reveal", "checking what I set");
        assertEquals("my-own-choice-99", password(shown));
        assertTrue(f.get("/console/api/vault/people", dana).body().contains("\"typed\":true"));
        assertEquals(401, recoverCode("ben", "my-own-choice-99").status(), "chosen, but still switched off");

        assertEquals(200, vaultPost(dana, "people/ben/activate", "ben is away and locked out").status());
        Resp ticket = recoverCode("ben", "my-own-choice-99");
        assertEquals(200, ticket.status(), ticket.body());
        assertEquals(200, recover(ticket.field("ticket")).status());
        assertFalse(vault.credential("ben").typed(), "after use it is a new random one again");
        assertFalse(trailText().contains("my-own-choice-99"));
    }

    @Test
    void aLockedOutAdministratorGetsBackInThroughTheOtherOneAndTheLeadIsTold() throws Exception {
        Sess dana = elevated("dana");
        assertEquals(403, vaultPost(dana, "people/dana/activate", "letting myself in").status(), "nobody switches on their own");
        Resp on = vaultPost(dana, "people/spector/activate", "spector is locked out of his account");
        assertEquals(200, on.status(), on.body());
        Resp ticket = recoverCode("spector", password(on));
        assertEquals(200, ticket.status(), ticket.body());
        assertEquals(200, recover(ticket.field("ticket")).status());
        assertEquals(200, f.login("spector", NEW_PASSWORD, NEW_PIN).status());
        assertTrue(notices("cleo").contains("dana switched on an emergency password for spector"), notices("cleo"));
        assertTrue(notices("cleo").contains("spector used an emergency password"));
        assertTrue(notices("dana").contains("spector used an emergency password"), "the other administrator is told it was used");
        assertFalse(trailText().contains(password(on)));
    }

    // ---- the administrator's own entry ---------------------------------------------------------------------------------------------

    @Test
    void anAdministratorKeepsTheirOwnPasswordAndPinAndOnlyTheyCanReadThem() throws Exception {
        Sess dana = elevated("dana");
        assertEquals(404, vaultPost(dana, "own/reveal", "reading my own entry").status(), "nothing kept yet");
        Resp saved = f.post("/console/api/vault/own/save", dana, "{\"reason\":\"keeping my own\",\"password\":\"my-real-password\",\"pin\":\"246810\"}");
        assertEquals(200, saved.status(), saved.body());
        Resp shown = vaultPost(dana, "own/reveal", "reading my own entry");
        assertEquals("my-real-password", shown.field("password"));
        assertEquals("246810", shown.field("pin"));
        Sess spector = elevated("spector");
        assertEquals(404, vaultPost(spector, "own/reveal", "reading dana's").status(), "his own entry is his own, and he has none");
        assertTrue(notices("spector").contains("dana changed their own entry") && notices("spector").contains("dana viewed their own entry"));
        String t = trailText();
        assertFalse(t.contains("my-real-password") || t.contains("246810"), t);
    }

    // ---- what is on disk -------------------------------------------------------------------------------------------------------------

    @Test
    void theVaultFileHoldsNoReadableSecretAndTheNoticesNoSecretEither() throws Exception {
        Sess dana = elevated("dana");
        String secret = password(vaultPost(dana, "people/ana/activate", "ana is locked out"));
        byte[] bytes = java.nio.file.Files.readAllBytes(dir.resolve("vault").resolve("vault.dat"));
        String raw = new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
        assertFalse(raw.contains(secret) || raw.contains("ana") || raw.contains("password"), "sealed, not just encoded");
        assertFalse(java.nio.file.Files.readString(dir.resolve("notices.txt")).contains(secret));
        assertTrue(java.nio.file.Files.isRegularFile(dir.resolve("key").resolve("vault.key")), "the key is in a folder of its own");
    }
}

package dev.dwarpal.console.vault;

import dev.dwarpal.console.ConsoleModule;
import dev.dwarpal.console.ConsoleModule.Principal;
import dev.dwarpal.console.ConsoleModule.Response;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.console.lab.FakeRoutes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The vault's own rules: what the file holds, how it fails, how it follows the people, and what the module does when the audit trail cannot take a record. */
class VaultTest {

    @TempDir
    Path dir;

    private Vault vault;

    @BeforeEach
    void open() throws Exception {
        vault = Vault.open(dir.resolve("data"), dir.resolve("key"), Clock.systemUTC());
    }

    @Test
    void aNewPersonGetsASwitchedOffEmergencyPasswordAndALeaverLosesIt() {
        assertTrue(vault.all().isEmpty());
        vault.personCreated("priya");
        Vault.Credential c = vault.credential("priya");
        assertEquals(Vault.State.OFF, c.state());
        assertFalse(c.typed());
        assertEquals("", c.activatedBy());
        String before = c.password();
        vault.personCreated("priya");
        assertEquals(before, vault.credential("priya").password(), "making it twice changes nothing");
        vault.saveOwn("priya", "a-password", "1234");
        vault.personRemoved("priya");
        assertTrue(vault.all().isEmpty(), "a leaver's emergency password is deleted");
        assertTrue(vault.own("priya").isEmpty());
        assertFalse(vault.accepts("priya", before));
    }

    @Test
    void itIsAcceptedOnlyWhileSwitchedOnAndOnlyExactlyAndUsingItReplacesIt() {
        vault.personCreated("ana");
        String secret = vault.credential("ana").password();
        assertFalse(vault.accepts("ana", secret), "off");
        vault.activate("ana", "dana");
        assertTrue(vault.accepts("ana", secret));
        assertTrue(vault.accepts("ana", " " + secret + " "), "spaces around it are not held against the person");
        assertFalse(vault.accepts("ana", secret.toLowerCase()));
        assertFalse(vault.accepts("ana", null));
        assertFalse(vault.accepts("ben", secret));
        assertEquals("dana", vault.credential("ana").activatedBy());
        List<String> told = new ArrayList<>();
        vault.onUsed(told::add);
        vault.used("ana");
        assertEquals(List.of("ana"), told);
        assertEquals(Vault.State.OFF, vault.credential("ana").state());
        assertNotEquals(secret, vault.credential("ana").password());
        assertFalse(vault.accepts("ana", secret));
    }

    @Test
    void aChosenPasswordIsKeptAsTypedWithinLimits() {
        vault.personCreated("ana");
        assertThrows(IllegalArgumentException.class, () -> vault.setTyped("ana", "short"));
        assertThrows(IllegalArgumentException.class, () -> vault.setTyped("ana", "x".repeat(65)));
        assertThrows(IllegalArgumentException.class, () -> vault.setTyped("ana", " leading-space-here"));
        assertThrows(IllegalArgumentException.class, () -> vault.setTyped("ana", "has\ttab-inside-it"));
        Vault.Credential c = vault.setTyped("ana", "Chosen By Dana 42!");
        assertTrue(c.typed());
        assertEquals("Chosen By Dana 42!", vault.credential("ana").password());
    }

    @Test
    void whatIsSavedComesBackAfterARestartAndTheFileIsSealed() throws Exception {
        vault.personCreated("ana");
        vault.activate("ana", "dana");
        vault.saveOwn("dana", "dana-secret-password", "135790");
        String secret = vault.credential("ana").password();
        Vault again = Vault.open(dir.resolve("data"), dir.resolve("key"), Clock.systemUTC());
        assertEquals(secret, again.credential("ana").password());
        assertEquals(Vault.State.ACTIVE, again.credential("ana").state());
        assertEquals("135790", again.own("dana").orElseThrow().pin());
        String raw = new String(Files.readAllBytes(dir.resolve("data").resolve("vault.dat")), java.nio.charset.StandardCharsets.ISO_8859_1);
        assertFalse(raw.contains(secret) || raw.contains("dana-secret-password") || raw.contains("135790"));
    }

    @Test
    void aChangedByteAWrongKeyOrAMissingKeyStopsTheVault() throws Exception {
        vault.personCreated("ana");
        Path data = dir.resolve("data").resolve("vault.dat");
        byte[] good = Files.readAllBytes(data);
        byte[] bad = good.clone();
        bad[bad.length / 2] ^= 0x01;
        Files.write(data, bad);
        assertThrows(IOException.class, () -> Vault.open(dir.resolve("data"), dir.resolve("key"), Clock.systemUTC()));
        Files.write(data, good);
        assertEquals(1, Vault.open(dir.resolve("data"), dir.resolve("key"), Clock.systemUTC()).all().size());
        Files.write(dir.resolve("key").resolve("vault.key"), new byte[32]);
        assertThrows(IOException.class, () -> Vault.open(dir.resolve("data"), dir.resolve("key"), Clock.systemUTC()), "the wrong key");
        Files.delete(dir.resolve("key").resolve("vault.key"));
        IOException e = assertThrows(IOException.class, () -> Vault.open(dir.resolve("data"), dir.resolve("key"), Clock.systemUTC()));
        assertTrue(e.getMessage().contains("key file is missing"), "a vault with data and no key is never remade: " + e.getMessage());
    }

    // ---- the module when the trail cannot take a record --------------------------------------------------------------------------

    private static final Principal DANA = new Principal("dana", Set.of(Role.ADMIN), true,
            new ConsoleModule.Elevation("el-1", "testing", Instant.now().plusSeconds(600)));

    @Test
    void ifTheAuditTrailCannotTakeTheRecordNothingIsShownOrChanged() {
        vault.personCreated("ana");
        String secret = vault.credential("ana").password();
        AtomicReference<Boolean> accept = new AtomicReference<>(false);
        List<String> notices = new ArrayList<>();
        VaultModule module = new VaultModule(vault, () -> List.of(new VaultModule.Person("ana", "Ana", "SOC")), () -> Set.of("dana", "spector"),
                () -> Set.of("cleo"));
        module.attach(new ConsoleModule.Host() {
            @Override
            public boolean audit(String type, String person, Map<String, String> fields) {
                return accept.get();
            }

            @Override
            public void closeAccount(String personId) {
            }

            @Override
            public boolean notify(String personId, String text) {
                notices.add(personId);
                return true;
            }
        });
        FakeRoutes routes = FakeRoutes.of(module);
        Response refused = routes.call("POST", "people/ana/activate", DANA, "{\"reason\":\"locked out of everything\"}");
        assertEquals(503, refused.status(), refused.body());
        assertEquals(Vault.State.OFF, vault.credential("ana").state(), "not switched on");
        assertFalse(refused.body().contains(secret));
        assertEquals(503, routes.call("POST", "people/ana/reveal", DANA, "{\"reason\":\"locked out of everything\"}").status());
        assertTrue(notices.isEmpty(), "nobody is told about something that did not happen");
        accept.set(true);
        assertEquals(200, routes.call("POST", "people/ana/activate", DANA, "{\"reason\":\"locked out of everything\"}").status());
        assertEquals(Vault.State.ACTIVE, vault.credential("ana").state());
        assertEquals(Set.of("ana", "spector", "cleo"), Set.copyOf(notices), "the person, the other administrator and the lead, not the one who acted");
    }

    @Test
    void aCallWithoutAnElevationOrFromAnotherRoleIsRefusedBeforeAnythingHappens() {
        VaultModule module = new VaultModule(vault, () -> List.of(), () -> Set.of(), () -> Set.of());
        module.attach(new ConsoleModule.Host() {
            @Override
            public boolean audit(String type, String person, Map<String, String> fields) {
                throw new AssertionError("nothing may be recorded for a refused call");
            }

            @Override
            public void closeAccount(String personId) {
            }
        });
        FakeRoutes routes = FakeRoutes.of(module);
        Principal notElevated = new Principal("dana", Set.of(Role.ADMIN), true);
        assertEquals(423, routes.call("GET", "people", notElevated, "").status());
        int other = routes.call("GET", "people", FakeRoutes.LEAD, "").status();
        assertTrue(other == 403 || other == 404, "refused before the vault does anything (the host answers 404): " + other);
        assertTrue(module.hidden());
        assertEquals(Role.ADMIN, module.minimum());
        for (FakeRoutes.Route r : routes.all()) {
            assertEquals(Role.ADMIN, r.minimum(), r.pattern());
            if (r.method().equals("POST")) {
                assertTrue(r.stepUp(), r.pattern() + " needs a fresh password and PIN");
            }
        }
    }
}

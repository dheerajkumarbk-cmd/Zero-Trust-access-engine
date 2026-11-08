package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleAuth.Enrolment;
import dev.dwarpal.console.ConsoleAuth.Person;
import dev.dwarpal.console.ConsoleModule.Role;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DemoPeopleTest {

    @Test
    void theLabKeepsItsPeopleAndSecretsBetweenStarts(@TempDir Path dir) throws Exception {
        List<Enrolment> first = DemoPeople.loadOrCreate(dir);
        List<Enrolment> second = DemoPeople.loadOrCreate(dir);
        assertEquals(6, first.size());
        assertEquals(first.stream().map(e -> e.person().id() + e.password() + e.pin()).toList(),
                second.stream().map(e -> e.person().id() + e.password() + e.pin()).toList());
        assertTrue(Files.isRegularFile(dir.resolve("console").resolve("people.txt")));
    }

    @Test
    void secretsAreRandomPerLabAndLongEnough(@TempDir Path a, @TempDir Path b) throws Exception {
        Enrolment x = DemoPeople.loadOrCreate(a).getFirst();
        Enrolment y = DemoPeople.loadOrCreate(b).getFirst();
        assertNotEquals(x.password(), y.password());
        assertEquals(16, x.password().length());
        assertEquals(8, x.pin().length());
    }

    @Test
    void rolesAreAnalystLeadAdminUserAndHr() {
        List<Enrolment> all = DemoPeople.fresh();
        assertEquals(Set.of(Role.LEAD, Role.ANALYST), all.stream().filter(e -> e.person().id().equals("cleo")).findFirst().orElseThrow().person().roles());
        assertEquals(Set.of(Role.ADMIN), all.stream().filter(e -> e.person().id().equals("dana")).findFirst().orElseThrow().person().roles());
        assertEquals(Set.of(Role.USER), all.stream().filter(e -> e.person().id().equals("uma")).findFirst().orElseThrow().person().roles());
        assertEquals(Set.of(Role.HR), all.stream().filter(e -> e.person().id().equals("hana")).findFirst().orElseThrow().person().roles());
    }

    @Test
    void aDamagedPeopleFileStopsTheLabInsteadOfLettingSomeoneIn(@TempDir Path dir) throws Exception {
        Files.createDirectories(dir.resolve("console"));
        Files.writeString(dir.resolve("console").resolve("people.txt"), "ana|Ana|ANALYST|only-three-fields\n");
        assertThrows(IllegalArgumentException.class, () -> DemoPeople.loadOrCreate(dir));
    }

    @Test
    void enrolmentsRefuseWeakSecretsAndHideThemInText() {
        Person p = new Person("zed", "Zed", Set.of(Role.USER));
        assertThrows(IllegalArgumentException.class, () -> new Enrolment(p, "short", "123456"));
        assertThrows(IllegalArgumentException.class, () -> new Enrolment(p, "long-enough-password", "123"));
        Enrolment e = new Enrolment(p, "long-enough-password", "123456");
        assertFalse(e.toString().contains("long-enough-password") || e.toString().contains("123456"));
        assertThrows(IllegalArgumentException.class, () -> new ConsoleAuth(List.of(e, e), new ConsoleFixture.TestClock(), 10_000, 1_000));
    }

    @Test
    void aLabMadeBeforeHanaGetsHerLineAndEveryoneElseKeepsTheirSecrets(@TempDir Path dir) throws Exception {
        List<Enrolment> first = DemoPeople.loadOrCreate(dir);
        Path file = dir.resolve("console").resolve("people.txt");
        List<String> old = Files.readAllLines(file).stream().filter(l -> !l.startsWith("hana|")).toList();
        Files.write(file, old);
        List<Enrolment> second = DemoPeople.loadOrCreate(dir);
        assertEquals(6, second.size());
        for (Enrolment e : first) {
            if (!e.person().id().equals("hana")) {
                Enrolment same = second.stream().filter(x -> x.person().id().equals(e.person().id())).findFirst().orElseThrow();
                assertEquals(e.password(), same.password());
                assertEquals(e.pin(), same.pin());
            }
        }
        assertEquals(second.stream().map(e -> e.person().id()).toList(), DemoPeople.loadOrCreate(dir).stream()
                .map(e -> e.person().id()).toList());
    }
}

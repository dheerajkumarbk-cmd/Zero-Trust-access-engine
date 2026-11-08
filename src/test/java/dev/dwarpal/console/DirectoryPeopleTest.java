package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleAuth.Enrolment;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.directory.DirectoryPerson;
import dev.dwarpal.directory.MemoryDirectory;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** How the people file and the directory are joined at start-up: the directory is the authority. */
class DirectoryPeopleTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-08T10:00:00Z"), ZoneOffset.UTC);

    private static DirectoryPerson person(String id, String name, DirectoryPerson.Status status, String... roles) {
        return new DirectoryPerson(id, name, "SOC", "Analyst", status, DirectoryPerson.Source.SEED, CLOCK.instant(), Set.of(roles));
    }

    @Test
    void theFirstStartMovesEveryoneInWithTheirJobsAndEnrolsThemAll() {
        MemoryDirectory directory = new MemoryDirectory();
        List<Enrolment> file = DemoPeople.fresh();
        DirectoryPeople.Result r = DirectoryPeople.sync(directory, file, CLOCK);
        assertEquals(7, r.movedIn());
        assertEquals(0, r.skipped());
        assertEquals(file.stream().map(e -> e.person().id()).sorted().toList(), r.people().stream().map(e -> e.person().id()).sorted().toList());
        DirectoryPerson hana = directory.find("hana").orElseThrow();
        assertEquals(Set.of("HR"), hana.consoleRoles());
        assertEquals("Human Resources", hana.department());
        assertEquals(DirectoryPerson.Source.SEED, hana.source());
        assertEquals("Administrator", directory.find("dana").orElseThrow().businessRole());
    }

    @Test
    void aSecondStartMovesNobodyAgainAndKeepsEachPersonsSecrets() {
        MemoryDirectory directory = new MemoryDirectory();
        List<Enrolment> file = DemoPeople.fresh();
        DirectoryPeople.sync(directory, file, CLOCK);
        DirectoryPeople.Result again = DirectoryPeople.sync(directory, file, CLOCK);
        assertEquals(0, again.movedIn());
        Enrolment ana = again.people().stream().filter(e -> e.person().id().equals("ana")).findFirst().orElseThrow();
        Enrolment original = file.stream().filter(e -> e.person().id().equals("ana")).findFirst().orElseThrow();
        assertEquals(original.password(), ana.password());
        assertEquals(original.pin(), ana.pin());
    }

    @Test
    void whatTheDirectorySaysWinsOverWhatThePeopleFileSays() {
        MemoryDirectory directory = new MemoryDirectory();
        directory.addIfAbsent(person("ana", "Ana, promoted", DirectoryPerson.Status.ACTIVE, "LEAD", "ANALYST"));
        DirectoryPeople.Result r = DirectoryPeople.sync(directory, DemoPeople.fresh(), CLOCK);
        Enrolment ana = r.people().stream().filter(e -> e.person().id().equals("ana")).findFirst().orElseThrow();
        assertEquals("Ana, promoted", ana.person().display());
        assertEquals(Set.of(Role.LEAD, Role.ANALYST), ana.person().roles());
        assertEquals(6, r.movedIn(), "ana was already there");
    }

    @Test
    void aDisabledPersonIsNotEnrolled() {
        MemoryDirectory directory = new MemoryDirectory();
        directory.addIfAbsent(person("ben", "Ben, left", DirectoryPerson.Status.DISABLED, "ANALYST"));
        DirectoryPeople.Result r = DirectoryPeople.sync(directory, DemoPeople.fresh(), CLOCK);
        assertFalse(r.people().stream().anyMatch(e -> e.person().id().equals("ben")));
        assertEquals(6, r.people().size());
        assertEquals(1, r.skipped());
    }

    @Test
    void aPersonWithNoFirstSecretsIsLeftOutUntilTheyHaveSome() {
        MemoryDirectory directory = new MemoryDirectory();
        directory.addIfAbsent(person("newbie", "New Joiner", DirectoryPerson.Status.ACTIVE, "USER"));
        DirectoryPeople.Result r = DirectoryPeople.sync(directory, DemoPeople.fresh(), CLOCK);
        assertFalse(r.people().stream().anyMatch(e -> e.person().id().equals("newbie")));
        assertTrue(directory.find("newbie").isPresent());
        assertEquals(1, r.skipped());
    }

    @Test
    void theHrRoleIsItsOwnThingNotAnAnalystNorAnAdministrator() {
        Set<Role> hr = Set.of(Role.HR);
        assertTrue(ConsoleServer.satisfiesModule(hr, Role.USER));
        assertTrue(ConsoleServer.satisfiesModule(hr, Role.HR));
        assertFalse(ConsoleServer.satisfiesModule(hr, Role.ANALYST));
        assertFalse(ConsoleServer.satisfiesModule(hr, Role.LEAD));
        assertFalse(ConsoleServer.satisfiesModule(hr, Role.ADMIN));
        assertFalse(ConsoleServer.satisfies(hr, Role.ANALYST));
        assertFalse(ConsoleServer.satisfiesModule(Set.of(Role.ADMIN), Role.HR), "an administrator is not HR: separate duties");
        assertFalse(ConsoleServer.satisfiesModule(Set.of(Role.USER), Role.HR));
    }
}

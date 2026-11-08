package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleAuth.Enrolment;
import dev.dwarpal.console.ConsoleAuth.Person;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.directory.DirectoryPerson;
import dev.dwarpal.directory.MemoryDirectory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A person approved since the last start gets first secrets at the next one; a person with no role, or who left, gets none. */
class DirectoryPeopleJoinersTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-08T10:00:00Z"), ZoneOffset.UTC);

    private static DirectoryPerson person(String id, DirectoryPerson.Status status, DirectoryPerson.Source source, String... roles) {
        return new DirectoryPerson(id, "Name of " + id, "Engineering", "Software engineer", status, source, CLOCK.instant(),
                Set.of(roles));
    }

    @Test
    void anActiveJoinerWithAConsoleRoleIsGivenFirstSecretsOnceAndEnrolled() {
        MemoryDirectory directory = new MemoryDirectory();
        directory.addIfAbsent(person("priya", DirectoryPerson.Status.ACTIVE, DirectoryPerson.Source.HR, "USER"));
        List<String> issuedTo = new ArrayList<>();
        DirectoryPeople.Result r = DirectoryPeople.sync(directory, List.of(), CLOCK, p -> {
            issuedTo.add(p.id());
            return new Enrolment(p, "a-first-password-1", "first-pin-1");
        });
        assertEquals(List.of("priya"), issuedTo);
        assertEquals(1, r.issued());
        assertEquals(List.of("priya"), r.people().stream().map(e -> e.person().id()).toList());
        assertEquals(Set.of(Role.USER), r.people().getFirst().person().roles());
    }

    @Test
    void aPersonWithNoConsoleRoleOrWhoLeftOrWithoutAnIssuerIsNotEnrolled() {
        MemoryDirectory directory = new MemoryDirectory();
        directory.addIfAbsent(person("noroles", DirectoryPerson.Status.ACTIVE, DirectoryPerson.Source.HR));
        directory.addIfAbsent(person("gone", DirectoryPerson.Status.DISABLED, DirectoryPerson.Source.HR, "USER"));
        directory.addIfAbsent(person("waiting", DirectoryPerson.Status.ACTIVE, DirectoryPerson.Source.HR, "USER"));
        List<String> asked = new ArrayList<>();
        DirectoryPeople.Result r = DirectoryPeople.sync(directory, List.of(), CLOCK, p -> {
            asked.add(p.id());
            return null;
        });
        assertEquals(List.of("waiting"), asked, "only an active person with a role is even considered");
        assertEquals(0, r.people().size());
        assertEquals(3, r.skipped());
        assertEquals(0, DirectoryPeople.sync(directory, List.of(), CLOCK).people().size(), "the short form issues nothing");
    }

    @Test
    void aPersonWhoAlreadyHasSecretsKeepsThemAndIsNotIssuedNewOnes() {
        MemoryDirectory directory = new MemoryDirectory();
        directory.addIfAbsent(person("priya", DirectoryPerson.Status.ACTIVE, DirectoryPerson.Source.HR, "USER"));
        Enrolment mine = new Enrolment(new Person("priya", "Priya", Set.of(Role.USER)), "already-chosen-1", "chosen-pin-1");
        DirectoryPeople.Result r = DirectoryPeople.sync(directory, List.of(mine), CLOCK, p -> {
            throw new AssertionError("no new secrets for somebody who has them");
        });
        assertEquals(0, r.issued());
        assertEquals("already-chosen-1", r.people().getFirst().password());
    }

    @Test
    void firstSecretsAreWrittenToThePeopleFileAndReadBackAtTheNextStart(@TempDir Path lab) throws IOException {
        DemoPeople.loadOrCreate(lab);
        Enrolment e = DemoPeople.issue(lab, new Person("priya", "Priya Nair", Set.of(Role.USER)));
        assertTrue(e.password().length() >= 16 && e.pin().length() >= 8);
        String file = Files.readString(lab.resolve("console").resolve("people.txt"));
        assertTrue(file.lines().anyMatch(l -> l.startsWith("priya|Priya Nair|USER|")));
        List<Enrolment> again = DemoPeople.loadOrCreate(lab);
        assertEquals(8, again.size(), "the seven demo people and the joiner");
        Enrolment back = again.stream().filter(x -> x.person().id().equals("priya")).findFirst().orElseThrow();
        assertEquals(e.password(), back.password());
        assertEquals(e.pin(), back.pin());
        assertFalse(e.toString().contains(e.password()), "the secrets never show in a log line");
    }
}

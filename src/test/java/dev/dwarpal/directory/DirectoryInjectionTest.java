package dev.dwarpal.directory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static dev.dwarpal.directory.DirectoryPersonTest.AT;
import static dev.dwarpal.directory.DirectoryPersonTest.cp;
import static dev.dwarpal.directory.DirectoryPersonTest.person;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Hostile text sent into every input that reaches the database. Nothing may leak, nothing may change, and text that is
 * merely odd (a quote, a semicolon) is kept exactly as written, because it only ever travels as a query parameter.
 */
class DirectoryInjectionTest {

    private static final List<String> HOSTILE = List.of(
            "' OR 1=1 --",
            "' OR '1'='1",
            "\" OR \"\"=\"",
            "ana' --",
            "ana'; DROP TABLE directory_person; --",
            "'; DELETE FROM directory_person_role; --",
            "ana' UNION SELECT person_id, display_name, department, business_role, status, source, created_at"
                    + " FROM directory_person --",
            "1; SELECT pg_sleep(5)",
            "%", "_", "ana%", "$$; DROP SCHEMA public CASCADE; $$",
            "Robert'); DROP TABLE directory_person;--",
            "ana" + cp(10) + "ben", "x".repeat(5000), cp(0xFF41, 0xFF4E, 0xFF41));

    private PostgresDirectory directory;

    @BeforeEach
    void seed() {
        TestDatabase.require();
        TestDatabase.reset();
        directory = new PostgresDirectory(TestDatabase.app());
        directory.addIfAbsent(person("ana", "Ana", "ANALYST"));
        directory.addIfAbsent(person("dana", "Dana", "ADMIN"));
    }

    private void assertUntouched() {
        List<DirectoryPerson> all = directory.people();
        assertEquals(List.of("ana", "dana"), all.stream().map(DirectoryPerson::id).toList());
        assertEquals(Set.of("ANALYST"), all.get(0).consoleRoles());
        assertEquals(Set.of("ADMIN"), all.get(1).consoleRoles());
        assertEquals("Ana", all.get(0).displayName());
    }

    @Test
    void aLookupWithHostileTextFindsNobodyAndChangesNothing() {
        for (String s : HOSTILE) {
            assertTrue(directory.find(s).isEmpty(), "find: " + s.length());
        }
        assertUntouched();
    }

    @Test
    void theQueryItselfIsSafeEvenIfTheCheckInFrontOfItWereMissing() {
        for (String s : HOSTILE) {
            assertTrue(directory.findExact(s).isEmpty(), "findExact: " + s.length());
        }
        // a NUL byte cannot be sent to PostgreSQL text at all: the driver refuses it, and nothing is read or changed
        assertThrows(DirectoryException.class, () -> directory.findExact("ana" + cp(0)));
        assertUntouched();
    }

    @Test
    void hostileButLegalTextIsStoredAndReturnedExactlyAsWritten() {
        DirectoryPerson odd = new DirectoryPerson("odd", "Robert'); DROP TABLE directory_person;--", "' OR 1=1 --",
                "\"; DELETE FROM directory_person; --", DirectoryPerson.Status.ACTIVE, DirectoryPerson.Source.HR, AT, Set.of("USER"));
        assertTrue(directory.addIfAbsent(odd));
        assertEquals(odd, directory.find("odd").orElseThrow());
        assertEquals(3, directory.people().size(), "the table is still there and holds exactly the three rows");
    }

    @Test
    void textThatCouldForgeALineOrCarryInjectionInAnIdOrRoleNeverGetsNearTheDatabase() {
        for (String s : HOSTILE) {
            assertThrows(IllegalArgumentException.class, () -> person(s, "Name", "USER"), "id " + s.length());
            assertThrows(IllegalArgumentException.class, () -> person("ok", "Name", s), "role " + s.length());
        }
        assertThrows(IllegalArgumentException.class, () -> person("ok", "Name" + cp(0), "USER"));
        assertUntouched();
    }
}

package dev.dwarpal.directory;

import dev.dwarpal.console.ConsoleModule;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Every field of a person is checked before it can reach a query or a page. */
class DirectoryPersonTest {

    static final Instant AT = Instant.parse("2026-11-08T10:00:00Z");

    static DirectoryPerson person(String id, String name, String... roles) {
        return new DirectoryPerson(id, name, "SOC", "Security analyst", DirectoryPerson.Status.ACTIVE,
                DirectoryPerson.Source.SEED, AT, Set.of(roles));
    }

    /** Text from code points, so no invisible character is ever written into this source file. */
    static String cp(int... points) {
        return new String(points, 0, points.length);
    }

    @Test
    void theRolesTheDatabaseAllowsAreExactlyTheRolesTheConsoleKnows() {
        assertEquals(Arrays.stream(ConsoleModule.Role.values()).map(Enum::name).collect(Collectors.toSet()), DirectoryPerson.ROLES);
    }

    @Test
    void aWellFormedPersonIsAccepted() {
        DirectoryPerson p = person("ana", "Ana (analyst)", "ANALYST", "LEAD");
        assertEquals(Set.of("ANALYST", "LEAD"), p.consoleRoles());
        assertThrows(UnsupportedOperationException.class, () -> p.consoleRoles().add("ADMIN"));
    }

    @Test
    void anIdIsShortLowerCaseAndPlain() {
        for (String bad : List.of("A", "a", "Ana", "ana ", " ana", "ana'--", "ana;drop", "../x", "a..b", "x".repeat(33), "9ana",
                "ana" + cp(0), "ana" + cp(10), cp(0x430) + "na")) {
            assertThrows(IllegalArgumentException.class, () -> person(bad, "Name", "USER"), "id of length " + bad.length());
            assertFalse(DirectoryPerson.validId(bad), "id of length " + bad.length());
        }
        assertTrue(DirectoryPerson.validId("ana"));
        assertTrue(DirectoryPerson.validId("a.b-c_d9"));
        assertFalse(DirectoryPerson.validId(null));
    }

    @Test
    void aPersonHoldsKnownRolesAndNothingElseAndMayHoldNoneAtAll() {
        // a leaver, or a joiner whose items still wait for approval, holds no console role
        assertTrue(person("ana", "Ana").consoleRoles().isEmpty());
        assertThrows(IllegalArgumentException.class, () -> person("ana", "Ana", "ROOT"));
        assertThrows(IllegalArgumentException.class, () -> person("ana", "Ana", "ADMIN' OR '1'='1"));
        assertThrows(IllegalArgumentException.class, () -> person("ana", "Ana", "admin"));
    }

    @Test
    void textMayHoldQuotesAndAccentsButNothingThatForgesALineOrFlipsADirection() {
        for (String ok : List.of("O'Brien", "Robert'); DROP TABLE directory_person;--", "Jos" + cp(0xE9) + " M" + cp(0xFC) + "ller",
                cp(0x5C71, 0x7530) + " " + cp(0x592A, 0x90CE), "Ana (analyst)", "a \"quoted\" name")) {
            assertEquals(ok, person("ana", ok, "USER").displayName());
        }
        for (String bad : List.of("", "   ", "Ana" + cp(0), "Ana" + cp(10) + "Ben", "Ana" + cp(13), "Ana" + cp(0x202E) + "evil",
                "Ana" + cp(0x2066), "Ana" + cp(0x200B), "Ana" + cp(0xFEFF), "Ana" + cp(0x2028), "lone" + cp(0xD800) + "surrogate",
                "x".repeat(101))) {
            assertThrows(IllegalArgumentException.class, () -> person("ana", bad, "USER"), "name of length " + bad.length());
        }
    }

    @Test
    void departmentAndJobFollowTheSameRules() {
        assertThrows(IllegalArgumentException.class, () -> new DirectoryPerson("ana", "Ana", "", "job", DirectoryPerson.Status.ACTIVE,
                DirectoryPerson.Source.SEED, AT, Set.of("USER")));
        assertThrows(IllegalArgumentException.class, () -> new DirectoryPerson("ana", "Ana", "SOC", "job" + cp(7),
                DirectoryPerson.Status.ACTIVE, DirectoryPerson.Source.SEED, AT, Set.of("USER")));
        assertThrows(IllegalArgumentException.class, () -> new DirectoryPerson("ana", "Ana", "d".repeat(61), "job",
                DirectoryPerson.Status.ACTIVE, DirectoryPerson.Source.SEED, AT, Set.of("USER")));
    }

    @Test
    void nullsAreRefused() {
        assertThrows(NullPointerException.class, () -> new DirectoryPerson(null, "Ana", "SOC", "job", DirectoryPerson.Status.ACTIVE,
                DirectoryPerson.Source.SEED, AT, Set.of("USER")));
        assertThrows(NullPointerException.class, () -> new DirectoryPerson("ana", "Ana", "SOC", "job", null,
                DirectoryPerson.Source.SEED, AT, Set.of("USER")));
        assertThrows(NullPointerException.class, () -> new DirectoryPerson("ana", "Ana", "SOC", "job", DirectoryPerson.Status.ACTIVE,
                DirectoryPerson.Source.SEED, null, Set.of("USER")));
    }
}

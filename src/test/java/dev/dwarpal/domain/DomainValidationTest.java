package dev.dwarpal.domain;

import dev.dwarpal.Fixtures;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DomainValidationTest {

    @Test
    void logInjectionThroughIdentifiersIsImpossible() {
        assertThrows(IllegalArgumentException.class,
                () -> Fixtures.request().subject("alice\n2026-11-01 ALLOW root").build());
        assertThrows(IllegalArgumentException.class, () -> Fixtures.request().subject("").build());
        assertThrows(IllegalArgumentException.class, () -> Fixtures.request().subject("a".repeat(129)).build());
        assertThrows(IllegalArgumentException.class, () -> Fixtures.request().roles("<script>").build());
        assertDoesNotThrow(() -> Fixtures.request().subject("alice@corp.example").build());
    }

    @Test
    void coordinatesAndAccuracyAreChecked() {
        assertThrows(IllegalArgumentException.class, () -> new NetworkContext("1.2.3.4", "AS1", "IN", 91, 0, 1));
        assertThrows(IllegalArgumentException.class, () -> new NetworkContext("1.2.3.4", "AS1", "IN", 0, 181, 1));
        assertThrows(IllegalArgumentException.class, () -> new NetworkContext("1.2.3.4", "AS1", "IN", 0, 0, -1));
        assertThrows(IllegalArgumentException.class,
                () -> new NetworkContext("1.2.3.4", "AS1", "IN", Double.NaN, 0, 1));
    }

    @Test
    void orderingsAreSecurityRelevantAndCorrect() {
        assertTrue(AssuranceLevel.HARDWARE_ATTESTED.atLeast(AssuranceLevel.AGENT_SIGNED));
        assertFalse(AssuranceLevel.SELF_REPORTED.atLeast(AssuranceLevel.AGENT_SIGNED));
        assertTrue(DataClassification.RESTRICTED.atLeast(DataClassification.CONFIDENTIAL));
        assertTrue(DataClassification.PUBLIC.atMost(DataClassification.INTERNAL));
    }

    @Test
    void resourceDefaultsToFailClosed() {
        assertTrue(new Resource("x", ResourceKind.WEB, DataClassification.PUBLIC).failMode() == FailMode.FAIL_CLOSED);
    }

    @Test
    void subjectRolesAreImmutableCopies() {
        Set<String> roles = new java.util.HashSet<>(Set.of("engineer"));
        Subject s = new Subject("bob", SubjectType.HUMAN, roles, "eng");
        roles.add("admin");
        assertFalse(s.roles().contains("admin"), "mutating the caller's set must not grant a role");
    }

    @Test
    void healthyRequiresAllThreeChecks() {
        assertFalse(new DevicePosture(true, true, false, AssuranceLevel.AGENT_SIGNED).healthy());
        assertTrue(new DevicePosture(true, true, true, AssuranceLevel.SELF_REPORTED).healthy());
    }
}

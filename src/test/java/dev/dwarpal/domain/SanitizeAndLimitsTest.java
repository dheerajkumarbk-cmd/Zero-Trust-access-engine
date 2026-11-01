package dev.dwarpal.domain;

import dev.dwarpal.Fixtures;
import dev.dwarpal.pip.InMemoryDirectory;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SanitizeAndLimitsTest {

    @Test
    void controlLineSeparatorAndBidiCharactersAreEscaped() {
        String out = Sanitize.text("a\r\nb\u0000c" + (char) 0x2028 + "d" + (char) 0x202E + "e" + (char) 0x2066 + "f" + (char) 0x200F + "g\tz", 100);
        assertEquals("a\\u000d\\u000ab\\u0000c\\u2028d\\u202ee\\u2066f\\u200fg\\u0009z", out);
    }

    @Test
    void longTextIsTruncated() {
        String out = Sanitize.text("x".repeat(1000), 10);
        assertEquals("xxxxxxxxxx...[truncated]", out);
    }

    @Test
    void plainTextAndUnicodeLettersAreKept() {
        assertEquals("Mozilla/5.0 (Windows NT 10.0) – héllo", Sanitize.text("Mozilla/5.0 (Windows NT 10.0) – héllo", 100));
    }

    @Test
    void pathTraversalLookingIdsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> Validate.id("../../etc/passwd", "x"));
        assertThrows(IllegalArgumentException.class, () -> Validate.id("a..b", "x"));
        assertEquals("a.b", Validate.id("a.b", "x"));
    }

    @Test
    void homoglyphsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> Validate.id("аdmin", "x")); // Cyrillic а
    }

    @Test
    void labelsAreCanonicalEvenUnderATurkishDefaultLocale() {
        Locale saved = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            assertEquals("admin", Validate.label("ADMIN", "x"));
            assertEquals("IN", Validate.country("in", "x"));
        } finally {
            Locale.setDefault(saved);
        }
    }

    @Test
    void subjectCanonicalisesAndBoundsRoles() {
        Subject s = new Subject("alice", SubjectType.HUMAN, Set.of("Finance", "ADMIN"), "Accounts");
        assertEquals(Set.of("finance", "admin"), s.roles());
        assertEquals("accounts", s.department());
        Set<String> tooMany = IntStream.range(0, Subject.MAX_ROLES + 1).mapToObj(i -> "r" + i).collect(Collectors.toSet());
        assertThrows(IllegalArgumentException.class, () -> new Subject("a", SubjectType.HUMAN, tooMany, "d"));
    }

    @Test
    void absurdMagnitudesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> Validate.positive(1e300, "x"));
        assertThrows(IllegalArgumentException.class, () -> Validate.positive(Double.POSITIVE_INFINITY, "x"));
    }

    @Test
    void directoryRejectsDuplicateRecords() {
        Subject a = Fixtures.request().build().subject();
        assertThrows(IllegalStateException.class, () -> new InMemoryDirectory(List.of(a, a), List.of()));
        assertFalse(new InMemoryDirectory(List.of(a), List.of()).resource("nope").isPresent());
        assertTrue(new InMemoryDirectory(List.of(a), List.of()).subject("alice").isPresent());
    }
}

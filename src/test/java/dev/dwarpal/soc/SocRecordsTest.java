package dev.dwarpal.soc;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.sim.SimOrganisation;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 5 part 0: alerts are bounded and safe to show; verdicts count only when an analyst signed them. */
class SocRecordsTest {

    private static final Instant T = Instant.parse("2026-11-04T10:00:00Z");
    private static final SimOrganisation ORG = SimOrganisation.create(1, 6);

    private static Alert alert(List<Entity> entities, List<Long> evidence, long count, String summary) {
        return new Alert("al-1", "break-glass-used", Severity.HIGH, T, entities, evidence, count, summary);
    }

    @Test
    void alertsAreBoundedAndTheirSummaryIsSafeToShow() {
        Alert a = alert(List.of(Entity.subject("bg-admin-1")), List.of(41L), 1,
                "break-glass by bg-admin-1\nFAKE: all clear\u202e");
        assertFalse(a.summary().contains("\n"), "no forged second line in an analyst's view");
        assertFalse(a.summary().contains("\u202e"), "no bidi override");
        assertTrue(alert(List.of(Entity.ip("10.0.0.1")), List.of(1L), 1, "x".repeat(500)).summary().length()
                <= Alert.MAX_SUMMARY);
        assertThrows(IllegalArgumentException.class, () -> alert(List.of(), List.of(1L), 1, "s"));
        assertThrows(IllegalArgumentException.class, () -> alert(Collections.nCopies(17, Entity.subject("a")),
                List.of(1L), 1, "s"));
        assertThrows(IllegalArgumentException.class, () -> alert(List.of(Entity.subject("a")), List.of(), 1, "s"));
        assertThrows(IllegalArgumentException.class, () -> alert(List.of(Entity.subject("a")),
                Collections.nCopies(101, 1L), 1, "s"));
        assertThrows(IllegalArgumentException.class, () -> alert(List.of(Entity.subject("a")), List.of(0L), 1, "s"));
        assertThrows(IllegalArgumentException.class, () -> alert(List.of(Entity.subject("a")), List.of(1L), 0, "s"));
        assertThrows(IllegalArgumentException.class, () -> new Alert("al 1", "r", Severity.LOW, T,
                List.of(Entity.subject("a")), List.of(1L), 1, "s"), "ids are identifiers, not free text");
        assertThrows(IllegalArgumentException.class, () -> Entity.subject("bob\nadmin"));
        assertThrows(NullPointerException.class, () -> new Entity(null, "x"));
        assertEquals(Entity.Kind.DEVICE, Entity.device("laptop-1").kind());
    }

    @Test
    void severitiesAreOrdered() {
        assertTrue(Severity.CRITICAL.atLeast(Severity.HIGH));
        assertTrue(Severity.MEDIUM.atLeast(Severity.MEDIUM));
        assertFalse(Severity.LOW.atLeast(Severity.MEDIUM));
    }

    @Test
    void aVerdictCountsOnlyWhenItsAnalystSignedExactlyIt() {
        Verdict good = ORG.verdict("ana", "al-1", Verdict.Outcome.TRUE_POSITIVE, T);
        assertTrue(good.verify(ORG.keys, T.plusSeconds(30)).valid());

        Verdict otherOutcome = new Verdict("al-1", "ana", Verdict.Outcome.FALSE_POSITIVE, good.proof());
        assertFalse(otherOutcome.verify(ORG.keys, T).valid(), "the outcome is signed");
        Verdict otherAlert = new Verdict("al-2", "ana", Verdict.Outcome.TRUE_POSITIVE, good.proof());
        assertFalse(otherAlert.verify(ORG.keys, T).valid(), "the alert is signed");

        Verdict benAsAna = new Verdict("al-1", "ana", Verdict.Outcome.TRUE_POSITIVE, new SignatureProof("soc-ben", T,
                Ed25519.sign(SimOrganisation.ANALYST_BEN.getPrivate(),
                        SignedMessages.socVerdict("al-1", "ana", "TRUE_POSITIVE", T))));
        assertFalse(benAsAna.verify(ORG.keys, T).valid(), "one analyst cannot sign in another's name");

        Verdict byIdp = new Verdict("al-1", "ana", Verdict.Outcome.TRUE_POSITIVE, new SignatureProof(
                dev.dwarpal.Fixtures.IDP_KEY_ID, T, Ed25519.sign(dev.dwarpal.Fixtures.IDP.getPrivate(),
                SignedMessages.socVerdict("al-1", "ana", "TRUE_POSITIVE", T))));
        assertFalse(byIdp.verify(ORG.keys, T).valid(), "an identity-provider key is not an analyst key");

        assertFalse(good.verify(ORG.keys, T.plus(Verdict.MAX_AGE).plus(Duration.ofMinutes(5))).valid(), "stale");
        assertThrows(NullPointerException.class, () -> good.verify(null, T));
        assertThrows(IllegalArgumentException.class, () -> new Verdict("al-1", "ana\n", Verdict.Outcome.BENIGN,
                good.proof()));
    }
}

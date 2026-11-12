package dev.dwarpal.console;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The same read, again and again, becomes one record that says how many repeats it stands for. */
class ReadWindowTest {

    private static final Instant T0 = Instant.parse("2026-11-08T10:00:00Z");

    @Test
    void theFirstReadIsRecordedAndTheRepeatsAreCountedUntilTheWindowEnds() {
        ReadWindow w = new ReadWindow(Duration.ofSeconds(60), 100);
        assertTrue(w.see("ana|case-1", T0).record());
        assertFalse(w.see("ana|case-1", T0.plusSeconds(5)).record());
        assertFalse(w.see("ana|case-1", T0.plusSeconds(59)).record());
        ReadWindow.Decision next = w.see("ana|case-1", T0.plusSeconds(61));
        assertTrue(next.record());
        assertEquals(2, next.repeats(), "the record says how many reads it stands for");
        assertEquals(0, w.see("ana|case-1", T0.plusSeconds(200)).repeats());
    }

    @Test
    void differentThingsAndDifferentPeopleAreSeparate() {
        ReadWindow w = new ReadWindow(Duration.ofSeconds(60), 100);
        assertTrue(w.see("ana|case-1", T0).record());
        assertTrue(w.see("ana|case-2", T0).record());
        assertTrue(w.see("ben|case-1", T0).record());
    }

    @Test
    void aReadWhoseRecordFailedIsTriedAgain() {
        ReadWindow w = new ReadWindow(Duration.ofSeconds(60), 100);
        assertTrue(w.see("k", T0).record());
        w.undo("k");
        assertTrue(w.see("k", T0.plusSeconds(1)).record(), "the failed record is not counted as written");
    }

    @Test
    void aClockThatWentBackwardsRecordsAgainInsteadOfHiding() {
        ReadWindow w = new ReadWindow(Duration.ofSeconds(60), 100);
        assertTrue(w.see("k", T0).record());
        assertTrue(w.see("k", T0.minusSeconds(30)).record());
    }

    @Test
    void theMemoryIsBoundedAndForgettingOnlyMeansMoreRecords() {
        ReadWindow w = new ReadWindow(Duration.ofHours(1), 3);
        for (int i = 0; i < 10; i++) {
            assertTrue(w.see("k" + i, T0).record(), "every first read is recorded");
        }
        assertEquals(3, w.size());
        assertTrue(w.see("k0", T0.plusSeconds(1)).record(), "k0 was forgotten, so it is recorded again");
    }

    @Test
    void aWindowAndACapacityAreRequired() {
        assertThrows(IllegalArgumentException.class, () -> new ReadWindow(Duration.ZERO, 5));
        assertThrows(IllegalArgumentException.class, () -> new ReadWindow(Duration.ofSeconds(1), 0));
    }
}

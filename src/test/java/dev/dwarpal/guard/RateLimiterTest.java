package dev.dwarpal.guard;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RateLimiterTest {

    private static final Instant T = Instant.parse("2026-11-02T09:00:00Z");

    @Test
    void allowsTheLimitPerWindowThenRefusesUntilTheWindowEnds() {
        RateLimiter r = new RateLimiter(3, Duration.ofMinutes(1), 10);
        assertTrue(r.tryAcquire("a", T));
        assertTrue(r.tryAcquire("a", T.plusSeconds(10)));
        assertTrue(r.tryAcquire("a", T.plusSeconds(20)));
        assertFalse(r.tryAcquire("a", T.plusSeconds(59)));
        assertTrue(r.tryAcquire("b", T.plusSeconds(59)), "keys are independent");
        assertTrue(r.tryAcquire("a", T.plusSeconds(60)), "a new window");
        assertEquals(1, r.refused());
    }

    @Test
    void aFullTableRefusesNewKeysUntilWindowsExpire() {
        RateLimiter r = new RateLimiter(5, Duration.ofMinutes(1), 2);
        assertTrue(r.tryAcquire("a", T));
        assertTrue(r.tryAcquire("b", T));
        assertFalse(r.tryAcquire("c", T), "a flood of fresh keys is refused, not allowed");
        assertTrue(r.tryAcquire("a", T), "known keys keep working");
        assertTrue(r.tryAcquire("c", T.plusSeconds(61)), "room again once windows end");
    }

    @Test
    void invalidSettingsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new RateLimiter(0, Duration.ofMinutes(1), 1));
        assertThrows(IllegalArgumentException.class, () -> new RateLimiter(1, Duration.ZERO, 1));
        assertThrows(IllegalArgumentException.class, () -> new RateLimiter(1, Duration.ofMinutes(1), 0));
    }
}

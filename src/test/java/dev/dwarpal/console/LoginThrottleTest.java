package dev.dwarpal.console;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoginThrottleTest {

    private final ConsoleFixture.TestClock clock = new ConsoleFixture.TestClock();
    private final LoginThrottle t = new LoginThrottle(clock);

    @Test
    void theWaitDoublesFromFiveSecondsUpToFifteenMinutes() {
        for (int i = 0; i < 3; i++) {
            t.failure("a", "10.0.0.1");
            assertEquals(0, t.retryAfterSeconds("a", "10.0.0.1"));
        }
        long previous = 0;
        for (int i = 0; i < 12; i++) {
            t.failure("a", "10.0.0.1");
            long wait = t.retryAfterSeconds("a", "10.0.0.1");
            assertTrue(wait >= previous - 1 && wait <= 901, "wait " + wait);
            previous = Math.min(wait, 900);
            clock.advance(Duration.ofSeconds(wait + 1));
        }
        assertTrue(previous >= 600, "capped near fifteen minutes: " + previous);
    }

    @Test
    void thePairAndTheAddressAreSeparateKeys() {
        for (int i = 0; i < 6; i++) {
            t.failure("a", "10.0.0.1");
        }
        assertTrue(t.retryAfterSeconds("a", "10.0.0.1") > 0);
        assertEquals(0, t.retryAfterSeconds("a", "10.0.0.2"), "the same account from another address is not locked");
        assertEquals(0, t.retryAfterSeconds("b", "10.0.0.1"), "another account from the same address is not locked by one account");
    }

    @Test
    void successForgetsThePairButNotTheAddress() {
        for (int i = 0; i < 5; i++) {
            t.failure("a", "10.0.0.1");
        }
        clock.advance(Duration.ofSeconds(40));
        t.success("a", "10.0.0.1");
        assertEquals(0, t.retryAfterSeconds("a", "10.0.0.1"));
    }

    @Test
    void anAddressThatTriesManyAccountsIsLockedForTenMinutes() {
        for (int i = 0; i < LoginThrottle.SOURCE_FAILURES; i++) {
            t.failure("user" + i, "10.0.0.9");
        }
        assertTrue(t.retryAfterSeconds("fresh", "10.0.0.9") > 0);
        assertEquals(0, t.retryAfterSeconds("fresh", "10.0.0.8"));
        clock.advance(Duration.ofMinutes(11));
        assertEquals(0, t.retryAfterSeconds("fresh", "10.0.0.9"));
    }

    @Test
    void aFullTableRefusesNewKeysInsteadOfForgettingOldOnes() {
        for (int i = 0; i < 10_000; i++) {
            t.failure("u" + i, "10.1." + (i / 250) + "." + (i % 250));
        }
        assertTrue(t.retryAfterSeconds("brand-new", "10.9.9.9") > 0, "under a flood of fresh keys the answer is wait");
    }
}

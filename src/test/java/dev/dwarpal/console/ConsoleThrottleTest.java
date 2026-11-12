package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Resp;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Standards: login throttling per account and source, exponential delay, visible lockout, no oracle. */
class ConsoleThrottleTest {

    private static ConsoleFixture f;

    @BeforeAll
    static void start() throws Exception {
        f = ConsoleFixture.start();
    }

    @AfterAll
    static void stop() {
        f.close();
    }

    private Resp wrong(String user) throws Exception {
        return f.login(user, "wrong-password-0", "BADPIN99");
    }

    @Test
    void failuresLockTheAccountAtThisSourceWithAGrowingVisibleWaitAndNoOracle() throws Exception {
        for (int i = 0; i < 3; i++) {
            assertEquals(401, wrong("ben").status(), "the first three failures cost nothing");
        }
        Resp locked = wrong("ben");
        assertEquals(429, locked.status(), "the fourth failure starts the lockout and the answer already says so");
        assertNotNull(locked.header("Retry-After"));
        long first = Long.parseLong(locked.header("Retry-After"));
        assertTrue(first >= 5 && first <= 7, "5 seconds for the first lockout: " + first);
        assertTrue(locked.body().contains("\"retryAfterSeconds\""));

        // the right password does not get through while locked, and does not say that it was right
        ConsoleAuth.Enrolment ben = f.person("ben");
        Resp right = f.login("ben", ben.password(), ben.pin());
        assertEquals(429, right.status());
        assertEquals(0, right.headers().allValues("Set-Cookie").size());

        f.clock.advance(Duration.ofSeconds(8));
        Resp longer = wrong("ben");
        assertEquals(429, longer.status(), "after the wait one more try; it fails and doubles the wait");
        assertTrue(Long.parseLong(longer.header("Retry-After")) >= 10, longer.header("Retry-After"));

        f.clock.advance(Duration.ofSeconds(15));
        assertEquals(200, f.login("ben", ben.password(), ben.pin()).status(), "waiting is enough, and a success clears the pair");
        assertEquals(401, wrong("ben").status(), "a cleared pair starts again with free failures");
    }

    @Test
    void anUnknownAccountIsThrottledExactlyLikeAKnownOne() throws Exception {
        for (int i = 0; i < 3; i++) {
            assertEquals(401, wrong("ghost").status());
        }
        Resp ghost = wrong("ghost");
        assertEquals(429, ghost.status());
        for (int i = 0; i < 3; i++) {
            assertEquals(401, wrong("uma").status());
        }
        Resp uma = wrong("uma");
        assertEquals(429, uma.status());
        assertEquals(ghost.body().replaceAll("\\d+", "N"), uma.body().replaceAll("\\d+", "N"), "same shape for both");
    }

    @Test
    void oneAddressTryingManyAccountsIsStoppedWhateverTheAccount() throws Exception {
        f.clock.advance(Duration.ofMinutes(31));
        int refused = 0;
        for (int i = 0; i < 40 && refused == 0; i++) {
            Resp r = wrong("user" + i);
            if (r.status() == 429) {
                refused++;
            }
        }
        assertEquals(1, refused, "after 30 failures from one address that address waits");
        ConsoleAuth.Enrolment cleo = f.person("cleo");
        Resp real = f.login("cleo", cleo.password(), cleo.pin());
        assertEquals(429, real.status(), "even for an account that was never attacked");
        f.clock.advance(Duration.ofMinutes(11));
        assertEquals(200, f.login("cleo", cleo.password(), cleo.pin()).status());
    }

    @Test
    void stepUpGuessesAreThrottledToo() throws Exception {
        ConsoleFixture.Sess s = f.login("ana");
        ConsoleAuth.Enrolment ana = f.person("ana");
        int locked = 0;
        for (int i = 0; i < 8; i++) {
            Resp r = f.post("/console/api/session/stepup", s, "{\"password\":\"" + ana.password() + "\",\"pin\":\"BADPIN9" + i + "\"}");
            if (r.status() == 429) {
                locked++;
            } else {
                assertEquals(401, r.status());
            }
        }
        assertTrue(locked >= 3, "a stolen session cannot guess the key PIN at leisure: " + locked);
        Resp good = f.post("/console/api/session/stepup", s, "{\"password\":\"" + ana.password() + "\",\"pin\":\"" + ana.pin() + "\"}");
        assertEquals(429, good.status());
        assertFalse(good.body().contains("csrf"));
    }
}

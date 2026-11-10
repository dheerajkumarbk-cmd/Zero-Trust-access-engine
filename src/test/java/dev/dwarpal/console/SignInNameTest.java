package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleAuth.Change;
import dev.dwarpal.console.ConsoleAuth.Status;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** User names are accepted in any ASCII letter case, with one lockout counter per person; other characters are refused. */
class SignInNameTest {

    private static final String SOURCE = "127.0.0.1";

    private ConsoleFixture f;
    private ConsoleAuth auth;
    private ConsoleAuth.Enrolment ana;

    @BeforeEach
    void start() throws Exception {
        f = ConsoleFixture.start();
        auth = new ConsoleAuth(f.people, f.clock, 10_000, 1_000);
        ana = f.person("ana");
    }

    @AfterEach
    void stop() {
        f.close();
    }

    private ConsoleAuth.Authenticated signIn(String typed, String password, String pin) {
        ConsoleAuth.Begun b = auth.begin(typed, password, SOURCE);
        if (b.status() != Status.OK) {
            return new ConsoleAuth.Authenticated(b.status(), null, b.retryAfterSeconds(), typed);
        }
        return auth.complete(b.loginId(), pin, SOURCE);
    }

    @Test
    void aNameInAnyLetterCaseSignsInAsThePerson() {
        for (String typed : List.of("Ana", "ANA", "ana")) {
            ConsoleAuth.Authenticated a = signIn(typed, ana.password(), ana.pin());
            assertEquals(Status.OK, a.status(), typed);
            assertEquals("ana", a.subject(), typed);
            assertEquals("ana", a.person().id(), typed);
        }
    }

    @Test
    void wrongTriesInDifferentCaseShareOneLockout() {
        for (int i = 0; i <= LoginThrottle.FREE_FAILURES; i++) {
            String typed = i % 2 == 0 ? "Ana" : "ANA";
            assertNotEquals(Status.OK, signIn(typed, "not-the-password", ana.pin()).status());
        }
        assertTrue(auth.begin("ana", ana.password(), SOURCE).retryAfterSeconds() > 0, "ana is locked too");
        assertEquals(Status.LOCKED, auth.begin("aNa", ana.password(), SOURCE).status());
    }

    @Test
    void aNameWithNonAsciiLettersIsRefusedNotMapped() {
        for (String typed : List.of("Ken", "аna", "АNA", "ana ", " ana", "an a")) {
            ConsoleAuth.Begun b = auth.begin(typed, ana.password(), SOURCE);
            assertEquals(Status.FAILED, b.status(), typed);
            assertNull(b.loginId(), typed);
        }
        assertEquals("Ken", ConsoleAuth.typedName("Ken"));
        assertNull(ConsoleAuth.typedName(null));
    }

    @Test
    void recoveryAcceptsTheNameInAnyCase() {
        ConsoleAuth.Changed[] result = new ConsoleAuth.Changed[1];
        Optional<List<String>> codes = auth.newBackupCodes("ana", ana.password(), ana.pin(), SOURCE, result);
        assertTrue(codes.isPresent(), "backup codes are reachable");
        ConsoleAuth.Recovering r = auth.checkBackupCode("Ana", codes.get().getFirst(), SOURCE);
        assertEquals(Change.OK, r.status());
        assertEquals(Optional.of("ana"), auth.recoveryOf(r.ticket()));
    }
}

package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A real device passkey (WebAuthn) end to end over the console's HTTP routes: registering one, unlocking with it, and the
 * elevation. A software authenticator makes real attestation objects and signatures, so the console's own checks run on real
 * bytes: the challenge is used once and belongs to the person, the origin and the relying party must be this console's, the
 * device must report presence and verification, the signature must fit the stored key, and a counter must not go backwards.
 */
class WebAuthnEndToEndTest {

    private static final String RP = "localhost";

    @TempDir
    Path dir;

    private ConsoleFixture f;
    private WebAuthnStepUp step;

    @BeforeEach
    void start() throws Exception {
        f = ConsoleFixture.startWithAuth((b, auth) -> {
            try {
                step = WebAuthnStepUp.open(auth, dir.resolve("passkeys.txt"), RP, "https://localhost", Clock.systemUTC());
            } catch (java.io.IOException e) {
                throw new IllegalStateException(e);
            }
            b.passkeyStepUp(step).passkeyLock(Duration.ofMinutes(15), Duration.ofMinutes(5));
        }, ConsoleSettings.defaults().fastHashing());
        step.expectOrigin(f.origin);
    }

    @AfterEach
    void stop() {
        f.close();
    }

    private static String quoted(String json) {
        return "\"" + json.replace("\"", "\\\"") + "\"";
    }

    private ConsoleAuth.Enrolment enrolment(String id) {
        return f.people.stream().filter(e -> e.person().id().equals(id)).findFirst().orElseThrow();
    }

    private String challengeFor(Sess s) throws Exception {
        Resp r = f.post("/console/api/session/passkey/challenge", s, "{}");
        assertEquals(200, r.status(), r.body());
        return r.field("challenge");
    }

    /** Registers the device as this person's passkey, the way the Profile page does (begin, then the device, then save). */
    private SoftAuthenticator register(String who, Sess s, boolean rsa) throws Exception {
        ConsoleAuth.Enrolment e = enrolment(who);
        String proof = "\"password\":\"" + e.password() + "\",\"pin\":\"" + e.pin() + "\"";
        Resp begin = f.post("/console/api/profile/passkey/begin", s, "{" + proof + "}");
        assertEquals(200, begin.status(), begin.body());
        SoftAuthenticator device = new SoftAuthenticator(rsa);
        String evidence = device.attestation(f.origin, RP, begin.field("challenge"), (byte) (SoftAuthenticator.UP | SoftAuthenticator.UV
                | SoftAuthenticator.AT), 0);
        Resp saved = f.post("/console/api/profile/passkey", s, "{" + proof + ",\"passkey\":" + quoted(evidence) + "}");
        assertEquals(200, saved.status(), saved.body());
        return device;
    }

    private Resp unlock(Sess s, String evidence) throws Exception {
        return f.post("/console/api/session/unlock", s, "{\"passkey\":" + quoted(evidence) + ",\"scope\":\"window\"}");
    }

    private static final byte GOOD = SoftAuthenticator.UP | SoftAuthenticator.UV;

    @Test
    void aPersonRegistersTheirDeviceAndUnlocksWithItAndNoOtherAnswerWorks() throws Exception {
        Sess dana = f.login("dana");
        assertEquals("webauthn", f.post("/console/api/session/passkey/challenge", dana, "{}").field("kind"), "the console says it wants a device");
        SoftAuthenticator device = register("dana", dana, false);
        String me = f.get("/console/api/me", dana).body();
        assertTrue(me.contains("\"passkeySet\":true") && me.contains("\"passkeyKind\":\"webauthn\""), me);
        Resp ok = unlock(dana, device.assertion(f.origin, RP, challengeFor(dana), GOOD, 1));
        assertEquals(200, ok.status(), ok.body());
        assertTrue(ok.body().contains("unlockedSeconds"));
    }

    @Test
    void anAnswerWorksOnceAndOnlyForTheChallengeItWasGivenFor() throws Exception {
        Sess dana = f.login("dana");
        SoftAuthenticator device = register("dana", dana, false);
        String challenge = challengeFor(dana);
        String evidence = device.assertion(f.origin, RP, challenge, GOOD, 1);
        assertEquals(200, unlock(dana, evidence).status());
        assertEquals(401, unlock(dana, evidence).status(), "the same signed answer cannot be replayed");
        // a signature over a challenge the console never issued
        challengeFor(dana);
        assertEquals(401, unlock(dana, device.assertion(f.origin, RP, SoftAuthenticator.b64(new byte[32]), GOOD, 2)).status());
    }

    @Test
    void aLookAlikeOriginAnotherRelyingPartyOrAnUnverifiedPersonIsRefused() throws Exception {
        Sess dana = f.login("dana");
        SoftAuthenticator device = register("dana", dana, false);
        assertEquals(401, unlock(dana, device.assertion("https://localhost.evil.example", RP, challengeFor(dana), GOOD, 1)).status(), "origin");
        assertEquals(401, unlock(dana, device.assertion(f.origin, "evil.example", challengeFor(dana), GOOD, 2)).status(), "relying party");
        assertEquals(401, unlock(dana, device.assertion(f.origin, RP, challengeFor(dana), SoftAuthenticator.UP, 3)).status(),
                "the device did not verify the person (no PIN or fingerprint)");
        assertEquals(200, unlock(dana, device.assertion(f.origin, RP, challengeFor(dana), GOOD, 4)).status(),
                "and the right answer still works after the refused ones");
    }

    /** Refused: wrong (401), or already in the growing wait that repeated wrong answers earn (429). */
    private static void refused(Resp r, String why) {
        assertTrue(r.status() == 401 || r.status() == 429, why + " -> " + r.status());
    }

    @Test
    void aSignatureFromAnotherKeyIsRefusedAndTypingAPasskeyNoLongerWorks() throws Exception {
        Sess dana = f.login("dana");
        SoftAuthenticator device = register("dana", dana, false);
        assertEquals(401, unlock(dana, device.assertion(f.origin, RP, challengeFor(dana), GOOD, 1, SoftAuthenticator.anotherEcKey())).status());
        refused(f.post("/console/api/session/unlock", dana, "{\"passkey\":\"a-typed-passkey-123\",\"scope\":\"window\"}"), "typed");
        refused(unlock(dana, "{}"), "empty answer");
        refused(unlock(dana, "not json at all"), "not json");
    }

    @Test
    void repeatedWrongAnswersEarnTheSameGrowingWaitAsWrongTypedPasskeys() throws Exception {
        Sess dana = f.login("dana");
        register("dana", dana, false);
        int waits = 0;
        for (int i = 0; i < 12; i++) {
            if (unlock(dana, "{}").status() == 429) {
                waits++;
            }
        }
        assertTrue(waits > 0, "a run of wrong answers ends in a wait");
    }

    @Test
    void aCounterThatGoesBackwardsIsRefusedAndOneThatStaysAtZeroIsFine() throws Exception {
        Sess dana = f.login("dana");
        SoftAuthenticator device = register("dana", dana, false);
        assertEquals(200, unlock(dana, device.assertion(f.origin, RP, challengeFor(dana), GOOD, 5)).status());
        assertEquals(401, unlock(dana, device.assertion(f.origin, RP, challengeFor(dana), GOOD, 3)).status(), "a copied key shows as a counter going back");
        assertEquals(200, unlock(dana, device.assertion(f.origin, RP, challengeFor(dana), GOOD, 6)).status());
        Sess spector = f.login("spector");
        SoftAuthenticator synced = register("spector", spector, false);
        assertEquals(200, unlock(spector, synced.assertion(f.origin, RP, challengeFor(spector), GOOD, 0)).status());
        assertEquals(200, unlock(spector, synced.assertion(f.origin, RP, challengeFor(spector), GOOD, 0)).status());
    }

    @Test
    void anotherPersonsChallengeAndAnotherPersonsDeviceDoNotOpenMyAccount() throws Exception {
        Sess dana = f.login("dana");
        Sess spector = f.login("spector");
        SoftAuthenticator danaDevice = register("dana", dana, false);
        register("spector", spector, false);
        String spectorChallenge = challengeFor(spector);
        assertEquals(401, unlock(dana, danaDevice.assertion(f.origin, RP, spectorChallenge, GOOD, 1)).status(), "a challenge is for one person");
        assertEquals(401, unlock(spector, danaDevice.assertion(f.origin, RP, challengeFor(spector), GOOD, 1)).status(), "dana's device is not spector's");
    }

    @Test
    void anRsaDevicesPasskeyWorksToo() throws Exception {
        Sess dana = f.login("dana");
        SoftAuthenticator device = register("dana", dana, true);
        assertEquals(200, unlock(dana, device.assertion(f.origin, RP, challengeFor(dana), GOOD, 1)).status());
    }

    @Test
    void aRegistrationNeedsThePasswordAndPinAndAFreshChallengeAndTheDeviceFlags() throws Exception {
        Sess dana = f.login("dana");
        ConsoleAuth.Enrolment e = enrolment("dana");
        String proof = "\"password\":\"" + e.password() + "\",\"pin\":\"" + e.pin() + "\"";
        assertEquals(401, f.post("/console/api/profile/passkey/begin", dana, "{\"password\":\"wrong-password-x\",\"pin\":\"" + e.pin() + "\"}").status());
        Resp begin = f.post("/console/api/profile/passkey/begin", dana, "{" + proof + "}");
        SoftAuthenticator device = new SoftAuthenticator(false);
        byte flagsWithoutVerification = (byte) (SoftAuthenticator.UP | SoftAuthenticator.AT);
        String weak = device.attestation(f.origin, RP, begin.field("challenge"), flagsWithoutVerification, 0);
        assertEquals(400, f.post("/console/api/profile/passkey", dana, "{" + proof + ",\"passkey\":" + quoted(weak) + "}").status(),
                "a device that did not verify the person cannot be registered");
        assertFalse(f.get("/console/api/me", dana).body().contains("\"passkeySet\":true"));
        // the password and PIN are checked again at the end, not only at the start
        Resp again = f.post("/console/api/profile/passkey/begin", dana, "{" + proof + "}");
        String good = device.attestation(f.origin, RP, again.field("challenge"), (byte) (GOOD | SoftAuthenticator.AT), 0);
        assertEquals(401, f.post("/console/api/profile/passkey", dana, "{\"password\":\"wrong-password-x\",\"pin\":\"" + e.pin() + "\",\"passkey\":"
                + quoted(good) + "}").status());
    }

    @Test
    void theElevationAsksForTheDeviceAndWrongPinAndWrongDeviceLookTheSame() throws Exception {
        Sess dana = f.login("dana");
        SoftAuthenticator device = register("dana", dana, false);
        ConsoleAuth.Enrolment e = enrolment("dana");
        String badPin = f.post("/console/api/session/elevate", dana, "{\"pin\":\"000000\",\"reason\":\"approving a request\",\"passkey\":"
                + quoted(device.assertion(f.origin, RP, challengeFor(dana), GOOD, 1)) + "}").body();
        String badKey = f.post("/console/api/session/elevate", dana, "{\"pin\":\"" + e.pin() + "\",\"reason\":\"approving a request\",\"passkey\":"
                + quoted(device.assertion(f.origin, "evil.example", challengeFor(dana), GOOD, 2)) + "}").body();
        assertEquals(badPin, badKey);
        Resp ok = f.post("/console/api/session/elevate", dana, "{\"pin\":\"" + e.pin() + "\",\"reason\":\"approving a request\",\"passkey\":"
                + quoted(device.assertion(f.origin, RP, challengeFor(dana), GOOD, 3)) + "}");
        assertEquals(200, ok.status(), ok.body());
    }

    @Test
    void thePublicKeyIsKeptInTheFileAndNotTheSecretAndSurvivesARestart() throws Exception {
        Sess dana = f.login("dana");
        SoftAuthenticator device = register("dana", dana, false);
        List<String> lines = java.nio.file.Files.readAllLines(dir.resolve("passkeys.txt"));
        assertTrue(lines.stream().anyMatch(l -> l.startsWith("dana|" + device.id() + "|-7|")), lines.toString());
        PasskeyStore again = PasskeyStore.open(dir.resolve("passkeys.txt"));
        assertEquals(1, again.of("dana").size());
        assertTrue(again.find("dana", device.id()).isPresent());
        assertTrue(again.find("spector", device.id()).isEmpty(), "a passkey belongs to one person");
    }
}

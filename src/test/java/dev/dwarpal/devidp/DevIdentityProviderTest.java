package dev.dwarpal.devidp;

import dev.dwarpal.Fixtures;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.edge.EdgeFixtures;
import dev.dwarpal.session.FailureReportReceiver;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DevIdentityProviderTest {

    private static final String RP = "dwarpal.localhost";
    private static final String IP = "127.0.0.1";

    private final EdgeFixtures.TestClock clock = new EdgeFixtures.TestClock();
    private final SoftwareAuthenticator alicesKey = SoftwareAuthenticator.register(RP);
    private final List<FailureReportReceiver.FailureReport> reports = new ArrayList<>();
    private final List<SignatureProof> reportProofs = new ArrayList<>();
    private final DevIdentityProvider idp = new DevIdentityProvider(UserFile.parse(
            UserFile.line("alice", "correct horse".toCharArray(), UserFile.MIN_ITERATIONS, alicesKey.credentialId(),
                    alicesKey.publicKey())), Fixtures.IDP, Fixtures.IDP_KEY_ID, RP, clock, (r, p) -> {
                        reports.add(r);
                        reportProofs.add(p);
                    });
    private final KeyPair session = Ed25519.generateKeyPair();
    private final String thumb = Digests.thumbprint(session.getPublic());

    private Optional<IdentityProvider.MfaProof> login(String user, String password, SoftwareAuthenticator a, String ip) {
        WebAuthn.Challenge c = idp.challenge(user, "laptop-alice", thumb, ip).orElseThrow();
        return a.assertion(c, true).flatMap(s -> idp.authenticate(new IdentityProvider.Attempt(c.challengeId(), user,
                password, s), ip));
    }

    @Test
    void passwordPlusWebAuthnGivesAKeyBoundSignedProof() {
        IdentityProvider.MfaProof m = login("alice", "correct horse", alicesKey, IP).orElseThrow();
        assertEquals(AuthMethod.WEBAUTHN, m.authentication().method());
        assertTrue(m.authentication().boundTo(thumb));
        assertTrue(EdgeFixtures.keyRing().verify(KeyPurpose.IDENTITY_PROVIDER, null, m.proof(),
                SignedMessages.authentication("alice", "laptop-alice", m.authentication(), m.proof().signedAt()),
                clock.now(), Duration.ofMinutes(5)).valid(), "the engine's key ring accepts it");
        assertEquals(1, idp.succeeded());
        assertTrue(reports.isEmpty());
    }

    @Test
    void everyFailureIsGenericAndReportedSigned() {
        assertTrue(login("alice", "wrong", alicesKey, IP).isEmpty(), "wrong password");
        assertTrue(login("mallory", "x", alicesKey, IP).isEmpty(), "unknown user");
        assertTrue(login("alice", "", alicesKey, IP).isEmpty(), "empty password");
        assertEquals(3, reports.size());
        FailureReportReceiver.FailureReport r = reports.get(0);
        assertEquals("alice", r.subjectId());
        assertEquals(IP, r.ip());
        assertTrue(Ed25519.verify(Fixtures.IDP.getPublic(), SignedMessages.authenticationFailure(r.reportId(),
                r.subjectId(), r.ip(), r.failedAt(), reportProofs.get(0).signedAt()), reportProofs.get(0).signature()));
        assertEquals(3, idp.failed());
    }

    @Test
    void challengesAreSingleUseShortLivedAndPerSubject() {
        WebAuthn.Challenge c = idp.challenge("alice", "laptop-alice", thumb, IP).orElseThrow();
        WebAuthn.Assertion a = alicesKey.assertion(c, true).orElseThrow();
        assertTrue(idp.authenticate(new IdentityProvider.Attempt(c.challengeId(), "alice", "correct horse", a), IP)
                .isPresent());
        WebAuthn.Assertion again = alicesKey.assertion(c, true).orElseThrow();
        assertTrue(idp.authenticate(new IdentityProvider.Attempt(c.challengeId(), "alice", "correct horse", again), IP)
                .isEmpty(), "reused challenge");

        WebAuthn.Challenge old = idp.challenge("alice", "laptop-alice", thumb, IP).orElseThrow();
        clock.advance(DevIdentityProvider.CHALLENGE_LIFETIME.plusSeconds(1));
        assertTrue(idp.authenticate(new IdentityProvider.Attempt(old.challengeId(), "alice", "correct horse",
                alicesKey.assertion(old, true).orElseThrow()), IP).isEmpty(), "expired challenge");

        WebAuthn.Challenge bobs = idp.challenge("bob", "laptop-alice", thumb, IP).orElseThrow();
        assertTrue(idp.authenticate(new IdentityProvider.Attempt(bobs.challengeId(), "alice", "correct horse",
                alicesKey.assertion(bobs, true).orElseThrow()), IP).isEmpty(), "someone else's challenge");
        assertTrue(idp.authenticate(new IdentityProvider.Attempt("ch-none", "alice", "correct horse",
                alicesKey.assertion(bobs, true).orElseThrow()), IP).isEmpty(), "unknown challenge");
    }

    @Test
    void theAuthenticatorIsPhishingResistantAndClonesAreCaught() {
        SoftwareAuthenticator phishedSite = new SoftwareAuthenticator("dwarpal-login.example", alicesKey.credentialId(),
                Ed25519.generateKeyPair(), 0);
        WebAuthn.Challenge c = idp.challenge("alice", "laptop-alice", thumb, IP).orElseThrow();
        assertTrue(phishedSite.assertion(c, true).isEmpty(), "a key registered elsewhere does not answer");
        assertTrue(alicesKey.assertion(new WebAuthn.Challenge("ch-1", "A".repeat(43), "evil.example"), true).isEmpty(),
                "and alice's key does not answer a look-alike relying party");

        assertTrue(login("alice", "correct horse", alicesKey, IP).isPresent());
        assertTrue(login("alice", "correct horse", SoftwareAuthenticator.register(RP), IP).isEmpty(), "other credential");

        // A copy of the key taken before its last use: its counter goes backwards.
        KeyPair stolen = Ed25519.generateKeyPair();
        SoftwareAuthenticator original = new SoftwareAuthenticator(RP, "cred-x", stolen, 10);
        SoftwareAuthenticator clone = new SoftwareAuthenticator(RP, "cred-x", stolen, 10);
        DevIdentityProvider p = new DevIdentityProvider(UserFile.parse(UserFile.line("carol", "pw".toCharArray(),
                UserFile.MIN_ITERATIONS, "cred-x", stolen.getPublic())), Fixtures.IDP, Fixtures.IDP_KEY_ID, RP, clock,
                (r, s) -> { });
        WebAuthn.Challenge c1 = p.challenge("carol", "d", thumb, IP).orElseThrow();
        assertTrue(p.authenticate(new IdentityProvider.Attempt(c1.challengeId(), "carol", "pw",
                original.assertion(c1, true).orElseThrow()), IP).isPresent());
        WebAuthn.Challenge c2 = p.challenge("carol", "d", thumb, IP).orElseThrow();
        assertTrue(p.authenticate(new IdentityProvider.Attempt(c2.challengeId(), "carol", "pw",
                clone.assertion(c2, true).orElseThrow()), IP).isEmpty(), "counter did not go up: cloned");
    }

    @Test
    void tamperedAssertionsAreRefused() {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        for (int k = 0; k < 10; k++) {
            String ip = "10.0.0." + k;
            WebAuthn.Challenge c = idp.challenge("alice", "laptop-alice", thumb, ip).orElseThrow();
            WebAuthn.Assertion good = alicesKey.assertion(c, true).orElseThrow();
            WebAuthn.Assertion a = switch (k) {
                case 0 -> alicesKey.assertion(c, false).orElseThrow();
                case 1 -> new WebAuthn.Assertion(good.credentialId(), good.authenticatorData(),
                        b64.encodeToString(WebAuthn.clientData(WebAuthn.TYPE_GET, c.challenge(), "https://evil.example")),
                        good.signature());
                case 2 -> new WebAuthn.Assertion(good.credentialId(), good.authenticatorData(),
                        b64.encodeToString(WebAuthn.clientData("webauthn.create", c.challenge(), WebAuthn.origin(RP))),
                        good.signature());
                case 3 -> new WebAuthn.Assertion(good.credentialId(), good.authenticatorData(),
                        b64.encodeToString("[]".getBytes(StandardCharsets.UTF_8)), good.signature());
                case 4 -> new WebAuthn.Assertion(good.credentialId(), good.authenticatorData(),
                        b64.encodeToString(JsonWriter.bytes(JsonValue.object().put("type", WebAuthn.TYPE_GET)
                                .put("challenge", JsonValue.num(1)).put("origin", WebAuthn.origin(RP)).build())),
                        good.signature());
                case 5 -> new WebAuthn.Assertion(good.credentialId(), b64.encodeToString(new byte[5]), good.clientData(),
                        good.signature());
                case 6 -> new WebAuthn.Assertion(good.credentialId(), b64.encodeToString(WebAuthn.authenticatorData(
                        "other.rp", (byte) 5, 99)), good.clientData(), good.signature());
                case 7 -> new WebAuthn.Assertion(good.credentialId(), good.authenticatorData(), good.clientData(),
                        Ed25519.sign(Ed25519.generateKeyPair().getPrivate(), new byte[1]));
                case 8 -> new WebAuthn.Assertion(good.credentialId(), "!!not-base64!!", good.clientData(), good.signature());
                default -> new WebAuthn.Assertion(good.credentialId(), b64.encodeToString(WebAuthn.authenticatorData(RP,
                        WebAuthn.FLAG_USER_VERIFIED, 99)), good.clientData(), good.signature());
            };
            assertTrue(idp.authenticate(new IdentityProvider.Attempt(c.challengeId(), "alice", "correct horse", a), ip)
                    .isEmpty(), "tampering " + k);
        }
        assertTrue(login("alice", "correct horse", alicesKey, IP).isPresent(), "an honest assertion still works");
    }

    @Test
    void failuresLockOutOneSubjectAtOneAddressOnly() {
        for (int i = 0; i < DevIdentityProvider.MAX_FAILURES + 1; i++) {
            assertTrue(login("alice", "guess-" + i, alicesKey, "10.9.9.9").isEmpty());
        }
        assertTrue(login("alice", "correct horse", alicesKey, "10.9.9.9").isEmpty(), "locked at the attacker's address");
        assertTrue(idp.throttled() > 0);
        assertTrue(login("alice", "correct horse", alicesKey, IP).isPresent(), "but alice herself is not locked out");
        clock.advance(DevIdentityProvider.LOCKOUT.plusSeconds(1));
        assertTrue(login("alice", "correct horse", alicesKey, "10.9.9.9").isPresent(), "the lock lapses");

        for (int i = 0; i < 10; i++) {
            assertTrue(login("alice", "correct horse", alicesKey, IP).isPresent(), "own logins never count");
        }
    }

    @Test
    void challengesAreValidatedAndLimitedPerAddress() {
        assertTrue(idp.challenge("alice", "laptop-alice", "nothex", IP).isEmpty());
        assertTrue(idp.challenge("alice", "laptop-alice", "A".repeat(64), IP).isEmpty(), "upper case");
        assertTrue(idp.challenge("al ice", "laptop-alice", thumb, IP).isEmpty());
        assertTrue(idp.challenge(null, "laptop-alice", thumb, IP).isEmpty());
        assertTrue(idp.challenge("alice", "laptop-alice", null, IP).isEmpty());
        assertTrue(idp.challenge("alice", "laptop-alice", thumb, "not an ip").isEmpty());
        for (int i = 0; i < DevIdentityProvider.CHALLENGES_PER_MINUTE; i++) {
            assertTrue(idp.challenge("alice", "d", thumb, "10.1.1.1").isPresent());
        }
        assertTrue(idp.challenge("alice", "d", thumb, "10.1.1.1").isEmpty());
        assertTrue(idp.challenge("alice", "d", thumb, IP).isPresent(), "other addresses unaffected");
    }

    @Test
    void theGlobalChallengeCapStillHoldsAndExpiredOnesMakeRoom() {
        int ips = DevIdentityProvider.MAX_PENDING / DevIdentityProvider.CHALLENGES_PER_MINUTE + 1;
        for (int i = 0; i < ips; i++) {
            for (int j = 0; j < DevIdentityProvider.CHALLENGES_PER_MINUTE; j++) {
                idp.challenge("u", "d", thumb, "10.2." + (i / 250) + "." + (i % 250));
            }
        }
        assertTrue(idp.challenge("alice", "d", thumb, IP).isEmpty(), "full");
        clock.advance(DevIdentityProvider.CHALLENGE_LIFETIME.plusSeconds(1));
        assertTrue(idp.challenge("alice", "d", thumb, IP).isPresent(), "expired challenges are dropped when full");
    }

    @Test
    void aBrokenFailureSinkStillRefusesTheLogin() {
        DevIdentityProvider p = new DevIdentityProvider(UserFile.parse(UserFile.line("alice", "pw".toCharArray(),
                UserFile.MIN_ITERATIONS, alicesKey.credentialId(), alicesKey.publicKey())), Fixtures.IDP,
                Fixtures.IDP_KEY_ID, RP, clock, (r, s) -> {
                    throw new IllegalStateException("receiver down");
                });
        WebAuthn.Challenge c = p.challenge("alice", "d", thumb, IP).orElseThrow();
        assertTrue(p.authenticate(new IdentityProvider.Attempt(c.challengeId(), "alice", "nope",
                alicesKey.assertion(c, true).orElseThrow()), IP).isEmpty());
        assertEquals(1, p.sinkFailures());
        IdentityProvider client = p.forClient(IP);
        assertTrue(client.challenge("alice", "d", thumb).isPresent());
    }

    @Test
    void userFilesAreStrict(@TempDir Path dir) throws Exception {
        String good = UserFile.line("alice", "pw".toCharArray(), UserFile.MIN_ITERATIONS, "cred-1", alicesKey.publicKey());
        String[] f = good.split(" ");
        Path file = dir.resolve("users.txt");
        Files.writeString(file, "# users\n" + good + "\n");
        assertTrue(UserFile.load(file).user("alice").orElseThrow().passwordMatches("pw".toCharArray()));
        assertFalse(UserFile.load(file).user("alice").orElseThrow().passwordMatches("px".toCharArray()));
        assertTrue(UserFile.load(file).user("bob").isEmpty());
        assertEquals(UserFile.MIN_ITERATIONS, UserFile.parse(good).maxIterations());
        assertEquals(UserFile.MIN_ITERATIONS, UserFile.parse("").maxIterations());
        for (String bad : new String[]{good + " extra", good.replace(UserFile.SCHEME, "md5"),
            good.replace(" " + UserFile.MIN_ITERATIONS + " ", " 1000 "), good + "\n" + good,
            String.join(" ", f[0], f[1], f[2], f[3], f[4], f[5], "AAAA"), String.join(" ", f[0], f[1], f[2], "AAAA", f[4], f[5], f[6]),
            String.join(" ", f[0], f[1], "lots", f[3], f[4], f[5], f[6])}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> UserFile.parse(bad));
            assertFalse(e.getMessage().contains(f[4]), "never echoes the hash");
        }
        Files.writeString(dir.resolve("big.txt"), "#".repeat((1 << 20) + 1));
        assertThrows(IllegalArgumentException.class, () -> UserFile.load(dir.resolve("big.txt")));
        assertThrows(IllegalArgumentException.class, () -> UserFile.parse("#".repeat((1 << 20) + 1)));
        char[] pw = "secret".toCharArray();
        UserFile.line("bob", pw, UserFile.MIN_ITERATIONS, "cred-2", alicesKey.publicKey());
        assertArrayEquals(new char[6], pw, "the password array is wiped");
        assertThrows(IllegalArgumentException.class, () -> UserFile.derive(new char[UserFile.MAX_PASSWORD_CHARS + 1],
                new byte[16], UserFile.MIN_ITERATIONS));
    }

    @Test
    void theWireFormatIsStrictBothWays() {
        WebAuthn.Challenge c = idp.challenge("alice", "laptop-alice", thumb, IP).orElseThrow();
        assertEquals(c, IdpWire.readChallenge(reparse(IdpWire.challenge(c))));
        IdpWire.ChallengeRequest req = new IdpWire.ChallengeRequest("alice", "d", thumb);
        assertEquals(req, IdpWire.readChallengeRequest(reparse(IdpWire.challengeRequest(req))));
        IdentityProvider.Attempt a = new IdentityProvider.Attempt(c.challengeId(), "alice", "pw",
                alicesKey.assertion(c, true).orElseThrow());
        assertEquals(a, IdpWire.readAttempt(reparse(IdpWire.attempt(a))));
        assertFalse(a.toString().contains("=pw"), "toString redacts the password");
        IdentityProvider.MfaProof m = login("alice", "correct horse", alicesKey, IP).orElseThrow();
        assertEquals(m, IdpWire.readMfa(reparse(IdpWire.mfa(m))));

        assertThrows(JsonException.class, () -> IdpWire.readChallenge(JsonValue.str("x")));
        assertThrows(JsonException.class, () -> IdpWire.readChallengeRequest(JsonValue.object().put("subjectId", "a").build()));
        assertThrows(JsonException.class, () -> IdpWire.readChallengeRequest(JsonValue.object().put("subjectId", "a")
                .put("deviceId", "d").put("keyThumbprint", JsonValue.num(1)).build()));
        assertThrows(JsonException.class, () -> IdpWire.readChallenge(JsonValue.object().put("challengeId", "a b")
                .put("challenge", "c").put("rpId", "r").build()));
        assertThrows(JsonException.class, () -> IdpWire.readAttempt(JsonValue.object().put("challengeId", "c")
                .put("subjectId", "a b").put("password", "p").put("assertion", JsonValue.object().put("credentialId", "x")
                        .put("authenticatorData", "a").put("clientData", "b").put("signature", "c").build()).build()));
        JsonValue.JObject mj = IdpWire.mfa(m);
        JsonValue.JObject.Builder badMethod = JsonValue.object();
        badMethod.put("authentication", JsonValue.object().put("method", "MAGIC").put("authenticatedAt", "x")
                .put("keyThumbprint", thumb).build()).put("proof", mj.get("proof").orElseThrow());
        assertThrows(JsonException.class, () -> IdpWire.readMfa(badMethod.build()));
        assertThrows(IllegalArgumentException.class, () -> new IdentityProvider.MfaProof(
                new dev.dwarpal.domain.AuthenticationContext(AuthMethod.WEBAUTHN, clock.now()), m.proof()),
                "never unbound");
    }

    @Test
    void recordsRefuseJunk() {
        assertThrows(IllegalArgumentException.class, () -> new WebAuthn.Challenge("c", "short", RP));
        assertThrows(IllegalArgumentException.class, () -> new WebAuthn.Assertion("c", "", "x", "y"));
        assertThrows(IllegalArgumentException.class, () -> new WebAuthn.Assertion("c", "a", "x".repeat(2000), "y"));
        assertThrows(IllegalArgumentException.class, () -> new SoftwareAuthenticator(RP, "c", Ed25519.generateKeyPair(), -1));
        assertThrows(IllegalArgumentException.class,
                () -> new SoftwareAuthenticator(RP, "c", Ed25519.generateKeyPair(), 0xFFFF_FFFFL));
        SoftwareAuthenticator worn = new SoftwareAuthenticator(RP, "c", Ed25519.generateKeyPair(), 0xFFFF_FFFEL);
        assertTrue(worn.assertion(new WebAuthn.Challenge("ch-1", "A".repeat(43), RP), true).isEmpty(), "counter exhausted");
        assertFalse(alicesKey.toString().contains("Private"));
        assertEquals(RP, alicesKey.rpId());
        assertThrows(IllegalArgumentException.class, () -> new UserFile.User("a", UserFile.MIN_ITERATIONS, "AAAA", "AAAA",
                "c", alicesKey.publicKey()));
    }

    private static JsonValue reparse(JsonValue v) {
        return new JsonReader().read(JsonWriter.bytes(v));
    }
}

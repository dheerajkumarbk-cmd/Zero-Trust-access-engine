package dev.dwarpal.oidc;

import dev.dwarpal.oidc.OidcException.Reason;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;

import static dev.dwarpal.oidc.TestTokens.NONCE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OidcVerifierEndToEndTest {

    private static final String[] ALGS = {"RS256", "ES256", "EdDSA"};

    private FakeIdp idp;
    private FakeIdp.TestClock clock;
    private OidcVerifier verifier;

    @BeforeEach
    void start() throws IOException {
        clock = new FakeIdp.TestClock(TestTokens.NOW);
        idp = new FakeIdp(clock);
        OidcHttp http = OidcHttp.forLoopbackTests();
        OidcDiscovery discovery = OidcDiscovery.fetch(idp.issuer(), http);
        verifier = new OidcVerifier(idp.policy(), new JwksSource(discovery, http, clock), clock);
    }

    @AfterEach
    void stop() {
        idp.close();
    }

    private void refused(Reason reason, String token) {
        OidcException e = assertThrows(OidcException.class, () -> verifier.verify(token, NONCE));
        assertEquals(reason, e.reason());
        assertEquals(reason.message(), e.getMessage());
        assertTrue(token.isEmpty() || !e.getMessage().contains(token));
    }

    @Test
    void aTokenFromTheProviderVerifiesForEachAlgorithm() {
        for (String alg : ALGS) {
            VerifiedIdToken v = verifier.verify(idp.mint(alg, NONCE), NONCE);
            assertEquals(alg, v.algorithm());
            assertEquals(idp.issuer(), v.issuer());
            assertEquals(TestTokens.SUBJECT, v.subject());
            assertEquals(idp.signer(alg).kid(), v.keyId());
        }
        assertEquals(1, idp.jwksRequests());
        assertEquals(1, idp.discoveryRequests());
    }

    @Test
    void aTokenSignedByTheNewKeyVerifiesAfterExactlyOneRefresh() {
        verifier.verify(idp.mint("RS256", NONCE), NONCE);
        assertEquals(1, idp.jwksRequests());
        idp.rotate();
        clock.advance(Duration.ofSeconds(31));
        for (String alg : ALGS) {
            assertEquals(idp.signer(alg).kid(), verifier.verify(idp.mint(alg, NONCE), NONCE).keyId());
        }
        assertEquals(2, idp.jwksRequests());
        // the dropped key no longer verifies, and asking again does not fetch again inside 30 s
        refused(Reason.KEY_NOT_FOUND, idp.mint(idp.retiredSigner("RS256"), NONCE));
        assertEquals(2, idp.jwksRequests());
    }

    @Test
    void aRotationInsideThirtySecondsOfTheLastFetchWaitsForTheLimit() {
        verifier.verify(idp.mint("ES256", NONCE), NONCE);
        idp.rotate();
        clock.advance(Duration.ofSeconds(10));
        refused(Reason.KEY_NOT_FOUND, idp.mint("ES256", NONCE));
        assertEquals(1, idp.jwksRequests());
        clock.advance(Duration.ofSeconds(20));
        verifier.verify(idp.mint("ES256", NONCE), NONCE);
        assertEquals(2, idp.jwksRequests());
    }

    @Test
    void aFloodOfUnknownKeyIdsCausesAtMostOneKeyRequestPerThirtySeconds() {
        verifier.verify(idp.mint("RS256", NONCE), NONCE);
        int seconds = 0;
        for (int round = 0; round < 60; round++) {
            for (int i = 0; i < 25; i++) {
                String token = idp.mintWithUnknownKid(ALGS[i % 3], NONCE, "invented-" + round + "-" + i);
                refused(Reason.KEY_NOT_FOUND, token);
            }
            clock.advance(Duration.ofSeconds(5));
            seconds += 5;
        }
        // 295 simulated seconds, 1,500 bad tokens: the first fetch (t=0) and one at each of t=30, 60 ... 270
        assertEquals(10, idp.jwksRequests());
        assertTrue(idp.jwksRequests() <= 1 + seconds / 30);
        assertEquals(1, idp.discoveryRequests());
    }

    @Test
    void otherRefusalsNeverTouchTheNetwork() {
        verifier.verify(idp.mint("RS256", NONCE), NONCE);
        refused(Reason.NONCE_MISMATCH, idp.mint("RS256", "someone-else"));
        refused(Reason.MALFORMED, "a.b");
        refused(Reason.MALFORMED, "");
        assertEquals(1, idp.jwksRequests());
    }

    @Test
    void aTokenWithoutKidIsFoundByAlgorithmWhenTheSetHasOneSuchKey() {
        // the provider's set has one key per algorithm, so a token without kid resolves
        TestTokens.Signer rsa = idp.signer("RS256");
        var header = TestTokens.header(rsa);
        header.remove("kid");
        var claims = TestTokens.claims();
        claims.put("iss", TestTokens.q(idp.issuer()));
        claims.put("nonce", TestTokens.q(NONCE));
        long now = clock.instant().getEpochSecond();
        claims.put("iat", Long.toString(now - 5));
        claims.put("exp", Long.toString(now + 100));
        assertEquals("RS256", verifier.verify(TestTokens.mint(rsa, header, claims), NONCE).algorithm());
    }

    @Test
    void aBlankNonceIsAProgrammingErrorAndFetchesNothing() {
        String token = idp.mint("RS256", NONCE);
        assertThrows(IllegalArgumentException.class, () -> verifier.verify(token, null));
        assertThrows(IllegalArgumentException.class, () -> verifier.verify(token, " "));
        assertEquals(0, idp.jwksRequests());
    }

    @Test
    void anOutageKeepsWorkingOnCachedKeysForUnderAnHourThenFailsClosed() {
        String nonce = NONCE;
        verifier.verify(idp.mint("EdDSA", nonce), nonce);
        idp.jwksStatus(503);
        clock.advance(Duration.ofMinutes(11));
        verifier.verify(idp.mint("EdDSA", nonce), nonce);
        clock.advance(Duration.ofMinutes(48));                        // 59 min since the good fetch
        verifier.verify(idp.mint("RS256", nonce), nonce);
        clock.advance(Duration.ofMinutes(1));                         // 60 min
        refused(Reason.KEYS_UNAVAILABLE, idp.mint("RS256", nonce));
        refused(Reason.KEYS_UNAVAILABLE, idp.mint("EdDSA", nonce));
        // recovery needs only the provider to come back
        idp.jwksStatus(200);
        clock.advance(Duration.ofSeconds(30));
        verifier.verify(idp.mint("ES256", nonce), nonce);
    }

    @Test
    void aPoisonedKeySetDoesNotBreakVerificationOfTokensFromTheGoodKeys() {
        verifier.verify(idp.mint("RS256", NONCE), NONCE);
        idp.jwksBody("{\"keys\":[]}");
        clock.advance(Duration.ofMinutes(11));
        verifier.verify(idp.mint("RS256", NONCE), NONCE);
        idp.jwksBody("garbage");
        clock.advance(Duration.ofMinutes(11));
        verifier.verify(idp.mint("ES256", NONCE), NONCE);
    }

    @Test
    void aTokenWithAnotherIssuerOrKeyTypeIsRefused() {
        // signed by the real key but for another issuer
        var claims = TestTokens.claims();
        long now = clock.instant().getEpochSecond();
        claims.put("iat", Long.toString(now - 5));
        claims.put("exp", Long.toString(now + 100));
        refused(Reason.ISSUER_MISMATCH, TestTokens.mint(idp.signer("RS256"), claims));
        // a key the provider never published
        refused(Reason.KEY_NOT_FOUND, idp.mint(TestTokens.Signer.ec("ec-stranger"), NONCE));
    }

    @Test
    void discoveringOverPlainHttpIsRefusedByTheProductionFactory() {
        assertThrows(IllegalArgumentException.class, () -> OidcVerifier.discover(idp.policy(), clock));
        assertEquals(1, idp.discoveryRequests());                     // only the one made in start()
    }
}

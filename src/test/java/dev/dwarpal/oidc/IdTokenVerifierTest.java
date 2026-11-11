package dev.dwarpal.oidc;

import dev.dwarpal.oidc.OidcException.Reason;
import dev.dwarpal.oidc.TestTokens.Signer;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static dev.dwarpal.oidc.TestTokens.ALL;
import static dev.dwarpal.oidc.TestTokens.CLIENT;
import static dev.dwarpal.oidc.TestTokens.EC_1;
import static dev.dwarpal.oidc.TestTokens.EC_2;
import static dev.dwarpal.oidc.TestTokens.ED_1;
import static dev.dwarpal.oidc.TestTokens.ISSUER;
import static dev.dwarpal.oidc.TestTokens.NONCE;
import static dev.dwarpal.oidc.TestTokens.NOW;
import static dev.dwarpal.oidc.TestTokens.RSA_1;
import static dev.dwarpal.oidc.TestTokens.RSA_2;
import static dev.dwarpal.oidc.TestTokens.SUBJECT;
import static dev.dwarpal.oidc.TestTokens.b64;
import static dev.dwarpal.oidc.TestTokens.claims;
import static dev.dwarpal.oidc.TestTokens.header;
import static dev.dwarpal.oidc.TestTokens.keySet;
import static dev.dwarpal.oidc.TestTokens.mint;
import static dev.dwarpal.oidc.TestTokens.q;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdTokenVerifierTest {

    private static final IdTokenVerifier V = new IdTokenVerifier(TestTokens.policy());
    private static final JwkSet KEYS = keySet(RSA_1, RSA_2, EC_1, EC_2, ED_1);

    private static VerifiedIdToken ok(String token) {
        return V.verify(token, KEYS, NONCE, NOW);
    }

    private static VerifiedIdToken ok(String token, Instant now) {
        return V.verify(token, KEYS, NONCE, now);
    }

    private static void refused(Reason expected, String token) {
        refused(expected, token, KEYS, NOW);
    }

    private static void refused(Reason expected, String token, JwkSet keys, Instant now) {
        OidcException e = assertThrows(OidcException.class, () -> V.verify(token, keys, NONCE, now));
        assertEquals(expected, e.reason());
        assertEquals(expected.message(), e.getMessage());
        assertNull(e.getCause());
        noLeak(e, token);
    }

    /** The message holds nothing of the token, any claim value, or a key id. */
    private static void noLeak(OidcException e, String token) {
        String m = e.getMessage();
        List<String> secrets = new ArrayList<>(List.of(SUBJECT, CLIENT, ISSUER, NONCE, "rsa-1", "ec-1", "ed-1"));
        if (token != null) {
            for (String part : token.split("\\.", -1)) {
                if (part.length() > 6) {
                    secrets.add(part);
                }
            }
        }
        for (String s : secrets) {
            assertFalse(m.contains(s), "the message must not contain " + s.length() + " characters of input");
        }
        assertEquals(0, e.getSuppressed().length);
    }

    private static String[] parts(String token) {
        return token.split("\\.", -1);
    }

    private static String join(String h, String p, String s) {
        return h + "." + p + "." + s;
    }

    private static Map<String, String> with(String key, String rawJson) {
        Map<String, String> c = claims();
        c.put(key, rawJson);
        return c;
    }

    private static Map<String, String> without(String key) {
        Map<String, String> c = claims();
        c.remove(key);
        return c;
    }

    private static String mintWith(Map<String, String> claims) {
        return mint(RSA_1, claims);
    }

    // ---------------------------------------------------------------- happy paths

    @Test
    void anHonestTokenIsAcceptedForEveryAlgorithm() {
        for (Signer s : ALL) {
            VerifiedIdToken t = ok(mint(s));
            assertEquals(SUBJECT, t.subject());
            assertEquals(ISSUER, t.issuer());
            assertEquals(s.alg(), t.algorithm());
            assertEquals(s.kid(), t.keyId());
            assertEquals(NOW.minusSeconds(30), t.issuedAt());
            assertEquals(NOW.plusSeconds(300), t.expiresAt());
            assertEquals("", t.acr());
            assertTrue(t.amr().isEmpty());
            assertTrue(t.authTime().isEmpty());
        }
    }

    @Test
    void optionalClaimsAreReadAndCopied() {
        Map<String, String> c = claims();
        c.put("aud", "[" + q("other") + "," + q(CLIENT) + "]");
        c.put("azp", q(CLIENT));
        c.put("nbf", Long.toString(NOW.getEpochSecond() - 60));
        c.put("auth_time", Long.toString(NOW.getEpochSecond() - 100));
        c.put("acr", q("urn:mace:incommon:iap:silver"));
        c.put("amr", "[\"pwd\",\"otp\",\"hwk-2_x\"]");
        VerifiedIdToken t = ok(mintWith(c));
        assertEquals("urn:mace:incommon:iap:silver", t.acr());
        assertEquals(List.of("pwd", "otp", "hwk-2_x"), t.amr());
        assertEquals(NOW.minusSeconds(100), t.authTime().orElseThrow());
        assertThrows(UnsupportedOperationException.class, () -> t.amr().add("forged"));
    }

    @Test
    void tokenWithoutKidUsesTheOnlyKeyOfTheRightType() {
        for (Signer s : ALL) {
            Map<String, String> h = header(s);
            h.remove("kid");
            JwkSet oneOfEach = keySet(RSA_1, EC_1, ED_1);
            assertEquals(s.kid(), V.verify(mint(s, h, claims()), oneOfEach, NONCE, NOW).keyId());
        }
    }

    @Test
    void headersThatNameAKeyElsewhereAreIgnored() {
        Map<String, String> h = header(EC_1);
        h.put("jku", q("https://evil.example/jwks"));
        h.put("x5u", q("https://evil.example/cert"));
        h.put("x5c", "[\"AAAA\"]");
        h.put("jwk", TestTokens.json(EC_2.jwk()));
        assertEquals("ec-1", ok(mint(EC_1, h, claims())).keyId());
    }

    @Test
    void anAttackerKeyEmbeddedInTheHeaderDoesNotVerify() {
        // signed by EC_2's private key, the header carries EC_2's public key and the kid of the honest EC_1
        Map<String, String> h = header(EC_1);
        h.put("jwk", TestTokens.json(EC_2.jwk()));
        refused(Reason.BAD_SIGNATURE, mint(EC_2, h, claims()), keySet(EC_1), NOW);
    }

    // ---------------------------------------------------------------- ES256 signature format

    @Test
    void es256UsesTheJdkNameThatGivesRawRAndS() throws Exception {
        // SHA256withECDSAinP1363Format makes the 64-byte R||S form that JWS requires
        byte[] input = "header.payload".getBytes(StandardCharsets.US_ASCII);
        assertEquals(64, EC_1.sign(input).length);
        java.security.Signature direct = java.security.Signature.getInstance("SHA256withECDSAinP1363Format");
        direct.initVerify(EC_1.pub());
        direct.update(input);
        assertTrue(direct.verify(EC_1.sign(input)));

        // the same signature made as DER and converted by hand verifies through the verifier too
        Map<String, String> h = header(EC_1);
        String signingInput = b64(TestTokens.json(h)) + "." + b64(TestTokens.json(claims()));
        byte[] der = TestTokens.signEcDer(EC_1, signingInput.getBytes(StandardCharsets.US_ASCII));
        String raw = TestTokens.b64(derToRaw(der));
        assertEquals("ec-1", ok(signingInput + "." + raw).keyId());
    }

    @Test
    void aDerEncodedEs256SignatureIsRefused() {
        String signingInput = b64(TestTokens.json(header(EC_1))) + "." + b64(TestTokens.json(claims()));
        byte[] der = TestTokens.signEcDer(EC_1, signingInput.getBytes(StandardCharsets.US_ASCII));
        assertTrue(der.length != 64);
        refused(Reason.BAD_SIGNATURE, signingInput + "." + TestTokens.b64(der));
    }

    private static byte[] derToRaw(byte[] der) {
        // SEQUENCE { INTEGER r, INTEGER s }, short-form lengths (a P-256 signature is under 128 bytes)
        int pos = 2;
        byte[] out = new byte[64];
        for (int part = 0; part < 2; part++) {
            assertEquals(0x02, der[pos]);
            int len = der[pos + 1] & 0xFF;
            byte[] n = java.util.Arrays.copyOfRange(der, pos + 2, pos + 2 + len);
            int skip = n.length > 32 ? n.length - 32 : 0;
            System.arraycopy(n, skip, out, part * 32 + (32 - (n.length - skip)), n.length - skip);
            pos += 2 + len;
        }
        return out;
    }

    // ---------------------------------------------------------------- algorithm confusion

    @Test
    void algNoneIsRefused() {
        for (String none : List.of("none", "None", "NONE")) {
            Map<String, String> h = new LinkedHashMap<>();
            h.put("alg", q(none));
            refused(Reason.ALG_REFUSED, TestTokens.assemble(h, claims(), ""));
        }
    }

    @Test
    void hs256SignedWithTheRsaPublicKeyIsRefused() {
        refused(Reason.ALG_REFUSED, TestTokens.hs256WithPublicKey(RSA_1.pub(), claims()));
    }

    @Test
    void anAlgorithmOutsideThePolicyListIsRefused() {
        IdTokenVerifier rsOnly = new IdTokenVerifier(
                new OidcPolicy(ISSUER, CLIENT, Set.of("RS256"), Duration.ofMinutes(2), Duration.ofMinutes(10)));
        OidcException e = assertThrows(OidcException.class, () -> rsOnly.verify(mint(EC_1), KEYS, NONCE, NOW));
        assertEquals(Reason.ALG_REFUSED, e.reason());
        assertEquals("rsa-1", rsOnly.verify(mint(RSA_1), KEYS, NONCE, NOW).keyId());
    }

    @Test
    void valuesNobodyAcceptsAreRefused() {
        for (String alg : List.of("PS256", "ES384", "RS512", "HS512", "EdDSA2", "rs256", "")) {
            Map<String, String> h = header(RSA_1);
            h.put("alg", q(alg));
            refused(Reason.ALG_REFUSED, mint(RSA_1, h, claims()));
        }
    }

    @Test
    void aMissingOrOddlyTypedAlgIsRefused() {
        Map<String, String> h = header(RSA_1);
        h.remove("alg");
        refused(Reason.ALG_REFUSED, mint(RSA_1, h, claims()));
        h.put("alg", "256");
        refused(Reason.ALG_REFUSED, mint(RSA_1, h, claims()));
        h.put("alg", "[\"RS256\"]");
        refused(Reason.ALG_REFUSED, mint(RSA_1, h, claims()));
    }

    @Test
    void aCritHeaderRefusesTheToken() {
        Map<String, String> h = header(RSA_1);
        h.put("crit", "[\"exp\"]");
        refused(Reason.ALG_REFUSED, mint(RSA_1, h, claims()));
    }

    @Test
    void aLogoutTokenTypeIsRefused() {
        for (String typ : List.of("logout+jwt", "Logout+JWT", "application/logout+jwt")) {
            Map<String, String> h = header(RSA_1);
            h.put("typ", q(typ));
            refused(Reason.TYPE_REFUSED, mint(RSA_1, h, claims()));
        }
    }

    // ---------------------------------------------------------------- key selection

    @Test
    void aKidPointingAtAnotherKeyFailsTheSignature() {
        Map<String, String> h = header(RSA_2);
        h.put("kid", q("rsa-1"));
        refused(Reason.BAD_SIGNATURE, mint(RSA_2, h, claims()));
    }

    @Test
    void aKeyOfTheSameNameThatIsNotInTheSetFailsTheSignature() {
        Signer impostor = Signer.rsa("rsa-1", 2048);
        refused(Reason.BAD_SIGNATURE, mint(impostor));
    }

    @Test
    void anUnknownKidIsKeyNotFound() {
        Map<String, String> h = header(RSA_1);
        h.put("kid", q("rsa-99"));
        refused(Reason.KEY_NOT_FOUND, mint(RSA_1, h, claims()));
    }

    @Test
    void noKidAndTwoKeysOfTheTypeIsKeyNotFound() {
        Map<String, String> h = header(RSA_1);
        h.remove("kid");
        refused(Reason.KEY_NOT_FOUND, mint(RSA_1, h, claims()), keySet(RSA_1, RSA_2), NOW);
        refused(Reason.KEY_NOT_FOUND, mint(RSA_1, h, claims()), keySet(EC_1), NOW);
    }

    @Test
    void aRsaKeyUnderAnEs256HeaderIsAMismatch() {
        Map<String, String> h = header(EC_1);
        h.put("kid", q("rsa-1"));
        refused(Reason.KEY_MISMATCH, mint(EC_1, h, claims()));
        Map<String, String> h2 = header(RSA_1);
        h2.put("kid", q("ed-1"));
        refused(Reason.KEY_MISMATCH, mint(RSA_1, h2, claims()));
    }

    @Test
    void aKeyThatDeclaresAnotherAlgorithmIsAMismatch() {
        Map<String, String> jwk = RSA_1.jwk();
        jwk.put("alg", q("RS384"));
        JwkSet set = JwkSet.parse(TestTokens.jwks(jwk));
        refused(Reason.KEY_MISMATCH, mint(RSA_1), set, NOW);
        jwk.put("alg", q("RS256"));
        assertEquals("rsa-1", V.verify(mint(RSA_1), JwkSet.parse(TestTokens.jwks(jwk)), NONCE, NOW).keyId());
    }

    @Test
    void aKeyForEncryptionIsAMismatch() {
        Map<String, String> jwk = RSA_1.jwk();
        jwk.put("use", q("enc"));
        refused(Reason.KEY_MISMATCH, mint(RSA_1), JwkSet.parse(TestTokens.jwks(jwk)), NOW);
        jwk.put("use", q("sig"));
        assertEquals("rsa-1", V.verify(mint(RSA_1), JwkSet.parse(TestTokens.jwks(jwk)), NONCE, NOW).keyId());
    }

    // ---------------------------------------------------------------- tampering

    @Test
    void aTamperedPayloadFailsTheSignature() {
        for (Signer s : ALL) {
            String[] p = parts(mint(s));
            Map<String, String> evil = claims();
            evil.put("sub", q("admin"));
            refused(Reason.BAD_SIGNATURE, join(p[0], b64(TestTokens.json(evil)), p[2]));
        }
    }

    @Test
    void aTamperedHeaderFailsTheSignature() {
        String[] p = parts(mint(RSA_1));
        Map<String, String> h = header(RSA_1);
        h.put("typ", q("at+jwt"));
        refused(Reason.BAD_SIGNATURE, join(b64(TestTokens.json(h)), p[1], p[2]));
    }

    @Test
    void aTamperedOrShortenedSignatureFails() {
        for (Signer s : ALL) {
            String[] p = parts(mint(s));
            byte[] sig = Base64.getUrlDecoder().decode(p[2]);
            sig[sig.length / 2] ^= 0x01;
            refused(Reason.BAD_SIGNATURE, join(p[0], p[1], TestTokens.b64(sig)));
            byte[] shorter = java.util.Arrays.copyOf(Base64.getUrlDecoder().decode(p[2]), sig.length - 3);
            refused(Reason.BAD_SIGNATURE, join(p[0], p[1], TestTokens.b64(shorter)));
            byte[] longer = java.util.Arrays.copyOf(Base64.getUrlDecoder().decode(p[2]), sig.length + 3);
            refused(Reason.BAD_SIGNATURE, join(p[0], p[1], TestTokens.b64(longer)));
            refused(Reason.BAD_SIGNATURE, join(p[0], p[1], ""));
        }
    }

    // ---------------------------------------------------------------- shape

    @Test
    void aFivePartTokenIsMalformed() {
        String[] p = parts(mint(RSA_1));
        refused(Reason.MALFORMED, String.join(".", p[0], "AAAA", "AAAA", "AAAA", p[2]));
    }

    @Test
    void tokensWithTheWrongNumberOfPartsAreMalformed() {
        String[] p = parts(mint(RSA_1));
        refused(Reason.MALFORMED, p[0] + "." + p[1]);
        refused(Reason.MALFORMED, p[0]);
        refused(Reason.MALFORMED, "");
        refused(Reason.MALFORMED, "..");
        refused(Reason.MALFORMED, join(p[0], "", p[2]));
        refused(Reason.MALFORMED, join("", p[1], p[2]));
        OidcException e = assertThrows(OidcException.class, () -> V.verify(null, KEYS, NONCE, NOW));
        assertEquals(Reason.MALFORMED, e.reason());
    }

    @Test
    void aTokenOverSixteenKibIsMalformed() {
        Map<String, String> c = claims();
        c.put("pad", q("a".repeat(IdTokenVerifier.MAX_TOKEN_CHARS)));
        refused(Reason.MALFORMED, mintWith(c));
    }

    @Test
    void charactersOutsideBase64urlAreMalformed() {
        String[] p = parts(mint(RSA_1));
        for (String bad : List.of("+", "/", "!", " ", "\n", "=", "é", "%41")) {
            refused(Reason.MALFORMED, join(p[0], p[1] + bad, p[2]));
            refused(Reason.MALFORMED, join(bad + p[0], p[1], p[2]));
            refused(Reason.MALFORMED, join(p[0], p[1], p[2] + bad));
        }
    }

    @Test
    void paddingIsMalformed() {
        // a payload whose length is not a multiple of 4 gets padded by a standard encoder
        String payload = TestTokens.json(claims());
        while (Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                .length() % 4 == 0) {
            payload = payload.replace("{", "{ ");
        }
        String padded = Base64.getUrlEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        assertTrue(padded.endsWith("="));
        String[] p = parts(mint(RSA_1));
        refused(Reason.MALFORMED, join(p[0], padded, p[2]));
    }

    @Test
    void nonCanonicalTrailingBitsAreMalformed() {
        // the last character of an unpadded 64-byte signature carries 4 spare bits; 'A' -> 'B' sets one
        String[] p = parts(mint(EC_1));
        String sig = p[2];
        char last = sig.charAt(sig.length() - 1);
        char altered = last == 'A' ? 'B' : (char) (last ^ 0x01);
        refused(Reason.MALFORMED, join(p[0], p[1], sig.substring(0, sig.length() - 1) + altered));
    }

    @Test
    void headerAndPayloadMustBeJsonObjects() {
        for (String notObject : List.of("[1,2]", "\"text\"", "123", "null", "true", "not json", "{\"a\":1}x", "")) {
            refused(Reason.MALFORMED, TestTokens.mintRaw(RSA_1, notObject, TestTokens.json(claims())));
            refused(Reason.MALFORMED, TestTokens.mintRaw(RSA_1, TestTokens.json(header(RSA_1)), notObject));
        }
    }

    @Test
    void duplicateMembersInThePayloadAreMalformed() {
        String payload = "{\"iss\":\"a\",\"iss\":\"b\"}";
        refused(Reason.MALFORMED, TestTokens.mintRaw(RSA_1, TestTokens.json(header(RSA_1)), payload));
    }

    @Test
    void nonStringKidOrTypIsMalformed() {
        Map<String, String> h = header(RSA_1);
        h.put("kid", "5");
        refused(Reason.MALFORMED, mint(RSA_1, h, claims()));
        Map<String, String> h2 = header(RSA_1);
        h2.put("typ", "[]");
        refused(Reason.MALFORMED, mint(RSA_1, h2, claims()));
    }

    // ---------------------------------------------------------------- issuer, audience

    @Test
    void theIssuerMustMatchExactly() {
        for (String iss : List.of(ISSUER + "/", ISSUER.toUpperCase(java.util.Locale.ROOT), "https://idp.example.test:443",
                "https://evil.example.test", ISSUER + " ", "")) {
            refused(Reason.ISSUER_MISMATCH, mintWith(with("iss", q(iss))));
        }
        refused(Reason.CLAIM_INVALID, mintWith(without("iss")));
        refused(Reason.CLAIM_INVALID, mintWith(with("iss", "5")));
        refused(Reason.CLAIM_INVALID, mintWith(with("iss", "[\"" + ISSUER + "\"]")));
    }

    @Test
    void theAudienceMustNameThisClient() {
        refused(Reason.AUDIENCE_MISMATCH, mintWith(with("aud", q("someone-else"))));
        refused(Reason.AUDIENCE_MISMATCH, mintWith(with("aud", q(CLIENT + "x"))));
        refused(Reason.AUDIENCE_MISMATCH, mintWith(with("aud", "[\"a\",\"b\"]")));
        refused(Reason.CLAIM_INVALID, mintWith(without("aud")));
        refused(Reason.CLAIM_INVALID, mintWith(with("aud", "5")));
        refused(Reason.CLAIM_INVALID, mintWith(with("aud", "[]")));
        refused(Reason.CLAIM_INVALID, mintWith(with("aud", "[\"" + CLIENT + "\",7]")));
    }

    @Test
    void anAudienceArrayNeedsAnAuthorisedParty() {
        Map<String, String> c = with("aud", "[" + q(CLIENT) + "," + q("other") + "]");
        refused(Reason.AUDIENCE_MISMATCH, mintWith(c));
        c.put("azp", q("other"));
        refused(Reason.AUDIENCE_MISMATCH, mintWith(c));
        c.put("azp", q(CLIENT));
        assertEquals(SUBJECT, ok(mintWith(c)).subject());
    }

    @Test
    void anAuthorisedPartyThatIsNotThisClientIsRefusedEvenForASingleAudience() {
        refused(Reason.AUDIENCE_MISMATCH, mintWith(with("azp", q("other"))));
        refused(Reason.CLAIM_INVALID, mintWith(with("azp", "3")));
        assertEquals(SUBJECT, ok(mintWith(with("azp", q(CLIENT)))).subject());
    }

    // ---------------------------------------------------------------- time

    @Test
    void anExpiredTokenIsRefusedJustOutsideTheSkewAndAcceptedJustInside() {
        long exp = NOW.getEpochSecond() + 300;
        String token = mintWith(claims());
        Instant limit = Instant.ofEpochSecond(exp).plus(Duration.ofMinutes(2));
        assertEquals(SUBJECT, ok(token, limit.minusSeconds(1)).subject());
        refused(Reason.EXPIRED, token, KEYS, limit);
        refused(Reason.EXPIRED, token, KEYS, limit.plusSeconds(1));
    }

    @Test
    void anIssueTimeInTheFutureIsRefusedBeyondTheSkew() {
        long now = NOW.getEpochSecond();
        assertEquals(SUBJECT, ok(mintWith(with("iat", Long.toString(now + 120)))).subject());
        refused(Reason.NOT_YET_VALID, mintWith(with("iat", Long.toString(now + 121))));
    }

    @Test
    void aTokenIssuedLongAgoIsTooOld() {
        long now = NOW.getEpochSecond();
        Map<String, String> c = with("iat", Long.toString(now - 600));
        c.put("exp", Long.toString(now + 600));
        assertEquals(SUBJECT, ok(mintWith(c)).subject());
        c.put("iat", Long.toString(now - 601));
        refused(Reason.TOO_OLD, mintWith(c));
    }

    @Test
    void notBeforeInTheFutureIsRefusedBeyondTheSkew() {
        long now = NOW.getEpochSecond();
        assertEquals(SUBJECT, ok(mintWith(with("nbf", Long.toString(now + 120)))).subject());
        refused(Reason.NOT_YET_VALID, mintWith(with("nbf", Long.toString(now + 121))));
        refused(Reason.CLAIM_INVALID, mintWith(with("nbf", "1.5")));
    }

    @Test
    void expIatAndSubAreRequired() {
        refused(Reason.CLAIM_INVALID, mintWith(without("exp")));
        refused(Reason.CLAIM_INVALID, mintWith(without("iat")));
        refused(Reason.CLAIM_INVALID, mintWith(without("sub")));
    }

    @Test
    void timesMustBeWholeNumbersInASaneRange() {
        List<String> bad = List.of("1780000000.5", "1780000000.0", "1.78e9", "1780000000e0", "\"1780000000\"",
                "-1", "99999999999", "99999999999999999999", "true", "null", "[1]");
        for (String value : bad) {
            refused(Reason.CLAIM_INVALID, mintWith(with("exp", value)));
            refused(Reason.CLAIM_INVALID, mintWith(with("iat", value)));
        }
    }

    // ---------------------------------------------------------------- subject, nonce

    @Test
    void theSubjectIsOneToTwoHundredFiftyFivePrintableAsciiCharacters() {
        assertEquals("s".repeat(255), ok(mintWith(with("sub", q("s".repeat(255))))).subject());
        refused(Reason.CLAIM_INVALID, mintWith(with("sub", q("s".repeat(256)))));
        refused(Reason.CLAIM_INVALID, mintWith(with("sub", q(""))));
        refused(Reason.CLAIM_INVALID, mintWith(with("sub", q("usér"))));
        refused(Reason.CLAIM_INVALID, mintWith(with("sub", q("a\\u0007b"))));
        refused(Reason.CLAIM_INVALID, mintWith(with("sub", q("a\\nb"))));
        refused(Reason.CLAIM_INVALID, mintWith(with("sub", "42")));
    }

    @Test
    void theNonceMustBePresentAndEqual() {
        refused(Reason.NONCE_MISMATCH, mintWith(without("nonce")));
        refused(Reason.NONCE_MISMATCH, mintWith(with("nonce", q("other"))));
        refused(Reason.NONCE_MISMATCH, mintWith(with("nonce", q(NONCE + "x"))));
        refused(Reason.NONCE_MISMATCH, mintWith(with("nonce", q(NONCE.substring(1)))));
        refused(Reason.NONCE_MISMATCH, mintWith(with("nonce", q(NONCE.toUpperCase(java.util.Locale.ROOT)))));
        refused(Reason.CLAIM_INVALID, mintWith(with("nonce", "5")));
    }

    @Test
    void aMissingExpectedNonceIsAProgrammingError() {
        String token = mintWith(claims());
        assertThrows(IllegalArgumentException.class, () -> V.verify(token, KEYS, null, NOW));
        assertThrows(IllegalArgumentException.class, () -> V.verify(token, KEYS, "", NOW));
        assertThrows(IllegalArgumentException.class, () -> V.verify(token, KEYS, "   ", NOW));
    }

    // ---------------------------------------------------------------- auth time, acr, amr

    @Test
    void authenticationAgeIsCheckedOnlyWhenTheCallerAsks() {
        long now = NOW.getEpochSecond();
        Duration max = Duration.ofMinutes(5);
        String recent = mintWith(with("auth_time", Long.toString(now - 300)));
        assertEquals(SUBJECT, V.verify(recent, KEYS, NONCE, NOW, max).subject());
        refused(Reason.TOO_OLD, mintWith(with("auth_time", Long.toString(now - 301))), KEYS, NOW, max);
        OidcException missing = assertThrows(OidcException.class,
                () -> V.verify(mintWith(claims()), KEYS, NONCE, NOW, max));
        assertEquals(Reason.CLAIM_INVALID, missing.reason());
        // without a limit, an old or missing auth_time is accepted
        assertEquals(SUBJECT, ok(mintWith(with("auth_time", "1000"))).subject());
        assertEquals(SUBJECT, ok(mintWith(claims())).subject());
        refused(Reason.NOT_YET_VALID, mintWith(with("auth_time", Long.toString(now + 121))));
        refused(Reason.CLAIM_INVALID, mintWith(with("auth_time", "1.5")));
    }

    private static void refused(Reason expected, String token, JwkSet keys, Instant now, Duration maxAuthAge) {
        OidcException e = assertThrows(OidcException.class, () -> V.verify(token, keys, NONCE, now, maxAuthAge));
        assertEquals(expected, e.reason());
        noLeak(e, token);
    }

    @Test
    void acrIsAtMostOneHundredTwentyEightPrintableCharacters() {
        assertEquals("a".repeat(128), ok(mintWith(with("acr", q("a".repeat(128))))).acr());
        refused(Reason.CLAIM_INVALID, mintWith(with("acr", q("a".repeat(129)))));
        refused(Reason.CLAIM_INVALID, mintWith(with("acr", q("é"))));
        refused(Reason.CLAIM_INVALID, mintWith(with("acr", "1")));
    }

    @Test
    void amrIsAtMostSixteenShortSafeStrings() {
        List<String> sixteen = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            sixteen.add(q("m" + i));
        }
        assertEquals(16, ok(mintWith(with("amr", "[" + String.join(",", sixteen) + "]"))).amr().size());
        sixteen.add(q("m16"));
        refused(Reason.CLAIM_INVALID, mintWith(with("amr", "[" + String.join(",", sixteen) + "]")));
        refused(Reason.CLAIM_INVALID, mintWith(with("amr", "[" + q("a".repeat(65)) + "]")));
        refused(Reason.CLAIM_INVALID, mintWith(with("amr", "[" + q("has space") + "]")));
        refused(Reason.CLAIM_INVALID, mintWith(with("amr", "[" + q("") + "]")));
        refused(Reason.CLAIM_INVALID, mintWith(with("amr", "[5]")));
        refused(Reason.CLAIM_INVALID, mintWith(with("amr", q("pwd"))));
    }

    // ---------------------------------------------------------------- the claims are not trusted before the signature

    @Test
    void aBadSignatureWinsOverEveryClaimProblem() {
        Map<String, String> c = claims();
        c.put("iss", q("https://evil.example"));
        c.put("exp", "1");
        String[] p = parts(mint(RSA_1, c));
        // a tampered signature on a token with bad claims still reports only the signature
        byte[] sig = Base64.getUrlDecoder().decode(p[2]);
        sig[0] ^= 0x40;
        refused(Reason.BAD_SIGNATURE, join(p[0], p[1], TestTokens.b64(sig)));
    }

    @Test
    void policyIsRequiredToBeSane() {
        assertThrows(IllegalArgumentException.class,
                () -> new OidcPolicy(ISSUER, CLIENT, Set.of("HS256"), Duration.ofMinutes(2), Duration.ofMinutes(10)));
        assertThrows(IllegalArgumentException.class,
                () -> new OidcPolicy(ISSUER, CLIENT, Set.of("RS256", "HS256"), Duration.ofMinutes(2), Duration.ofMinutes(10)));
        assertThrows(IllegalArgumentException.class,
                () -> new OidcPolicy(ISSUER, CLIENT, Set.of("none"), Duration.ofMinutes(2), Duration.ofMinutes(10)));
        assertThrows(IllegalArgumentException.class,
                () -> new OidcPolicy(ISSUER, CLIENT, Set.of(), Duration.ofMinutes(2), Duration.ofMinutes(10)));
        assertThrows(IllegalArgumentException.class, () -> OidcPolicy.of("", CLIENT));
        assertThrows(IllegalArgumentException.class, () -> OidcPolicy.of(ISSUER, " "));
        assertThrows(IllegalArgumentException.class,
                () -> new OidcPolicy(ISSUER, CLIENT, Set.of("RS256"), Duration.ofMinutes(6), Duration.ofMinutes(10)));
        assertThrows(IllegalArgumentException.class,
                () -> new OidcPolicy(ISSUER, CLIENT, Set.of("RS256"), Duration.ofMinutes(-1), Duration.ofMinutes(10)));
        assertThrows(IllegalArgumentException.class,
                () -> new OidcPolicy(ISSUER, CLIENT, Set.of("RS256"), Duration.ofMinutes(2), Duration.ofDays(2)));
        OidcPolicy d = OidcPolicy.of(ISSUER, CLIENT);
        assertEquals(Duration.ofMinutes(2), d.skew());
        assertEquals(Duration.ofMinutes(10), d.maxTokenAge());
        assertEquals(Set.of("RS256", "ES256", "EdDSA"), d.algorithms());
        assertThrows(UnsupportedOperationException.class, () -> d.algorithms().add("HS256"));
    }
}

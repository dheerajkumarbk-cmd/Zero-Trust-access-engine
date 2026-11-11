package dev.dwarpal.oidc;

import dev.dwarpal.oidc.OidcException.Reason;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static dev.dwarpal.oidc.TestTokens.EC_1;
import static dev.dwarpal.oidc.TestTokens.ED_1;
import static dev.dwarpal.oidc.TestTokens.RSA_1;
import static dev.dwarpal.oidc.TestTokens.b64;
import static dev.dwarpal.oidc.TestTokens.jwks;
import static dev.dwarpal.oidc.TestTokens.q;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwkSetTest {

    private static void invalid(String json) {
        OidcException e = assertThrows(OidcException.class, () -> JwkSet.parse(json));
        assertEquals(Reason.KEYS_INVALID, e.reason());
        assertEquals(Reason.KEYS_INVALID.message(), e.getMessage());
        assertTrue(json.length() < 100 || !e.getMessage().contains(json.substring(20, 60)));
    }

    private static Map<String, String> oct(String kid) {
        Map<String, String> m = new java.util.LinkedHashMap<>();
        m.put("kty", q("oct"));
        m.put("kid", q(kid));
        m.put("k", q(b64("shared-secret-bytes-0123456789abcdef")));
        return m;
    }

    @Test
    void theThreeUsableKeyTypesAreRead() {
        JwkSet set = JwkSet.parse(jwks(List.of(RSA_1.jwk(), EC_1.jwk(), ED_1.jwk())));
        assertEquals(3, set.size());
        assertEquals(Jwk.Type.RSA, set.find("rsa-1").orElseThrow().type());
        assertEquals(Jwk.Type.EC_P256, set.find("ec-1").orElseThrow().type());
        assertEquals(Jwk.Type.OKP_ED25519, set.find("ed-1").orElseThrow().type());
        assertEquals("ES256", set.find("ec-1").orElseThrow().type().algorithm());
        assertTrue(set.find("nope").isEmpty());
    }

    @Test
    void parsingFromBytesGivesTheSameSet() {
        String json = jwks(List.of(RSA_1.jwk()));
        assertEquals(1, JwkSet.parse(json.getBytes(StandardCharsets.UTF_8)).size());
    }

    @Test
    void aSymmetricKeyIsSkippedAndNeverUsable() {
        JwkSet set = JwkSet.parse(jwks(List.of(oct("hmac-1"), RSA_1.jwk())));
        assertEquals(1, set.size());
        assertTrue(set.find("hmac-1").isEmpty());
        // even with a kid that matches, the oct key cannot be chosen for any algorithm
        for (String alg : List.of("RS256", "ES256", "EdDSA", "HS256")) {
            assertThrows(OidcException.class, () -> set.select("hmac-1", alg));
        }
        assertEquals(0, JwkSet.parse(jwks(List.of(oct("a"), oct("a")))).size());
    }

    @Test
    void otherKeyTypesAndCurvesAreSkipped() {
        String p384 = "{\"kty\":\"EC\",\"kid\":\"p384\",\"crv\":\"P-384\",\"x\":\"AA\",\"y\":\"AA\"}";
        String ed448 = "{\"kty\":\"OKP\",\"kid\":\"ed448\",\"crv\":\"Ed448\",\"x\":\"AA\"}";
        String x25519 = "{\"kty\":\"OKP\",\"kid\":\"x\",\"crv\":\"X25519\",\"x\":\"AA\"}";
        String unknown = "{\"kty\":\"AKP\",\"kid\":\"pq\"}";
        String noKty = "{\"kid\":\"nothing\"}";
        JwkSet set = JwkSet.parse("{\"keys\":[" + String.join(",", p384, ed448, x25519, unknown, noKty) + "]}");
        assertEquals(0, set.size());
    }

    @Test
    void twoKeysWithTheSameKidRefuseTheWholeSet() {
        Map<String, String> other = RSA_1.jwk();
        invalid(jwks(List.of(RSA_1.jwk(), other)));
        Map<String, String> ec = EC_1.jwk();
        ec.put("kid", q("rsa-1"));
        invalid(jwks(List.of(RSA_1.jwk(), ec)));
    }

    @Test
    void keysWithoutKidDoNotCollide() {
        Map<String, String> a = RSA_1.jwk();
        a.remove("kid");
        Map<String, String> b = EC_1.jwk();
        b.remove("kid");
        assertEquals(2, JwkSet.parse(jwks(List.of(a, b))).size());
    }

    @Test
    void atMostTwentyKeys() {
        List<Map<String, String>> keys = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            Map<String, String> k = ED_1.jwk();
            k.put("kid", q("k" + i));
            keys.add(k);
        }
        assertEquals(20, JwkSet.parse(jwks(keys)).size());
        Map<String, String> extra = ED_1.jwk();
        extra.put("kid", q("k20"));
        keys.add(extra);
        invalid(jwks(keys));
    }

    @Test
    void inputOverTwoHundredFiftySixKibIsRefused() {
        String pad = "x".repeat(JwkSet.MAX_BYTES);
        invalid("{\"keys\":[],\"pad\":\"" + pad + "\"}");
        OidcException e = assertThrows(OidcException.class, () -> JwkSet.parse(new byte[JwkSet.MAX_BYTES + 1]));
        assertEquals(Reason.KEYS_INVALID, e.reason());
        assertThrows(OidcException.class, () -> JwkSet.parse((String) null));
    }

    @Test
    void documentsThatAreNotAKeySetAreRefused() {
        invalid("");
        invalid("not json");
        invalid("[]");
        invalid("{}");
        invalid("{\"keys\":{}}");
        invalid("{\"keys\":[1]}");
        invalid("{\"keys\":[[]]}");
        invalid("{\"keys\":[],\"keys\":[]}");
        invalid("{\"keys\":[{\"kty\":5}]}");
    }

    @Test
    void anEmptySetIsValidButHasNoKeys() {
        assertEquals(0, JwkSet.parse("{\"keys\":[]}").size());
    }

    @Test
    void identifiersMustBeStringsOfSaneLength() {
        Map<String, String> k = RSA_1.jwk();
        k.put("kid", "7");
        invalid(jwks(k));
        k.put("kid", q(""));
        invalid(jwks(k));
        k.put("kid", q("k".repeat(257)));
        invalid(jwks(k));
        Map<String, String> k2 = RSA_1.jwk();
        k2.put("alg", "[]");
        invalid(jwks(k2));
    }

    // ---------------------------------------------------------------- RSA

    @Test
    void aOneThousandTwentyFourBitRsaKeyIsRefused() {
        TestTokens.Signer weak = TestTokens.Signer.rsa("weak", 1024);
        invalid(jwks(weak.jwk()));
        TestTokens.Signer fine = TestTokens.Signer.rsa("fine", 2048);
        assertEquals(1, JwkSet.parse(jwks(fine.jwk())).size());
    }

    @Test
    void anRsaKeyNeedsASaneModulusAndExponent() {
        Map<String, String> k = RSA_1.jwk();
        k.put("e", q(b64(new byte[]{2})));            // even exponent
        invalid(jwks(k));
        k.put("e", q(b64(new byte[]{1})));            // exponent 1
        invalid(jwks(k));
        k.put("e", q(b64(new byte[]{1, 0, 0, 0, 0, 1})));   // 41 bits
        invalid(jwks(k));
        k.put("e", q(b64(new byte[]{3})));            // 3 is allowed with a large modulus
        assertEquals(1, JwkSet.parse(jwks(k)).size());

        Map<String, String> even = RSA_1.jwk();
        byte[] n = TestTokens.unsigned(((java.security.interfaces.RSAPublicKey) RSA_1.pub()).getModulus(), -1);
        n[n.length - 1] &= (byte) 0xFE;
        even.put("n", q(b64(n)));
        invalid(jwks(even));

        Map<String, String> missing = RSA_1.jwk();
        missing.remove("e");
        invalid(jwks(missing));
        Map<String, String> notBase64 = RSA_1.jwk();
        notBase64.put("n", q("!!!"));
        invalid(jwks(notBase64));
    }

    // ---------------------------------------------------------------- EC

    @Test
    void anEcPointOffTheCurveIsRefused() {
        // the JDK's KeyFactory accepts such a point without complaint, so the verifier checks the curve itself
        BigInteger y = ((ECPublicKey) EC_1.pub()).getW().getAffineY();
        Map<String, String> k = EC_1.jwk();
        k.put("y", q(b64(TestTokens.unsigned(y.add(BigInteger.ONE), 32))));
        invalid(jwks(k));
        BigInteger x = ((ECPublicKey) EC_1.pub()).getW().getAffineX();
        Map<String, String> k2 = EC_1.jwk();
        k2.put("x", q(b64(TestTokens.unsigned(x.add(BigInteger.ONE), 32))));
        invalid(jwks(k2));
        // the point at (0, 0) and a point with coordinates not below the field prime
        Map<String, String> zero = EC_1.jwk();
        zero.put("x", q(b64(new byte[32])));
        zero.put("y", q(b64(new byte[32])));
        invalid(jwks(zero));
        byte[] big = new byte[32];
        java.util.Arrays.fill(big, (byte) 0xFF);
        Map<String, String> huge = EC_1.jwk();
        huge.put("x", q(b64(big)));
        invalid(jwks(huge));
    }

    @Test
    void ecCoordinatesMustBeThirtyTwoBytes() {
        Map<String, String> k = EC_1.jwk();
        k.put("x", q(b64(new byte[31])));
        invalid(jwks(k));
        Map<String, String> k2 = EC_1.jwk();
        k2.put("y", q(b64(new byte[33])));
        invalid(jwks(k2));
        Map<String, String> k3 = EC_1.jwk();
        k3.remove("y");
        invalid(jwks(k3));
    }

    // ---------------------------------------------------------------- Ed25519

    @Test
    void ed25519KeysMustBeThirtyTwoBytesOnTheCurve() {
        Map<String, String> k = ED_1.jwk();
        k.put("x", q(b64(new byte[31])));
        invalid(jwks(k));
        Map<String, String> k2 = ED_1.jwk();
        k2.put("x", q(b64(new byte[33])));
        invalid(jwks(k2));
        // y = 2^255 - 1 is not below the field prime
        byte[] big = new byte[32];
        java.util.Arrays.fill(big, (byte) 0xFF);
        big[31] = 0x7F;
        Map<String, String> k3 = ED_1.jwk();
        k3.put("x", q(b64(big)));
        invalid(jwks(k3));
        // about half of all y values have no matching x: some small ones must be refused, some accepted
        int accepted = 0;
        int refused = 0;
        for (int y = 2; y < 60; y++) {
            byte[] enc = new byte[32];
            enc[0] = (byte) y;
            Map<String, String> k4 = ED_1.jwk();
            k4.put("x", q(b64(enc)));
            try {
                JwkSet.parse(jwks(k4));
                accepted++;
            } catch (OidcException e) {
                refused++;
            }
        }
        assertTrue(accepted > 0 && refused > 0);
    }

    @Test
    void theSignBitOfTheEdwardsEncodingIsHonoured() {
        // an honest key still verifies after parsing: bit 255 (the parity of x) went into the key
        JwkSet set = JwkSet.parse(jwks(List.of(ED_1.jwk())));
        String token = TestTokens.mint(ED_1);
        IdTokenVerifier v = new IdTokenVerifier(TestTokens.policy());
        assertEquals("ed-1", v.verify(token, set, TestTokens.NONCE, TestTokens.NOW).keyId());
        // flipping the sign bit gives a different key: the signature no longer verifies (or the key is refused)
        Map<String, String> flipped = ED_1.jwk();
        byte[] x = java.util.Base64.getUrlDecoder().decode(flipped.get("x").replace("\"", ""));
        x[31] ^= (byte) 0x80;
        flipped.put("x", q(b64(x)));
        try {
            JwkSet other = JwkSet.parse(jwks(flipped));
            OidcException e = assertThrows(OidcException.class,
                    () -> v.verify(token, other, TestTokens.NONCE, TestTokens.NOW));
            assertEquals(Reason.BAD_SIGNATURE, e.reason());
        } catch (OidcException refusedKey) {
            assertEquals(Reason.KEYS_INVALID, refusedKey.reason());
        }
        assertFalse(set.find("ed-1").isEmpty());
    }
}

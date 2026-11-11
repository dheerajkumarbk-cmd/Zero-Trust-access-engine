package dev.dwarpal.oidc;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Test helper: JDK-generated keys and a tiny token minter. Header, claims and JWK members are plain maps from
 * name to raw JSON text, so a test can put a float, remove a member or add a wrong one.
 */
final class TestTokens {

    static final String ISSUER = "https://idp.example.test";
    static final String CLIENT = "client-abc";
    static final String NONCE = "nonce-8f3a";
    static final String SUBJECT = "user-1234";
    static final Instant NOW = Instant.parse("2026-06-01T12:00:00Z");

    static final Signer RSA_1 = Signer.rsa("rsa-1", 2048);
    static final Signer RSA_2 = Signer.rsa("rsa-2", 2048);
    static final Signer EC_1 = Signer.ec("ec-1");
    static final Signer EC_2 = Signer.ec("ec-2");
    static final Signer ED_1 = Signer.ed("ed-1");
    static final Signer ED_2 = Signer.ed("ed-2");
    static final Signer[] ALL = {RSA_1, EC_1, ED_1};

    private TestTokens() {
    }

    /** A key pair with the JWS algorithm it signs with. */
    record Signer(String kid, String alg, PrivateKey priv, PublicKey pub) {

        static Signer rsa(String kid, int bits) {
            KeyPair kp = generate("RSA", bits, null);
            return new Signer(kid, "RS256", kp.getPrivate(), kp.getPublic());
        }

        static Signer ec(String kid) {
            KeyPair kp = generate("EC", 0, "secp256r1");
            return new Signer(kid, "ES256", kp.getPrivate(), kp.getPublic());
        }

        static Signer ed(String kid) {
            KeyPair kp = generate("Ed25519", 0, null);
            return new Signer(kid, "EdDSA", kp.getPrivate(), kp.getPublic());
        }

        private static KeyPair generate(String type, int bits, String curve) {
            try {
                KeyPairGenerator g = KeyPairGenerator.getInstance(type);
                if (curve != null) {
                    g.initialize(new ECGenParameterSpec(curve));
                } else if (bits > 0) {
                    g.initialize(bits);
                }
                return g.generateKeyPair();
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }

        /** The JWK members of this key's public half (kid and the key material). */
        Map<String, String> jwk() {
            Map<String, String> m = new LinkedHashMap<>();
            if (pub instanceof RSAPublicKey r) {
                m.put("kty", q("RSA"));
                m.put("kid", q(kid));
                m.put("n", q(b64(unsigned(r.getModulus(), -1))));
                m.put("e", q(b64(unsigned(r.getPublicExponent(), -1))));
            } else if (pub instanceof ECPublicKey e) {
                m.put("kty", q("EC"));
                m.put("kid", q(kid));
                m.put("crv", q("P-256"));
                m.put("x", q(b64(unsigned(e.getW().getAffineX(), 32))));
                m.put("y", q(b64(unsigned(e.getW().getAffineY(), 32))));
            } else if (pub instanceof EdECPublicKey d) {
                byte[] little = new byte[32];
                byte[] bigEndianY = unsigned(d.getPoint().getY(), 32);
                for (int i = 0; i < 32; i++) {
                    little[i] = bigEndianY[31 - i];
                }
                if (d.getPoint().isXOdd()) {
                    little[31] |= (byte) 0x80;
                }
                m.put("kty", q("OKP"));
                m.put("kid", q(kid));
                m.put("crv", q("Ed25519"));
                m.put("x", q(b64(little)));
            }
            return m;
        }

        /** Signs in the format JWS uses for this algorithm (ES256 as raw R||S). */
        byte[] sign(byte[] input) {
            try {
                Signature s = Signature.getInstance(switch (alg) {
                    case "RS256" -> "SHA256withRSA";
                    case "ES256" -> "SHA256withECDSAinP1363Format";
                    default -> "Ed25519";
                });
                s.initSign(priv);
                s.update(input);
                return s.sign();
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    static String q(String s) {
        return "\"" + s + "\"";
    }

    static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static String b64(String s) {
        return b64(s.getBytes(StandardCharsets.UTF_8));
    }

    /** Big-endian bytes without a sign byte; padded on the left to {@code length} if it is not -1. */
    static byte[] unsigned(BigInteger v, int length) {
        byte[] raw = v.toByteArray();
        int start = raw.length > 1 && raw[0] == 0 ? 1 : 0;
        byte[] out = Arrays.copyOfRange(raw, start, raw.length);
        if (length < 0 || out.length == length) {
            return out;
        }
        byte[] padded = new byte[length];
        System.arraycopy(out, 0, padded, length - out.length, out.length);
        return padded;
    }

    static String json(Map<String, String> members) {
        StringBuilder sb = new StringBuilder("{");
        members.forEach((k, v) -> {
            if (sb.length() > 1) {
                sb.append(',');
            }
            sb.append(q(k)).append(':').append(v);
        });
        return sb.append('}').toString();
    }

    static String jwks(java.util.List<Map<String, String>> keys) {
        StringBuilder sb = new StringBuilder("{\"keys\":[");
        for (int i = 0; i < keys.size(); i++) {
            sb.append(i == 0 ? "" : ",").append(json(keys.get(i)));
        }
        return sb.append("]}").toString();
    }

    static String jwks(Map<String, String> key) {
        return jwks(java.util.List.of(key));
    }

    static JwkSet keySet(Signer... signers) {
        StringBuilder sb = new StringBuilder("{\"keys\":[");
        for (int i = 0; i < signers.length; i++) {
            sb.append(i == 0 ? "" : ",").append(json(signers[i].jwk()));
        }
        return JwkSet.parse(sb.append("]}").toString());
    }

    static OidcPolicy policy() {
        return OidcPolicy.of(ISSUER, CLIENT);
    }

    static Map<String, String> header(Signer s) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("alg", q(s.alg()));
        h.put("kid", q(s.kid()));
        h.put("typ", q("JWT"));
        return h;
    }

    static Map<String, String> claims() {
        Map<String, String> c = new LinkedHashMap<>();
        c.put("iss", q(ISSUER));
        c.put("aud", q(CLIENT));
        c.put("sub", q(SUBJECT));
        c.put("nonce", q(NONCE));
        c.put("iat", Long.toString(NOW.getEpochSecond() - 30));
        c.put("exp", Long.toString(NOW.getEpochSecond() + 300));
        return c;
    }

    static String mint(Signer s) {
        return mint(s, header(s), claims());
    }

    static String mint(Signer s, Map<String, String> claims) {
        return mint(s, header(s), claims);
    }

    static String mint(Signer s, Map<String, String> header, Map<String, String> claims) {
        String input = b64(json(header)) + "." + b64(json(claims));
        return input + "." + b64(s.sign(input.getBytes(StandardCharsets.US_ASCII)));
    }

    /** A correctly signed token whose header and payload are the given texts (they need not be valid JSON objects). */
    static String mintRaw(Signer s, String headerText, String payloadText) {
        String input = b64(headerText) + "." + b64(payloadText);
        return input + "." + b64(s.sign(input.getBytes(StandardCharsets.US_ASCII)));
    }

    /** A token whose signature is whatever the test passes (already base64url). */
    static String assemble(Map<String, String> header, Map<String, String> claims, String signaturePart) {
        return b64(json(header)) + "." + b64(json(claims)) + "." + signaturePart;
    }

    /** An HS256 token signed with the bytes of an RSA public key, the classic algorithm-confusion attack. */
    static String hs256WithPublicKey(PublicKey rsaPublic, Map<String, String> claims) {
        try {
            Map<String, String> h = new LinkedHashMap<>();
            h.put("alg", q("HS256"));
            h.put("kid", q("rsa-1"));
            String input = b64(json(h)) + "." + b64(json(claims));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(rsaPublic.getEncoded(), "HmacSHA256"));
            return input + "." + b64(mac.doFinal(input.getBytes(StandardCharsets.US_ASCII)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Signs with the JDK's DER form of ECDSA (what ES256 must not use). */
    static byte[] signEcDer(Signer ec, byte[] input) {
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(ec.priv());
            s.update(input);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}

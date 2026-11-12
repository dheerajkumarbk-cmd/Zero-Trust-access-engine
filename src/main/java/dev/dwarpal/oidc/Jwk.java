package dev.dwarpal.oidc;

import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonValue.JObject;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Optional;

/**
 * One public signing key from a JSON Web Key Set (RFC 7517), already checked and turned into a JDK key.
 *
 * <p>Three key types can be used: RSA (modulus of at least 2048 bits), EC on P-256 (the point is checked
 * to be on the curve) and OKP on Ed25519. Anything else (symmetric {@code oct} keys, other curves)
 * is skipped by {@link JwkSet#parse(String)} and can never verify a token. Private-key members are
 * never read.
 */
public final class Jwk {

    /** The kinds of key this verifier can use. */
    public enum Type {
        RSA(OidcPolicy.RS256), EC_P256(OidcPolicy.ES256), OKP_ED25519(OidcPolicy.EDDSA);

        private final String algorithm;

        Type(String algorithm) {
            this.algorithm = algorithm;
        }

        /** The one JWS algorithm that goes with this key type. */
        public String algorithm() {
            return algorithm;
        }
    }

    private static final int MIN_RSA_BITS = 2048;
    private static final int MAX_RSA_BITS = 8192;
    private static final int MAX_EXPONENT_BITS = 32;
    private static final int MAX_NAME_CHARS = 256;
    private static final BigInteger ED_P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger ED_D = BigInteger.valueOf(-121665)
            .multiply(BigInteger.valueOf(121666).modInverse(ED_P)).mod(ED_P);

    private final String kid;
    private final Type type;
    private final String alg;
    private final String use;
    private final PublicKey key;

    private Jwk(String kid, Type type, String alg, String use, PublicKey key) {
        this.kid = kid;
        this.type = type;
        this.alg = alg;
        this.use = use;
        this.key = key;
    }

    public Optional<String> kid() {
        return Optional.ofNullable(kid);
    }

    public Type type() {
        return type;
    }

    /** The {@code alg} the key itself declares, if any. */
    public Optional<String> alg() {
        return Optional.ofNullable(alg);
    }

    /** The {@code use} the key itself declares, if any. */
    public Optional<String> use() {
        return Optional.ofNullable(use);
    }

    PublicKey publicKey() {
        return key;
    }

    /** True when this key type is the one that belongs to {@code algorithm}. */
    boolean fits(String algorithm) {
        return type.algorithm().equals(algorithm);
    }

    /**
     * Reads one key. Returns empty for a key type or curve this verifier does not use; throws
     * {@link OidcException} ({@code KEYS_INVALID}) for a key of a usable type that is malformed or too weak.
     */
    static Optional<Jwk> fromJson(JObject o) {
        String kty = stringOrNull(o, "kty");
        if (kty == null || !(kty.equals("RSA") || kty.equals("EC") || kty.equals("OKP"))) {
            return Optional.empty();
        }
        String kid = stringOrNull(o, "kid");
        String alg = stringOrNull(o, "alg");
        String use = stringOrNull(o, "use");
        if ((kid != null && (kid.isEmpty() || kid.length() > MAX_NAME_CHARS))
                || (alg != null && alg.length() > MAX_NAME_CHARS) || (use != null && use.length() > MAX_NAME_CHARS)) {
            throw invalid();
        }
        try {
            return switch (kty) {
                case "RSA" -> Optional.of(new Jwk(kid, Type.RSA, alg, use, rsa(o)));
                case "EC" -> "P-256".equals(stringOrNull(o, "crv"))
                        ? Optional.of(new Jwk(kid, Type.EC_P256, alg, use, ec(o))) : Optional.empty();
                case "OKP" -> "Ed25519".equals(stringOrNull(o, "crv"))
                        ? Optional.of(new Jwk(kid, Type.OKP_ED25519, alg, use, ed25519(o))) : Optional.empty();
                default -> Optional.empty();
            };
        } catch (GeneralSecurityException | RuntimeException e) {
            if (e instanceof OidcException oe) {
                throw oe;
            }
            throw invalid();
        }
    }

    private static PublicKey rsa(JObject o) throws GeneralSecurityException {
        BigInteger n = new BigInteger(1, member(o, "n", -1));
        BigInteger e = new BigInteger(1, member(o, "e", -1));
        if (n.bitLength() < MIN_RSA_BITS || n.bitLength() > MAX_RSA_BITS || !n.testBit(0)) {
            throw invalid();
        }
        if (e.bitLength() > MAX_EXPONENT_BITS || !e.testBit(0) || e.compareTo(BigInteger.valueOf(3)) < 0) {
            throw invalid();
        }
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
    }

    private static PublicKey ec(JObject o) throws GeneralSecurityException {
        BigInteger x = new BigInteger(1, member(o, "x", 32));
        BigInteger y = new BigInteger(1, member(o, "y", 32));
        ECParameterSpec params = P256.PARAMS;
        // The JDK's KeyFactory accepts a point that is not on the curve, so the curve equation is checked here.
        if (!onCurve(params.getCurve(), x, y)) {
            throw invalid();
        }
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), params));
    }

    private static boolean onCurve(EllipticCurve curve, BigInteger x, BigInteger y) {
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) {
            return false;
        }
        BigInteger left = y.multiply(y).mod(p);
        BigInteger right = x.pow(3).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
        return left.equals(right);
    }

    private static PublicKey ed25519(JObject o) throws GeneralSecurityException {
        byte[] x = member(o, "x", 32);
        boolean xOdd = (x[31] & 0x80) != 0;
        byte[] yBig = new byte[32];
        for (int i = 0; i < 32; i++) {
            yBig[i] = x[31 - i];
        }
        yBig[0] &= 0x7F;
        BigInteger y = new BigInteger(1, yBig);
        if (!isEd25519Point(y, xOdd)) {
            throw invalid();
        }
        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, y)));
    }

    /** RFC 8032, section 5.1.3: y below p, and x squared = (y^2 - 1) / (d y^2 + 1) must have a root. */
    private static boolean isEd25519Point(BigInteger y, boolean xOdd) {
        if (y.compareTo(ED_P) >= 0) {
            return false;
        }
        BigInteger y2 = y.multiply(y).mod(ED_P);
        BigInteger u = y2.subtract(BigInteger.ONE).mod(ED_P);
        BigInteger v = ED_D.multiply(y2).add(BigInteger.ONE).mod(ED_P);
        BigInteger x2 = u.multiply(v.modInverse(ED_P)).mod(ED_P);
        if (x2.signum() == 0) {
            return !xOdd;
        }
        return x2.modPow(ED_P.subtract(BigInteger.ONE).shiftRight(1), ED_P).equals(BigInteger.ONE);
    }

    /** A required base64url member; {@code length} is the exact byte length, or -1 for any. */
    private static byte[] member(JObject o, String name, int length) {
        String text = stringOrNull(o, name);
        if (text == null || text.isEmpty()) {
            throw invalid();
        }
        byte[] bytes = Base64Url.decode(text, OidcException.Reason.KEYS_INVALID);
        if (length >= 0 && bytes.length != length) {
            throw invalid();
        }
        return bytes;
    }

    /** The member as a string; null when absent; anything else than a string is an invalid key set. */
    private static String stringOrNull(JObject o, String name) {
        Optional<JsonValue> v = o.get(name);
        if (v.isEmpty()) {
            return null;
        }
        if (v.get() instanceof JsonValue.JString s) {
            return s.value();
        }
        throw invalid();
    }

    private static OidcException invalid() {
        return new OidcException(OidcException.Reason.KEYS_INVALID);
    }

    /** The P-256 parameters, read once from the JDK. */
    private static final class P256 {
        static final ECParameterSpec PARAMS = load();

        private static ECParameterSpec load() {
            try {
                AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
                ap.init(new ECGenParameterSpec("secp256r1"));
                return ap.getParameterSpec(ECParameterSpec.class);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("P-256 unavailable in this JDK", e);
            }
        }
    }
}

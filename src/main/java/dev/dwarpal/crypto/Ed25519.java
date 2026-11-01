package dev.dwarpal.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * Ed25519 signatures (RFC 8032) through the JDK's own provider (SunEC). No third-party crypto:
 * the JCA implementation is maintained by the OpenJDK security team, and Ed25519 has no
 * parameters to get wrong (no curve choice, no nonce to reuse: signing is deterministic).
 */
public final class Ed25519 {

    public static final int SIGNATURE_BYTES = 64;
    private static final String ALGORITHM = "Ed25519";

    private Ed25519() {
    }

    public static KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 unavailable in this JDK", e);
        }
    }

    /** Signs {@code message}; returns the signature as Base64. */
    public static String sign(PrivateKey key, byte[] message) {
        try {
            Signature s = Signature.getInstance(ALGORITHM);
            s.initSign(key);
            s.update(message);
            return Base64.getEncoder().encodeToString(s.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    /**
     * Verifies a Base64 signature. Never throws for bad input: malformed Base64, wrong length or
     * a wrong key type all simply yield {@code false}.
     */
    public static boolean verify(PublicKey key, byte[] message, String signatureBase64) {
        try {
            byte[] sig = Base64.getDecoder().decode(signatureBase64);
            if (sig.length != SIGNATURE_BYTES) {
                return false;
            }
            Signature s = Signature.getInstance(ALGORITHM);
            s.initVerify(key);
            s.update(message);
            return s.verify(sig);
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return false;
        }
    }

    public static boolean isEd25519(PublicKey key) {
        return "EdDSA".equals(key.getAlgorithm()) || ALGORITHM.equals(key.getAlgorithm());
    }
}

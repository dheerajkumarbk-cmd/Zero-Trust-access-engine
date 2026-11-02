package dev.dwarpal.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.HexFormat;

public final class Digests {

    private Digests() {
    }

    public static String sha256Hex(String text) {
        return sha256Hex(text.getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** SHA-256 of a public key's standard encoding: a short, stable name for the key. */
    public static String thumbprint(PublicKey key) {
        return sha256Hex(key.getEncoded());
    }
}

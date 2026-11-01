package dev.dwarpal.crypto;

import dev.dwarpal.domain.Validate;

import java.time.Instant;
import java.util.Objects;

/**
 * A signature over some claim, plus which key made it and when. The signing time is part of the
 * signed bytes, so it cannot be altered to make an old proof look fresh.
 */
public record SignatureProof(String keyId, Instant signedAt, String signature) {

    /** Base64 of a 64-byte Ed25519 signature is 88 characters; anything far longer is junk. */
    public static final int MAX_SIGNATURE_CHARS = 256;

    public SignatureProof {
        Validate.id(keyId, "proof.keyId");
        Objects.requireNonNull(signedAt, "proof.signedAt");
        Objects.requireNonNull(signature, "proof.signature");
        if (signature.isEmpty() || signature.length() > MAX_SIGNATURE_CHARS) {
            throw new IllegalArgumentException("proof.signature has an invalid length");
        }
    }
}

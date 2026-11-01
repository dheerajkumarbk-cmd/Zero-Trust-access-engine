package dev.dwarpal.crypto;

import dev.dwarpal.domain.Validate;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;

/**
 * A public key the system trusts, for one purpose, bound to one owner, for a limited time.
 *
 * @param boundTo the device id (DEVICE_AGENT), administrator id (POLICY_SIGNER) or issuer name
 *                (IDENTITY_PROVIDER) the key belongs to
 * @param notBefore start of validity; signatures dated earlier are rejected
 * @param notAfter  end of validity; forces rotation, limits the damage of an undetected leak
 */
public record TrustedKey(String keyId, KeyPurpose purpose, String boundTo, PublicKey publicKey,
                         Instant notBefore, Instant notAfter) {

    public TrustedKey {
        Validate.id(keyId, "key.id");
        Objects.requireNonNull(purpose, "key.purpose");
        Validate.id(boundTo, "key.boundTo");
        Objects.requireNonNull(publicKey, "key.publicKey");
        if (!Ed25519.isEd25519(publicKey)) {
            throw new IllegalArgumentException("only Ed25519 keys are accepted, got " + publicKey.getAlgorithm());
        }
        Objects.requireNonNull(notBefore, "key.notBefore");
        Objects.requireNonNull(notAfter, "key.notAfter");
        if (!notBefore.isBefore(notAfter)) {
            throw new IllegalArgumentException("key validity window is empty");
        }
    }

    public boolean validAt(Instant t) {
        return !t.isBefore(notBefore) && t.isBefore(notAfter);
    }
}

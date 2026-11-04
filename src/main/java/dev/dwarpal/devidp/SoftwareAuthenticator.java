package dev.dwarpal.devidp;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.domain.Validate;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

/**
 * A security key simulated in software (zero cost: no hardware to buy). Like a real one it is scoped to
 * one relying party id, so it will not sign a challenge from a look-alike identity provider (the
 * phishing resistance WebAuthn is valued for), and its signature counter only goes up, so a copied key
 * shows up at the identity provider as a counter that went backwards.
 */
public final class SoftwareAuthenticator {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final String rpId;
    private final String credentialId;
    private final KeyPair key;
    private final Object lock = new Object();
    private long counter;

    /**
     * @param counter the last counter value used; start a restored key above any value it signed before
     */
    public SoftwareAuthenticator(String rpId, String credentialId, KeyPair key, long counter) {
        this.rpId = Validate.id(rpId, "rpId");
        this.credentialId = Validate.id(credentialId, "credentialId");
        this.key = Objects.requireNonNull(key, "key");
        if (counter < 0 || counter >= 0xFFFF_FFFFL) {
            throw new IllegalArgumentException("counter out of range");
        }
        this.counter = counter;
    }

    /** A new credential for {@code rpId}: fresh Ed25519 key, random credential id. */
    public static SoftwareAuthenticator register(String rpId) {
        byte[] id = new byte[16];
        RANDOM.nextBytes(id);
        return new SoftwareAuthenticator(rpId, "cred-" + HexFormat.of().formatHex(id), Ed25519.generateKeyPair(), 0);
    }

    public String credentialId() {
        return credentialId;
    }

    public String rpId() {
        return rpId;
    }

    /** The public key the identity provider registers. */
    public PublicKey publicKey() {
        return key.getPublic();
    }

    /**
     * Signs a challenge, if it comes from this authenticator's relying party.
     *
     * @param userVerified whether the user passed the local check (PIN or biometric)
     */
    public Optional<WebAuthn.Assertion> assertion(WebAuthn.Challenge c, boolean userVerified) {
        long count;
        synchronized (lock) {
            if (!rpId.equals(c.rpId()) || counter >= 0xFFFF_FFFEL) {
                return Optional.empty();
            }
            count = ++counter;
        }
        byte flags = (byte) (WebAuthn.FLAG_USER_PRESENT | (userVerified ? WebAuthn.FLAG_USER_VERIFIED : 0));
        byte[] authData = WebAuthn.authenticatorData(rpId, flags, count);
        byte[] clientData = WebAuthn.clientData(WebAuthn.TYPE_GET, c.challenge(), WebAuthn.origin(rpId));
        String sig = Ed25519.sign(key.getPrivate(), WebAuthn.signedBytes(authData, clientData));
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return Optional.of(new WebAuthn.Assertion(credentialId, b64.encodeToString(authData),
                b64.encodeToString(clientData), sig));
    }

    @Override
    public String toString() {
        return "SoftwareAuthenticator[rpId=" + rpId + ", credentialId=" + credentialId + "]";
    }
}

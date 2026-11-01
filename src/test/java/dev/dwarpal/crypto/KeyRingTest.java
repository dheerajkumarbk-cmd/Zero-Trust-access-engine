package dev.dwarpal.crypto;

import dev.dwarpal.Fixtures;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyRingTest {

    private static final Instant NOW = Fixtures.T0;
    private static final byte[] MSG = Canonical.encode("test/v1", "hello");
    private static final KeyPair ADMIN = Ed25519.generateKeyPair();
    private static final KeyRing RING = new KeyRing(List.of(
            new TrustedKey("admin-1", KeyPurpose.POLICY_SIGNER, "asha", ADMIN.getPublic(),
                    NOW.minus(Duration.ofDays(30)), NOW.plus(Duration.ofDays(30)))));

    private static SignatureProof sign(KeyPair k, String keyId, byte[] msg, Instant at) {
        return new SignatureProof(keyId, at, Ed25519.sign(k.getPrivate(), msg));
    }

    private static KeyRing.Result verify(SignatureProof p, KeyPurpose purpose, String binding) {
        return RING.verify(purpose, binding, p, MSG, NOW, Duration.ofHours(1));
    }

    @Test
    void validSignatureVerifies() {
        KeyRing.Result r = verify(sign(ADMIN, "admin-1", MSG, NOW), KeyPurpose.POLICY_SIGNER, "asha");
        assertTrue(r.valid(), r.reason());
        assertEquals("asha", r.key().boundTo());
    }

    @Test
    void everyTrustRuleIsEnforced() {
        assertFalse(verify(sign(ADMIN, "nobody", MSG, NOW), KeyPurpose.POLICY_SIGNER, null).valid(), "unknown key");
        assertFalse(verify(sign(ADMIN, "admin-1", MSG, NOW), KeyPurpose.DEVICE_AGENT, null).valid(), "wrong purpose");
        assertFalse(verify(sign(ADMIN, "admin-1", MSG, NOW), KeyPurpose.POLICY_SIGNER, "ravi").valid(), "wrong owner");
        assertFalse(verify(sign(ADMIN, "admin-1", MSG, NOW.plus(Duration.ofMinutes(10))), KeyPurpose.POLICY_SIGNER, null).valid(), "future");
        assertFalse(verify(sign(ADMIN, "admin-1", MSG, NOW.minus(Duration.ofHours(2))), KeyPurpose.POLICY_SIGNER, null).valid(), "too old");
        assertFalse(verify(sign(ADMIN, "admin-1", Canonical.encode("test/v1", "hellO"), NOW), KeyPurpose.POLICY_SIGNER, null).valid(), "other message");
        assertFalse(verify(sign(Ed25519.generateKeyPair(), "admin-1", MSG, NOW), KeyPurpose.POLICY_SIGNER, null).valid(), "other private key");
        assertFalse(RING.verify(KeyPurpose.POLICY_SIGNER, null, sign(ADMIN, "admin-1", MSG, NOW), MSG,
                NOW.plus(Duration.ofDays(31)), Duration.ofDays(40)).valid(), "key expired");
    }

    @Test
    void malformedSignaturesFailClosedWithoutExceptions() {
        assertFalse(Ed25519.verify(ADMIN.getPublic(), MSG, "%%%not-base64%%%"));
        assertFalse(Ed25519.verify(ADMIN.getPublic(), MSG, "AAAA"));
        String sig = Ed25519.sign(ADMIN.getPrivate(), MSG);
        assertTrue(Ed25519.verify(ADMIN.getPublic(), MSG, sig));
        assertThrows(IllegalArgumentException.class, () -> new SignatureProof("k", NOW, "x".repeat(300)));
        assertThrows(IllegalArgumentException.class, () -> new SignatureProof("k", NOW, ""));
    }

    @Test
    void canonicalEncodingIsUnambiguousAndDomainSeparated() {
        assertFalse(Arrays.equals(Canonical.encode("d", "ab", "c"), Canonical.encode("d", "a", "bc")));
        assertFalse(Arrays.equals(Canonical.encode("posture/v1", "x"), Canonical.encode("authn/v1", "x")));
        assertTrue(Arrays.equals(Canonical.encode("d", "é"), Canonical.encode("d", "é")));
    }

    @Test
    void keyDefinitionsAreValidated() throws Exception {
        KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        assertThrows(IllegalArgumentException.class, () -> new TrustedKey("k", KeyPurpose.POLICY_SIGNER, "a",
                rsa.getPublic(), NOW, NOW.plusSeconds(1)), "only Ed25519");
        assertThrows(IllegalArgumentException.class, () -> new TrustedKey("k", KeyPurpose.POLICY_SIGNER, "a",
                ADMIN.getPublic(), NOW, NOW), "empty validity");
        TrustedKey k = new TrustedKey("k", KeyPurpose.POLICY_SIGNER, "a", ADMIN.getPublic(), NOW, NOW.plusSeconds(10));
        assertThrows(IllegalStateException.class, () -> new KeyRing(List.of(k, k)), "duplicate key ids");
        assertFalse(KeyRing.empty().verify(KeyPurpose.POLICY_SIGNER, null, sign(ADMIN, "k", MSG, NOW), MSG, NOW,
                Duration.ofHours(1)).valid());
    }

    @Test
    void digestsAreStable() {
        assertEquals("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Digests.sha256Hex("hello"));
    }
}

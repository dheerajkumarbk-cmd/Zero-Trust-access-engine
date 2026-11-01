package dev.dwarpal.crypto;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The single trust anchor for every signed claim in Dwarpal: device posture, authentication
 * and policy approvals all verify here, so the rules (purpose, binding, validity, freshness)
 * are enforced identically everywhere. Revoking a key means removing it and installing a new
 * key ring (which also starts a fresh verification cache).
 *
 * <p><b>Verification cache.</b> Ed25519 verification costs ~1.4 ms in the JDK's pure-Java
 * implementation, and the same proof arrives many times (an agent re-sends its signed posture until
 * it measures again; a login proof is reused for minutes). Successful verifications are cached,
 * keyed by SHA-256 of key id + signature + exact message bytes. Only successes are stored, so an
 * attacker cannot fill the cache with junk; purpose, binding, validity and freshness are still
 * checked on every call. Bounded LRU.
 */
public final class KeyRing {

    /** Tolerated clock difference between signer and verifier. */
    public static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(2);

    public static final int VERIFIED_CACHE_SIZE = 10_000;

    private final Map<String, TrustedKey> keys;
    private final Map<ByteBuffer, Boolean> verified = new LinkedHashMap<>(16, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<ByteBuffer, Boolean> eldest) {
            return size() > VERIFIED_CACHE_SIZE;
        }
    };

    public KeyRing(Collection<TrustedKey> trusted) {
        // Duplicate key ids would make "which key signed this?" ambiguous: reject.
        this.keys = trusted.stream().collect(Collectors.toUnmodifiableMap(TrustedKey::keyId, Function.identity()));
    }

    public static KeyRing empty() {
        return new KeyRing(java.util.List.of());
    }

    /** Outcome of a verification, with a reason suitable for an analyst explanation. */
    public record Result(boolean valid, String reason, TrustedKey key) {
        static Result fail(String reason) {
            return new Result(false, reason, null);
        }
    }

    /**
     * @param purpose         what the key must be allowed to sign
     * @param requiredBinding owner the key must be bound to, or {@code null} for any owner
     * @param message         the canonical bytes that were supposedly signed
     * @param now             verification time
     * @param maxAge          oldest acceptable signature
     */
    public Result verify(KeyPurpose purpose, String requiredBinding, SignatureProof proof, byte[] message,
                         Instant now, Duration maxAge) {
        Objects.requireNonNull(proof, "proof");
        TrustedKey key = keys.get(proof.keyId());
        if (key == null) {
            return Result.fail("unknown key " + proof.keyId());
        }
        if (key.purpose() != purpose) {
            return Result.fail("key " + key.keyId() + " is a " + key.purpose() + " key, not " + purpose);
        }
        if (requiredBinding != null && !requiredBinding.equals(key.boundTo())) {
            return Result.fail("key " + key.keyId() + " belongs to " + key.boundTo() + ", not " + requiredBinding);
        }
        if (!key.validAt(proof.signedAt()) || !key.validAt(now)) {
            return Result.fail("key " + key.keyId() + " is outside its validity window");
        }
        if (proof.signedAt().isAfter(now.plus(MAX_CLOCK_SKEW))) {
            return Result.fail("signature is dated in the future");
        }
        if (Duration.between(proof.signedAt(), now).compareTo(maxAge) > 0) {
            return Result.fail("signature is older than " + maxAge);
        }
        if (!cryptographicallyValid(key, proof, message)) {
            return Result.fail("signature does not verify");
        }
        return new Result(true, "verified by " + key.keyId(), key);
    }

    private boolean cryptographicallyValid(TrustedKey key, SignatureProof proof, byte[] message) {
        ByteBuffer cacheKey = ByteBuffer.wrap(digest(key.keyId(), proof.signature(), message));
        synchronized (verified) {
            if (verified.containsKey(cacheKey)) {
                return true;
            }
        }
        boolean ok = Ed25519.verify(key.publicKey(), message, proof.signature());
        if (ok) {
            synchronized (verified) {
                verified.put(cacheKey, Boolean.TRUE);
            }
        }
        return ok;
    }

    private static byte[] digest(String keyId, String signature, byte[] message) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(Canonical.encode("dwarpal/verified-cache/v1", keyId, signature));
            md.update(message);
            return md.digest();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Number of cached successful verifications (for tests and monitoring). */
    public int cachedVerifications() {
        synchronized (verified) {
            return verified.size();
        }
    }
}

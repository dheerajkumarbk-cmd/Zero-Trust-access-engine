package dev.dwarpal.devidp;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.guard.RateLimiter;
import dev.dwarpal.session.FailureReportReceiver;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The development identity provider. A login is two factors: the password (checked against the
 * salted PBKDF2 hash in the {@link UserFile}) and a WebAuthn assertion from the user's registered
 * authenticator over a fresh, single-use challenge. Success gives an {@code authentication/v3} proof:
 * signed with the identity provider's key and bound to the subject, the device and the thumbprint of
 * the client's session key, so it is worthless with any other key (Layer 3, R4).
 *
 * <p>Every failure is reported, signed, to a {@link FailureSink} (normally the Policy Administrator's
 * {@link FailureReportReceiver}), so the brute-force and spray detectors learn only from failures the
 * identity provider vouches for. Attempts are limited per client address and per subject at an
 * address, and only failures count towards the per-subject limit, never per subject alone: someone
 * else's junk must not lock a user out (Layer 3, R7), and neither must the user's own logins.
 * Answers never say which factor failed or whether the user exists, and an unknown user costs the
 * same PBKDF2 work as a known one.
 */
public final class DevIdentityProvider {

    public static final Duration CHALLENGE_LIFETIME = Duration.ofMinutes(2);
    public static final int MAX_PENDING = 10_000;
    public static final int MAX_FAILURES = 5;
    public static final int CHALLENGES_PER_MINUTE = 30;
    public static final Duration LOCKOUT = Duration.ofMinutes(5);

    /** Where signed failure reports go. */
    @FunctionalInterface
    public interface FailureSink {
        void report(FailureReportReceiver.FailureReport report, SignatureProof proof);
    }

    private record Pending(String subjectId, String deviceId, String thumbprint, String challenge, Instant expiresAt) {
    }

    private static final Set<String> CLIENT_DATA = Set.of("type", "challenge", "origin");

    private final UserFile users;
    private final KeyPair signer;
    private final String keyId;
    private final String rpId;
    private final Clock clock;
    private final FailureSink failures;
    private final UserFile.User dummy;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final Map<String, Long> counters = new HashMap<>();
    private final RateLimiter challengesPerAddress = new RateLimiter(CHALLENGES_PER_MINUTE, Duration.ofMinutes(1),
            100_000);
    /** Every attempt from one address counts. */
    private final RateLimiter perAddress = new RateLimiter(60, Duration.ofMinutes(1), 100_000);
    /** Only failures count: 5 wrong answers for one subject from one address lock that pair out for a while. */
    private final RateLimiter failuresPerSubjectAtAddress = new RateLimiter(MAX_FAILURES, LOCKOUT, 100_000);
    private final Map<String, Instant> lockedUntil = new ConcurrentHashMap<>();
    private final AtomicLong succeeded = new AtomicLong();
    private final AtomicLong failed = new AtomicLong();
    private final AtomicLong throttled = new AtomicLong();
    private final AtomicLong sinkFailures = new AtomicLong();

    /**
     * @param signer  the identity provider's Ed25519 key, trusted as {@code IDENTITY_PROVIDER} by the engine
     * @param keyId   its id in the engine's key ring
     * @param rpId    the relying party id authenticators are registered for
     */
    public DevIdentityProvider(UserFile users, KeyPair signer, String keyId, String rpId, Clock clock,
                               FailureSink failures) {
        this.users = Objects.requireNonNull(users, "users");
        this.signer = Objects.requireNonNull(signer, "signer");
        this.keyId = Validate.id(keyId, "keyId");
        this.rpId = Validate.id(rpId, "rpId");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.failures = Objects.requireNonNull(failures, "failures");
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        Base64.Encoder b64 = Base64.getEncoder();
        this.dummy = new UserFile.User("nobody", users.maxIterations(), b64.encodeToString(salt),
                b64.encodeToString(new byte[32]), "none", signer.getPublic());
    }

    /** The interface a client uses, with the client's address as this provider sees it. */
    public IdentityProvider forClient(String clientIp) {
        Validate.id(clientIp, "clientIp");
        return new IdentityProvider() {
            @Override
            public Optional<WebAuthn.Challenge> challenge(String subjectId, String deviceId, String keyThumbprint) {
                return DevIdentityProvider.this.challenge(subjectId, deviceId, keyThumbprint, clientIp);
            }

            @Override
            public Optional<IdentityProvider.MfaProof> authenticate(IdentityProvider.Attempt attempt) {
                return DevIdentityProvider.this.authenticate(attempt, clientIp);
            }
        };
    }

    /**
     * A fresh challenge, for any well-formed subject (known or not: no enumeration). At most
     * {@link #CHALLENGES_PER_MINUTE} per client address (B8: the global cap alone let one address hold
     * every slot, and nobody else could log in).
     */
    public Optional<WebAuthn.Challenge> challenge(String subjectId, String deviceId, String keyThumbprint,
                                                  String clientIp) {
        if (!validId(subjectId) || !validId(deviceId) || !validId(clientIp) || keyThumbprint == null
                || keyThumbprint.length() != 64
                || !keyThumbprint.chars().allMatch(c -> c >= '0' && c <= '9' || c >= 'a' && c <= 'f')) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        if (!challengesPerAddress.tryAcquire(clientIp, now)) {
            throttled.incrementAndGet();
            return Optional.empty();
        }
        if (pending.size() >= MAX_PENDING) {
            pending.values().removeIf(p -> !now.isBefore(p.expiresAt()));
            if (pending.size() >= MAX_PENDING) {
                return Optional.empty();
            }
        }
        byte[] id = new byte[16];
        byte[] challenge = new byte[32];
        random.nextBytes(id);
        random.nextBytes(challenge);
        String challengeId = "ch-" + HexFormat.of().formatHex(id);
        String c = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);
        pending.put(challengeId, new Pending(subjectId, deviceId, keyThumbprint, c, now.plus(CHALLENGE_LIFETIME)));
        return Optional.of(new WebAuthn.Challenge(challengeId, c, rpId));
    }

    /** Checks both factors; a signed, key-bound MFA proof on success, empty (and a failure report) otherwise. */
    public Optional<IdentityProvider.MfaProof> authenticate(IdentityProvider.Attempt a, String clientIp) {
        Objects.requireNonNull(a, "attempt");
        Validate.id(clientIp, "clientIp");
        Instant now = clock.instant();
        String pair = a.subjectId() + "|" + clientIp;
        Instant locked = lockedUntil.get(pair);
        if (locked != null && now.isBefore(locked) || !perAddress.tryAcquire(clientIp, now)) {
            throttled.incrementAndGet();
            pending.remove(a.challengeId());
            return Optional.empty();
        }
        // Single use: the challenge is gone whatever happens next.
        Pending p = pending.remove(a.challengeId());
        boolean challengeOk = p != null && now.isBefore(p.expiresAt()) && p.subjectId().equals(a.subjectId());
        Optional<UserFile.User> user = users.user(a.subjectId());
        boolean passwordOk = passwordMatches(user.orElse(dummy), a.password()) && user.isPresent();
        Optional<Long> signCount = challengeOk && passwordOk ? verifyAssertion(user.get(), p, a.assertion())
                : Optional.empty();
        if (signCount.isEmpty() || !advanceCounter(user.get().credentialId(), signCount.get())) {
            if (!failuresPerSubjectAtAddress.tryAcquire(pair, now)) {
                if (lockedUntil.size() >= MAX_PENDING) {
                    lockedUntil.values().removeIf(t -> !now.isBefore(t));
                }
                lockedUntil.put(pair, now.plus(LOCKOUT));
            }
            fail(a.subjectId(), clientIp, now);
            return Optional.empty();
        }
        AuthenticationContext ctx = new AuthenticationContext(AuthMethod.WEBAUTHN, now, Optional.of(p.thumbprint()));
        SignatureProof proof = new SignatureProof(keyId, now, Ed25519.sign(signer.getPrivate(),
                SignedMessages.authentication(p.subjectId(), p.deviceId(), ctx, now)));
        succeeded.incrementAndGet();
        return Optional.of(new IdentityProvider.MfaProof(ctx, proof));
    }

    public long succeeded() {
        return succeeded.get();
    }

    public long failed() {
        return failed.get();
    }

    public long throttled() {
        return throttled.get();
    }

    /** Failure reports the sink refused or could not take (the login is refused all the same). */
    public long sinkFailures() {
        return sinkFailures.get();
    }

    private static boolean passwordMatches(UserFile.User u, String password) {
        char[] pw = password.toCharArray();
        try {
            return u.passwordMatches(pw);
        } catch (IllegalArgumentException e) {
            return false;
        } finally {
            Arrays.fill(pw, (char) 0);
        }
    }

    /** The authenticator's signature counter when every WebAuthn check passes. */
    private Optional<Long> verifyAssertion(UserFile.User u, Pending p, WebAuthn.Assertion a) {
        try {
            if (!u.credentialId().equals(a.credentialId())) {
                return Optional.empty();
            }
            Base64.Decoder b64 = Base64.getUrlDecoder();
            byte[] authData = b64.decode(a.authenticatorData());
            byte[] clientData = b64.decode(a.clientData());
            if (authData.length != WebAuthn.AUTH_DATA_BYTES) {
                return Optional.empty();
            }
            ByteBuffer ad = ByteBuffer.wrap(authData);
            byte[] rpHash = new byte[32];
            ad.get(rpHash);
            byte flags = ad.get();
            long count = Integer.toUnsignedLong(ad.getInt());
            boolean present = (flags & WebAuthn.FLAG_USER_PRESENT) != 0;
            boolean verified = (flags & WebAuthn.FLAG_USER_VERIFIED) != 0;
            if (!MessageDigest.isEqual(rpHash, WebAuthn.sha256(rpId.getBytes(StandardCharsets.UTF_8)))
                    || !present || !verified || !clientDataMatches(clientData, p.challenge())) {
                return Optional.empty();
            }
            if (!Ed25519.verify(u.credentialKey(), WebAuthn.signedBytes(authData, clientData), a.signature())) {
                return Optional.empty();
            }
            return Optional.of(count);
        } catch (IllegalArgumentException | JsonException e) {
            return Optional.empty();
        }
    }

    private boolean clientDataMatches(byte[] clientData, String challenge) {
        if (!(new JsonReader().read(clientData) instanceof JsonValue.JObject o) || !Set.copyOf(o.keys()).equals(CLIENT_DATA)) {
            return false;
        }
        return string(o, "type").equals(WebAuthn.TYPE_GET)
                && MessageDigest.isEqual(string(o, "challenge").getBytes(StandardCharsets.UTF_8),
                challenge.getBytes(StandardCharsets.UTF_8))
                && string(o, "origin").equals(WebAuthn.origin(rpId));
    }

    private static String string(JsonValue.JObject o, String key) {
        return o.get(key).orElseThrow() instanceof JsonValue.JString s ? s.value() : "";
    }

    /** A counter that does not go up means a cloned authenticator: refused. */
    private boolean advanceCounter(String credentialId, long count) {
        synchronized (counters) {
            long last = counters.getOrDefault(credentialId, 0L);
            if (count <= last) {
                return false;
            }
            counters.put(credentialId, count);
            return true;
        }
    }

    private void fail(String subjectId, String clientIp, Instant now) {
        failed.incrementAndGet();
        byte[] id = new byte[16];
        random.nextBytes(id);
        String reportId = "fr-" + HexFormat.of().formatHex(id);
        try {
            FailureReportReceiver.FailureReport report = new FailureReportReceiver.FailureReport(reportId, subjectId,
                    clientIp, now);
            SignatureProof proof = new SignatureProof(keyId, now, Ed25519.sign(signer.getPrivate(),
                    SignedMessages.authenticationFailure(reportId, subjectId, clientIp, now, now)));
            failures.report(report, proof);
        } catch (RuntimeException e) {
            sinkFailures.incrementAndGet();
        }
    }

    private static boolean validId(String s) {
        if (s == null) {
            return false;
        }
        try {
            Validate.id(s, "id");
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}

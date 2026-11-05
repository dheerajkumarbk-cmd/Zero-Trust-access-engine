package dev.dwarpal.console;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.devidp.DevIdentityProvider;
import dev.dwarpal.devidp.IdentityProvider;
import dev.dwarpal.devidp.SoftwareAuthenticator;
import dev.dwarpal.devidp.UserFile;
import dev.dwarpal.devidp.WebAuthn;
import dev.dwarpal.domain.Validate;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Login and step-up through Dwarpal's development identity provider ({@link DevIdentityProvider}): a PBKDF2 password
 * and a (simulated) WebAuthn assertion over a fresh single-use challenge. In the lab the "security key" is a
 * {@link SoftwareAuthenticator} held here, and the key's local user check is a PIN, so the second factor is something
 * the person knows and the server cannot guess; a real key replaces it behind the same IdP interface.
 *
 * <p>Two steps, as the contract says. {@link #begin} takes user and password and <em>always</em> answers with a login
 * id (for unknown users too), so the answer reveals nothing; {@link #complete} takes the PIN, builds the assertion and
 * hands password and assertion to the IdP, which checks both and says only yes or no. The password waits in memory for
 * at most two minutes, in a bounded table, and is dropped on use (a difference from a real IdP, named in the notes).
 */
public final class ConsoleAuth {

    /** A person who can log in. */
    public record Person(String id, String display, Set<dev.dwarpal.console.ConsoleModule.Role> roles) {
        public Person {
            Validate.id(id, "person.id");
            roles = Set.copyOf(roles);
        }
    }

    /** The details to enrol a person: the lab prints them for the owner. */
    public record Enrolment(Person person, String password, String pin) {
        public Enrolment {
            Objects.requireNonNull(person, "person");
            if (password == null || password.length() < 8 || pin == null || pin.length() < 6) {
                throw new IllegalArgumentException("password of 8+ and PIN of 6+ characters");
            }
        }

        @Override
        public String toString() {
            return "Enrolment[" + person.id() + ", secrets redacted]";
        }
    }

    public enum Status { OK, FAILED, LOCKED }

    /** The answer to {@link #begin}: a login id to finish with, or a lockout. */
    public record Begun(Status status, String loginId, long retryAfterSeconds, Duration validFor) {
    }

    /** The answer to {@link #complete} and {@link #stepUp}. */
    public record Authenticated(Status status, Person person, long retryAfterSeconds, String subject) {
        static Authenticated failed(String subject) {
            return new Authenticated(Status.FAILED, null, 0, subject);
        }
    }

    private record Pending(String subject, String password, WebAuthn.Challenge challenge, Instant expiresAt, String source) {
    }

    private record Card(Person person, SoftwareAuthenticator key, byte[] pinSalt, byte[] pinHash) {
    }

    static final String RP_ID = "dwarpal.localhost";
    static final Duration LOGIN_VALID = Duration.ofMinutes(2);
    private static final int MAX_PENDING = 1_000;
    private static final int MAX_PENDING_PER_SOURCE = 20;
    private static final WebAuthn.Assertion BOGUS = new WebAuthn.Assertion("cred-none", "AAAA", "AAAA", "AAAA");
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Clock clock;
    private final LoginThrottle throttle;
    private final DevIdentityProvider idp;
    private final Map<String, Card> cards;
    private final int pinIterations;
    private final Card dummy;
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();

    /** Enrols the people and starts the identity provider that will vouch for them. */
    public ConsoleAuth(List<Enrolment> people, Clock clock, int passwordIterations, int pinIterations) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.throttle = new LoginThrottle(clock);
        this.pinIterations = pinIterations;
        Map<String, Card> built = new LinkedHashMap<>();
        StringBuilder users = new StringBuilder();
        for (Enrolment e : people) {
            SoftwareAuthenticator key = SoftwareAuthenticator.register(RP_ID);
            users.append(UserFile.line(e.person().id(), e.password().toCharArray(), passwordIterations, key.credentialId(),
                    key.publicKey())).append('\n');
            byte[] salt = randomBytes(16);
            Card card = new Card(e.person(), key, salt, pinHash(e.pin(), salt, pinIterations));
            if (built.putIfAbsent(e.person().id(), card) != null) {
                throw new IllegalArgumentException("two people with the same id");
            }
        }
        this.cards = Map.copyOf(built);
        byte[] salt = randomBytes(16);
        this.dummy = new Card(null, null, salt, pinHash("000000", salt, pinIterations));
        this.idp = new DevIdentityProvider(UserFile.parse(users.toString()), Ed25519.generateKeyPair(), "console-idp", RP_ID,
                clock, (report, proof) -> {
                    // failures are audited by the console itself; the lab has no policy administrator to report to
                });
    }

    // ---- login ------------------------------------------------------------------------------------------------

    /** Step one: user and password. The password is checked only in step two, together with the second factor. */
    public Begun begin(String user, String password, String source) {
        long wait = throttle.retryAfterSeconds(user, source);
        if (wait > 0) {
            return new Begun(Status.LOCKED, null, wait, Duration.ZERO);
        }
        Instant now = clock.instant();
        pending.values().removeIf(p -> !now.isBefore(p.expiresAt()));
        long fromSource = pending.values().stream().filter(p -> p.source().equals(source)).count();
        if (pending.size() >= MAX_PENDING || fromSource >= MAX_PENDING_PER_SOURCE || !wellFormed(user)) {
            throttle.failure(user, source);
            return new Begun(Status.FAILED, null, 0, Duration.ZERO);
        }
        Optional<WebAuthn.Challenge> challenge = idp.challenge(user, "console-browser", randomThumbprint(), source);
        if (challenge.isEmpty()) {
            return new Begun(Status.FAILED, null, 0, Duration.ZERO);
        }
        String loginId = "lg-" + HexFormat.of().formatHex(randomBytes(16));
        pending.put(loginId, new Pending(user, password, challenge.get(), now.plus(LOGIN_VALID), source));
        return new Begun(Status.OK, loginId, 0, LOGIN_VALID);
    }

    /** Step two: the PIN of the security key. Single use: the login id is gone whatever the answer. */
    public Authenticated complete(String loginId, String pin, String source) {
        Pending p = pending.remove(loginId == null ? "" : loginId);
        if (p == null || !p.source().equals(source) || !clock.instant().isBefore(p.expiresAt())) {
            return Authenticated.failed(p == null ? "unknown" : p.subject());
        }
        long wait = throttle.retryAfterSeconds(p.subject(), source);
        if (wait > 0) {
            return new Authenticated(Status.LOCKED, null, wait, p.subject());
        }
        return check(p.subject(), p.password(), pin, p.challenge(), source);
    }

    /** A fresh second factor for a privileged write: password and PIN again, against a new challenge. */
    public Authenticated stepUp(String subject, String password, String pin, String source) {
        long wait = throttle.retryAfterSeconds(subject, source);
        if (wait > 0) {
            return new Authenticated(Status.LOCKED, null, wait, subject);
        }
        Optional<WebAuthn.Challenge> challenge = idp.challenge(subject, "console-browser", randomThumbprint(), source);
        if (challenge.isEmpty()) {
            return Authenticated.failed(subject);
        }
        return check(subject, password, pin, challenge.get(), source);
    }

    private Authenticated check(String subject, String password, String pin, WebAuthn.Challenge challenge, String source) {
        Card card = cards.get(subject);
        // an unknown user costs the same PIN work as a known one
        boolean pinOk = pinMatches(card == null ? dummy : card, pin == null ? "" : pin) && card != null;
        WebAuthn.Assertion assertion = card == null ? BOGUS : card.key().assertion(challenge, pinOk).orElse(BOGUS);
        Optional<IdentityProvider.MfaProof> proof;
        try {
            proof = idp.forClient(source).authenticate(new IdentityProvider.Attempt(challenge.challengeId(), subject,
                    password == null ? "" : password, assertion));
        } catch (IllegalArgumentException malformed) {
            proof = Optional.empty();
        }
        if (proof.isEmpty() || card == null) {
            throttle.failure(subject, source);
            long wait = throttle.retryAfterSeconds(subject, source);
            return wait > 0 ? new Authenticated(Status.LOCKED, null, wait, subject) : Authenticated.failed(subject);
        }
        throttle.success(subject, source);
        return new Authenticated(Status.OK, card.person(), 0, subject);
    }

    public Optional<Person> person(String id) {
        Card c = cards.get(id);
        return c == null ? Optional.empty() : Optional.of(c.person());
    }

    public long lockouts() {
        return throttle.lockouts();
    }

    public long failed() {
        return idp.failed();
    }

    public long succeeded() {
        return idp.succeeded();
    }

    // ---- helpers ----------------------------------------------------------------------------------------------

    private static boolean wellFormed(String user) {
        try {
            Validate.id(user, "user");
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private boolean pinMatches(Card card, String pin) {
        if (pin.length() > 64) {
            return false;
        }
        return MessageDigest.isEqual(pinHash(pin, card.pinSalt(), pinIterations), card.pinHash());
    }

    private static byte[] pinHash(String pin, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(pin.toCharArray(), salt, iterations, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2 unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    /** The IdP binds its proof to a session key thumbprint; the console has none per login, so a fresh random one. */
    private static String randomThumbprint() {
        return Digests.sha256Hex(Base64.getEncoder().encodeToString(randomBytes(32)));
    }
}

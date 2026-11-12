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
import java.io.IOException;
import javax.crypto.spec.PBEKeySpec;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
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

    /** How a change of one's own secrets ended. WEAK: the new value breaks the rules, nothing was checked or changed. */
    public enum Change { OK, DENIED, LOCKED, WEAK, UNAVAILABLE }

    public record Changed(Change status, long retryAfterSeconds) {
        static Changed of(Change c) {
            return new Changed(c, 0);
        }
    }

    /** What the Profile page shows about a person's sign-in. */
    public record Standing(Instant passwordChanged, Instant pinChanged, Instant changeBy, boolean due, boolean passkeySet,
                           int backupCodesLeft, long rotationDays) {
    }

    private record Pending(String subject, String password, WebAuthn.Challenge challenge, Instant expiresAt, String source) {
    }

    /**
     * The emergency password of the vault, as the recovery sees it: accepted only while an administrator has switched it on,
     * and used up when the person has set a new password and PIN.
     */
    public interface Emergency {
        /** True while this person's emergency password is switched on and this is it. */
        boolean accepts(String user, String code);

        /** The person set new secrets with it: it is used up (and replaced by a new, switched-off one). */
        void used(String user);
    }

    /** What a recovery ticket carries when the emergency password opened it, so that it is told apart from a backup code. */
    private static final String EMERGENCY_MARK = "emergency:";

    private volatile Emergency emergency;

    /** Plugs the vault's emergency passwords into the recovery. */
    public void emergency(Emergency e) {
        this.emergency = e;
    }

    /** Proof that a backup code was right, held only until the new password and PIN arrive. */
    private record Recovery(String subject, String code, Instant expiresAt, String source) {
    }

    /** The first step of recovery: a ticket for the second step, or why there is none. */
    public record Recovering(Change status, String ticket, long retryAfterSeconds) {
    }

    private record Card(Person person, SoftwareAuthenticator key, byte[] pinSalt, byte[] pinHash) {
    }

    static final String RP_ID = "dwarpal.localhost";
    static final Duration LOGIN_VALID = Duration.ofMinutes(2);
    static final Duration RECOVERY_VALID = Duration.ofMinutes(5);
    private static final int MAX_PENDING = 1_000;
    private static final int MAX_PENDING_PER_SOURCE = 20;
    private static final WebAuthn.Assertion BOGUS = new WebAuthn.Assertion("cred-none", "AAAA", "AAAA", "AAAA");
    private static final SecureRandom RANDOM = new SecureRandom();
    public static final Duration WEEKLY = Duration.ofDays(7);
    public static final int MIN_PASSWORD = 12;
    public static final int MIN_PIN = 6;
    public static final int MIN_PASSKEY = 10;
    public static final int BACKUP_CODES = 10;
    private static final String CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    private static final int CODE_GROUPS = 3;
    private static final int CODE_GROUP = 5;

    private final Clock clock;
    private final LoginThrottle throttle;
    private final DevIdentityProvider idp;
    private final Map<String, Card> cards;
    private final Map<String, CredentialStore.Entry> entries = new ConcurrentHashMap<>();
    private final CredentialStore store;
    private final Duration rotation;
    private final int passwordIterations;
    private volatile UserFile users;
    private final int pinIterations;
    private final Card dummy;
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final Map<String, Recovery> recoveries = new ConcurrentHashMap<>();

    /** Enrols the people and starts the identity provider that will vouch for them. */
    public ConsoleAuth(List<Enrolment> people, Clock clock, int passwordIterations, int pinIterations) {
        this(people, clock, passwordIterations, pinIterations, null, WEEKLY);
    }

    /**
     * @param store    where people's own changes are kept across restarts; null keeps them in memory only
     * @param rotation how long a password or PIN lasts before it must be changed
     */
    public ConsoleAuth(List<Enrolment> people, Clock clock, int passwordIterations, int pinIterations, Path store,
                       Duration rotation) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.store = new CredentialStore(store);
        this.rotation = Objects.requireNonNull(rotation, "rotation");
        this.passwordIterations = passwordIterations;
        Map<String, CredentialStore.Entry> saved;
        try {
            saved = this.store.load();
        } catch (IOException e) {
            throw new IllegalStateException("the credentials file cannot be read", e);
        }
        this.throttle = new LoginThrottle(clock);
        this.pinIterations = pinIterations;
        Map<String, Card> built = new LinkedHashMap<>();
        Instant first = clock.instant();
        StringBuilder users = new StringBuilder();
        for (Enrolment e : people) {
            SoftwareAuthenticator key = SoftwareAuthenticator.register(RP_ID);
            users.append(UserFile.line(e.person().id(), e.password().toCharArray(), passwordIterations, key.credentialId(),
                    key.publicKey())).append('\n');
            CredentialStore.Entry entry = saved.getOrDefault(e.person().id(), CredentialStore.Entry.fresh(first));
            entries.put(e.person().id(), entry);
            byte[] salt = entry.pinHash().isEmpty() ? randomBytes(16) : Base64.getDecoder().decode(entry.pinSalt());
            byte[] pinHash = entry.pinHash().isEmpty() ? pinHash(e.pin(), salt, pinIterations)
                    : Base64.getDecoder().decode(entry.pinHash());
            Card card = new Card(e.person(), key, salt, pinHash);
            if (built.putIfAbsent(e.person().id(), card) != null) {
                throw new IllegalArgumentException("two people with the same id");
            }
        }
        this.cards = new ConcurrentHashMap<>(built);
        byte[] salt = randomBytes(16);
        this.dummy = new Card(null, null, salt, pinHash("000000", salt, pinIterations));
        UserFile file = UserFile.parse(users.toString());
        for (Map.Entry<String, CredentialStore.Entry> e : entries.entrySet()) {
            if (!e.getValue().passwordHash().isEmpty()) {
                file = file.withPassword(e.getKey(), new UserFile.Hashed(e.getValue().passwordIterations(),
                        e.getValue().passwordSalt(), e.getValue().passwordHash()));
            }
        }
        this.users = file;
        this.idp = new DevIdentityProvider(file, Ed25519.generateKeyPair(), "console-idp", RP_ID,
                clock, (report, proof) -> {
                    // failures are audited by the console itself; the lab has no policy administrator to report to
                });
    }

    // ---- login ------------------------------------------------------------------------------------------------

    /**
     * The name as the person is known: a typed name made only of printable ASCII (no spaces) is folded to lower case, so
     * "Dana" and "DANA" are "dana" and share one lockout counter. ASCII only on purpose: Unicode case mapping is refused
     * because, for example, the Kelvin sign U+212A lower-cases to "k" and Cyrillic look-alikes would map onto real names.
     * Anything else is returned unchanged, fails the well-formed check and is refused like any bad name.
     */
    static String typedName(String raw) {
        if (raw == null) {
            return null;
        }
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c < 0x21 || c > 0x7E) {
                return raw;
            }
        }
        return raw.toLowerCase(java.util.Locale.ROOT);
    }

    /** Step one: user and password. The password is checked only in step two, together with the second factor. */
    public Begun begin(String typed, String password, String source) {
        String user = typedName(typed);
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

    // ---- one's own secrets ----------------------------------------------------------------------------------------

    public Changed changePassword(String subject, String current, String pin, String fresh, String source) {
        if (!strongPassword(subject, fresh) || fresh.equals(current)) {
            return Changed.of(Change.WEAK);
        }
        Changed proof = prove(subject, current, pin, source);
        if (proof.status() != Change.OK) {
            return proof;
        }
        Instant now = clock.instant();
        UserFile.Hashed h = UserFile.hash(fresh.toCharArray(), passwordIterations);
        return update(subject, e -> e.password(h.iterations(), h.salt(), h.hash(), now), true);
    }

    public Changed changePin(String subject, String password, String current, String fresh, String source) {
        if (!strongPin(fresh) || fresh.equals(current)) {
            return Changed.of(Change.WEAK);
        }
        Changed proof = prove(subject, password, current, source);
        if (proof.status() != Change.OK) {
            return proof;
        }
        Instant now = clock.instant();
        byte[] salt = randomBytes(16);
        byte[] hash = pinHash(fresh, salt, pinIterations);
        return update(subject, e -> e.pin(text(salt), text(hash), now), true);
    }

    /** Sets or replaces the passkey that opens confidential views. Password and PIN prove who is asking. */
    public Changed setPasskey(String subject, String password, String pin, String passkey, String source) {
        if (passkey.length() < MIN_PASSKEY || passkey.length() > 128 || passkey.equals(password) || passkey.equals(pin)) {
            return Changed.of(Change.WEAK);
        }
        Changed proof = prove(subject, password, pin, source);
        if (proof.status() != Change.OK) {
            return proof;
        }
        byte[] salt = randomBytes(16);
        byte[] hash = pinHash(passkey, salt, passwordIterations);
        return update(subject, e -> e.passkey(text(salt), text(hash)), false);
    }

    /** Is this the person's passkey? Wrong guesses cost the same growing wait as wrong passwords. */
    public Authenticated unlock(String subject, String passkey, String source) {
        String account = "passkey:" + subject;
        long wait = throttle.retryAfterSeconds(account, source);
        if (wait > 0) {
            return new Authenticated(Status.LOCKED, null, wait, subject);
        }
        CredentialStore.Entry e = entries.get(subject);
        boolean set = e != null && !e.passkeyHash().isEmpty();
        byte[] salt = set ? Base64.getDecoder().decode(e.passkeySalt()) : randomBytes(16);
        byte[] made = pinHash(passkey.length() > 128 ? "" : passkey, salt, passwordIterations);
        Card card = cards.get(subject);
        if (set && card != null && MessageDigest.isEqual(made, Base64.getDecoder().decode(e.passkeyHash()))) {
            throttle.success(account, source);
            return new Authenticated(Status.OK, card.person(), 0, subject);
        }
        throttle.failure(account, source);
        long after = throttle.retryAfterSeconds(account, source);
        return after > 0 ? new Authenticated(Status.LOCKED, null, after, subject) : Authenticated.failed(subject);
    }

    /**
     * Is this the person's security PIN? On its own, for an elevation (the passkey is checked beside it). Wrong guesses
     * cost the same growing wait as wrong passwords, and an unknown person costs the same work as a known one.
     */
    public Authenticated checkPin(String subject, String pin, String source) {
        String account = "pin:" + subject;
        long wait = throttle.retryAfterSeconds(account, source);
        if (wait > 0) {
            return new Authenticated(Status.LOCKED, null, wait, subject);
        }
        Card card = cards.get(subject);
        boolean ok = pinMatches(card == null ? dummy : card, pin == null ? "" : pin) && card != null;
        if (ok) {
            throttle.success(account, source);
            return new Authenticated(Status.OK, card.person(), 0, subject);
        }
        throttle.failure(account, source);
        long after = throttle.retryAfterSeconds(account, source);
        return after > 0 ? new Authenticated(Status.LOCKED, null, after, subject) : Authenticated.failed(subject);
    }

    /**
     * Gives a signed-in person the roles the directory now says they hold. True when that changed anything, so the caller
     * can end their sessions. A person who cannot sign in at all (no card) is left alone.
     */
    public boolean updateRoles(String id, Set<dev.dwarpal.console.ConsoleModule.Role> roles) {
        boolean[] changed = new boolean[1];
        cards.computeIfPresent(id, (k, c) -> {
            if (c.person().roles().equals(roles)) {
                return c;
            }
            changed[0] = true;
            return new Card(new Person(c.person().id(), c.person().display(), roles), c.key(), c.pinSalt(), c.pinHash());
        });
        return changed[0];
    }

    /** Ten new one-use codes, shown once; older ones stop working. Only their hashes are kept. */
    public Optional<List<String>> newBackupCodes(String subject, String password, String pin, String source, Changed[] result) {
        Changed proof = prove(subject, password, pin, source);
        result[0] = proof;
        if (proof.status() != Change.OK) {
            return Optional.empty();
        }
        List<String> plain = new ArrayList<>();
        List<String> kept = new ArrayList<>();
        for (int i = 0; i < BACKUP_CODES; i++) {
            String code = newCode();
            plain.add(code);
            kept.add(sealed(code));
        }
        result[0] = update(subject, e -> e.backupCodes(kept), false);
        return result[0].status() == Change.OK ? Optional.of(List.copyOf(plain)) : Optional.empty();
    }

    /**
     * Recovery, step one: for a person who lost control of their password or PIN. A right code earns a short-lived ticket
     * for step two and nothing else; the code itself is used up only when new secrets are saved. Wrong guesses cost the
     * same growing wait as wrong passwords.
     */
    public Recovering checkBackupCode(String typed, String code, String source) {
        String user = typedName(typed);
        long wait = throttle.retryAfterSeconds(user, source);
        if (wait > 0) {
            return new Recovering(Change.LOCKED, null, wait);
        }
        CredentialStore.Entry e = wellFormed(user) ? entries.get(user) : null;
        String match = e == null ? null : e.codes().stream().filter(c -> opens(c, code)).findFirst().orElse(null);
        Emergency vault = emergency;
        if (match == null && e != null && vault != null && vault.accepts(user, code)) {
            match = EMERGENCY_MARK + code;
        }
        Instant now = clock.instant();
        recoveries.values().removeIf(r -> !now.isBefore(r.expiresAt()));
        if (match == null || recoveries.size() >= MAX_PENDING) {
            throttle.failure(user, source);
            long after = throttle.retryAfterSeconds(user, source);
            return after > 0 ? new Recovering(Change.LOCKED, null, after) : new Recovering(Change.DENIED, null, 0);
        }
        throttle.success(user, source);
        recoveries.values().removeIf(r -> r.subject().equals(user));
        String ticket = "rc-" + HexFormat.of().formatHex(randomBytes(16));
        recoveries.put(ticket, new Recovery(user, match, now.plus(RECOVERY_VALID), source));
        return new Recovering(Change.OK, ticket, 0);
    }

    /** Whose recovery this ticket belongs to, so the caller can end that person's sessions. */
    public Optional<String> recoveryOf(String ticket) {
        Recovery r = recoveries.get(ticket);
        return r == null ? Optional.empty() : Optional.of(r.subject());
    }

    /**
     * Recovery, step two: sets the new password and PIN and uses up the code. A weak choice keeps the ticket, so the
     * person can try again; a ticket that is old, from elsewhere, or whose code has since been replaced does nothing.
     */
    public Changed recover(String ticket, String newPassword, String newPin, String source) {
        Recovery r = recoveries.get(ticket);
        if (r == null || !r.source().equals(source) || !clock.instant().isBefore(r.expiresAt())) {
            return Changed.of(Change.DENIED);
        }
        if (!strongPassword(r.subject(), newPassword) || !strongPin(newPin)) {
            return Changed.of(Change.WEAK);
        }
        recoveries.remove(ticket);
        CredentialStore.Entry e = entries.get(r.subject());
        boolean byEmergency = r.code().startsWith(EMERGENCY_MARK);
        Emergency vault = emergency;
        if (e == null || (byEmergency ? vault == null || !vault.accepts(r.subject(), r.code().substring(EMERGENCY_MARK.length()))
                : !e.codes().contains(r.code()))) {
            return Changed.of(Change.DENIED);
        }
        Instant now = clock.instant();
        UserFile.Hashed h = UserFile.hash(newPassword.toCharArray(), passwordIterations);
        byte[] salt = randomBytes(16);
        byte[] pin = pinHash(newPin, salt, pinIterations);
        List<String> left = new ArrayList<>(e.codes());
        left.remove(r.code());
        Changed saved = update(r.subject(), x -> x.password(h.iterations(), h.salt(), h.hash(), now).pin(text(salt), text(pin), now)
                .backupCodes(left), true);
        if (byEmergency && saved.status() == Change.OK) {
            vault.used(r.subject());
        }
        return saved;
    }

    /** True when the password or the PIN has lasted its full term: until it changes, the person can do nothing else. */
    public boolean changeDue(String subject) {
        CredentialStore.Entry e = entries.get(subject);
        return e != null && !clock.instant().isBefore(changeBy(e));
    }

    public Standing standing(String subject) {
        CredentialStore.Entry e = entries.get(subject);
        return new Standing(e.passwordChanged(), e.pinChanged(), changeBy(e), changeDue(subject), !e.passkeyHash().isEmpty(),
                e.codes().size(), rotation.toDays());
    }

    /** True once a person has chosen their own password or PIN, so the printed first ones mean nothing. */
    public boolean hasOwnSecrets(String subject) {
        CredentialStore.Entry e = entries.get(subject);
        return e != null && e.hasOwnSecrets();
    }

    private Instant changeBy(CredentialStore.Entry e) {
        Instant oldest = e.passwordChanged().isBefore(e.pinChanged()) ? e.passwordChanged() : e.pinChanged();
        return oldest.plus(rotation);
    }

    /** Password and PIN prove who is asking, and nothing is changed (a device passkey is registered after this). */
    public Changed proveOwner(String subject, String password, String pin, String source) {
        return prove(subject, password, pin, source);
    }

    /**
     * Like {@link #unlock}, for a passkey that a device proves by signing: the same growing wait after wrong tries (counted
     * per person and per source) and the same answer. {@code proof} is asked only when the person is not in a wait.
     */
    public Authenticated unlockWith(String subject, String source, java.util.function.BooleanSupplier proof) {
        String account = "passkey:" + subject;
        long wait = throttle.retryAfterSeconds(account, source);
        if (wait > 0) {
            return new Authenticated(Status.LOCKED, null, wait, subject);
        }
        Card card = cards.get(subject);
        boolean ok = proof.getAsBoolean();
        if (ok && card != null) {
            throttle.success(account, source);
            return new Authenticated(Status.OK, card.person(), 0, subject);
        }
        throttle.failure(account, source);
        long after = throttle.retryAfterSeconds(account, source);
        return after > 0 ? new Authenticated(Status.LOCKED, null, after, subject) : Authenticated.failed(subject);
    }

    private Changed prove(String subject, String password, String pin, String source) {
        Authenticated a = stepUp(subject, password, pin, source);
        return switch (a.status()) {
            case OK -> Changed.of(Change.OK);
            case LOCKED -> new Changed(Change.LOCKED, a.retryAfterSeconds());
            case FAILED -> Changed.of(Change.DENIED);
        };
    }

    /** Disk first: a change that cannot be kept does not happen, so a restart never brings an old secret back. */
    private synchronized Changed update(String subject, java.util.function.UnaryOperator<CredentialStore.Entry> change,
                                        boolean ownSecret) {
        CredentialStore.Entry next = change.apply(entries.get(subject));
        Map<String, CredentialStore.Entry> all = new HashMap<>(entries);
        all.put(subject, next);
        try {
            store.save(all);
            if (ownSecret) {
                store.forgetFirstSecrets(subject);
            }
        } catch (IOException e) {
            return Changed.of(Change.UNAVAILABLE);
        }
        entries.put(subject, next);
        if (!next.pinHash().isEmpty()) {
            cards.computeIfPresent(subject, (id, c) -> new Card(c.person(), c.key(), Base64.getDecoder().decode(next.pinSalt()),
                    Base64.getDecoder().decode(next.pinHash())));
        }
        if (!next.passwordHash().isEmpty()) {
            users = users.withPassword(subject, new UserFile.Hashed(next.passwordIterations(), next.passwordSalt(),
                    next.passwordHash()));
            idp.replaceUsers(users);
        }
        return Changed.of(Change.OK);
    }

    static boolean strongPassword(String subject, String password) {
        return password.length() >= MIN_PASSWORD && password.length() <= 128
                && !password.toLowerCase(java.util.Locale.ROOT).contains(subject.toLowerCase(java.util.Locale.ROOT))
                && password.chars().distinct().count() >= 5;
    }

    static boolean strongPin(String pin) {
        return pin.length() >= MIN_PIN && pin.length() <= 64 && pin.chars().distinct().count() >= 3;
    }

    private static String newCode() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < CODE_GROUPS * CODE_GROUP; i++) {
            if (i > 0 && i % CODE_GROUP == 0) {
                sb.append('-');
            }
            sb.append(CODE_ALPHABET.charAt(RANDOM.nextInt(CODE_ALPHABET.length())));
        }
        return sb.toString();
    }

    /** A code has about 74 random bits, so a plain salted hash is enough: there is nothing to guess against. */
    private static String sealed(String code) {
        String salt = HexFormat.of().formatHex(randomBytes(8));
        return salt + ":" + Digests.sha256Hex(salt + "|" + code);
    }

    private static boolean opens(String kept, String code) {
        int at = kept.indexOf(':');
        String want = Digests.sha256Hex(kept.substring(0, at) + "|" + code.strip().toUpperCase(java.util.Locale.ROOT));
        return MessageDigest.isEqual(want.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                kept.substring(at + 1).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static String text(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    /** Takes a person off the sign-in list at once (a leaver): their next sign-in fails like an unknown user's. */
    public void block(String id) {
        cards.remove(id);
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

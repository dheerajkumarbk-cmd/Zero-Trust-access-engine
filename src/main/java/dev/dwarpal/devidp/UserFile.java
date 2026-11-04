package dev.dwarpal.devidp;

import dev.dwarpal.domain.Validate;
import dev.dwarpal.edge.WireFormat;
import dev.dwarpal.wire.JsonException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The development identity provider's local user file: one user per line,
 * <pre>
 *   &lt;subject&gt; pbkdf2-sha256 &lt;iterations&gt; &lt;salt b64&gt; &lt;hash b64&gt; &lt;credential id&gt; &lt;authenticator public key b64&gt;
 * </pre>
 * Passwords are stored only as salted PBKDF2-HMAC-SHA256 (NIST SP 800-63B section 5.1.1.2; OWASP
 * recommends 600,000 iterations). The last two fields register the user's (software) WebAuthn
 * authenticator. {@code #} starts a comment.
 */
public final class UserFile {

    public static final String SCHEME = "pbkdf2-sha256";
    public static final int DEFAULT_ITERATIONS = 600_000;
    /** Tests may go lower to stay fast; nothing below this is accepted. */
    public static final int MIN_ITERATIONS = 10_000;
    public static final int MAX_ITERATIONS = 10_000_000;
    public static final int MAX_PASSWORD_CHARS = 1024;
    private static final int MAX_FILE_BYTES = 1 << 20;
    private static final int MAX_USERS = 10_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** One registered user. Salt and hash are kept encoded, so nothing mutable is handed out. */
    public record User(String subjectId, int iterations, String salt, String hash, String credentialId,
                       PublicKey credentialKey) {
        public User {
            Validate.id(subjectId, "user.subjectId");
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                throw new IllegalArgumentException("iterations out of range");
            }
            if (Base64.getDecoder().decode(salt).length < SALT_BYTES
                    || Base64.getDecoder().decode(hash).length != HASH_BYTES) {
                throw new IllegalArgumentException("salt or hash has the wrong length");
            }
            Validate.id(credentialId, "user.credentialId");
            Objects.requireNonNull(credentialKey, "user.credentialKey");
        }

        /** Constant-time comparison of the derived key. */
        public boolean passwordMatches(char[] password) {
            return MessageDigest.isEqual(derive(password, Base64.getDecoder().decode(salt), iterations),
                    Base64.getDecoder().decode(hash));
        }
    }

    private final Map<String, User> users;
    private final int maxIterations;

    private UserFile(Map<String, User> users) {
        this.users = Map.copyOf(users);
        this.maxIterations = users.values().stream().mapToInt(User::iterations).max().orElse(MIN_ITERATIONS);
    }

    public static UserFile load(Path file) throws IOException {
        if (Files.size(file) > MAX_FILE_BYTES) {
            throw new IllegalArgumentException("user file too large");
        }
        return parse(Files.readString(file, StandardCharsets.UTF_8));
    }

    /** Parses the text form; errors give the line number, never its content. */
    public static UserFile parse(String text) {
        if (text.length() > MAX_FILE_BYTES) {
            throw new IllegalArgumentException("user file too large");
        }
        Map<String, User> out = new HashMap<>();
        String[] lines = text.split("\n", -1);
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n].strip();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            try {
                String[] f = line.split(" ", -1);
                if (f.length != 7 || !SCHEME.equals(f[1])) {
                    throw new IllegalArgumentException("wrong format");
                }
                User u = new User(f[0], Integer.parseInt(f[2]), f[3], f[4], f[5], WireFormat.readPublicKey(f[6]));
                if (out.putIfAbsent(u.subjectId(), u) != null || out.size() > MAX_USERS) {
                    throw new IllegalArgumentException("duplicate user or too many users");
                }
            } catch (IllegalArgumentException | JsonException e) {
                throw new IllegalArgumentException("user file line " + (n + 1) + " is invalid");
            }
        }
        return new UserFile(out);
    }

    /** A new line for the file, with a fresh random salt. The password array is wiped afterwards. */
    public static String line(String subjectId, char[] password, int iterations, String credentialId,
                              PublicKey credentialKey) {
        try {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            byte[] hash = derive(password, salt, iterations);
            Base64.Encoder b64 = Base64.getEncoder();
            User u = new User(subjectId, iterations, b64.encodeToString(salt), b64.encodeToString(hash), credentialId,
                    credentialKey);
            return u.subjectId() + " " + SCHEME + " " + iterations + " " + u.salt() + " " + u.hash() + " "
                    + credentialId + " " + WireFormat.publicKey(credentialKey);
        } finally {
            Arrays.fill(password, (char) 0);
        }
    }

    public Optional<User> user(String subjectId) {
        return Optional.ofNullable(users.get(subjectId));
    }

    /** The highest iteration count in the file, for checking unknown users at the same cost. */
    public int maxIterations() {
        return maxIterations;
    }

    static byte[] derive(char[] password, byte[] salt, int iterations) {
        if (password.length == 0 || password.length > MAX_PASSWORD_CHARS) {
            throw new IllegalArgumentException("password empty or too long");
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BYTES * 8);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2 unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }
}

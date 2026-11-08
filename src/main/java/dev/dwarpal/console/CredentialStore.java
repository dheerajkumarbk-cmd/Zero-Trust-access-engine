package dev.dwarpal.console;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * What a person has changed about their own sign-in: new password, new PIN, passkey, backup codes. One line per person
 * in {@code <lab>/console/credentials.txt} (owner-only). Nothing here can be read back: every secret is a salted one-way
 * hash, so a stolen copy of the file gives no password, PIN or passkey without guessing each one against PBKDF2. Without
 * a path nothing is kept on disk (the tests).
 *
 * <p>Once a person changes a secret, their line in {@code people.txt}, which the lab prints for the owner, is overwritten
 * with a random value, so the plain first password does not stay on the disk.
 */
final class CredentialStore {

    private static final String SEP = "\\|";
    private static final int FIELDS = 11;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** One person's state. Empty text means "not changed yet" or "not set". */
    record Entry(int passwordIterations, String passwordSalt, String passwordHash, Instant passwordChanged, String pinSalt,
                 String pinHash, Instant pinChanged, String passkeySalt, String passkeyHash, List<String> codes) {
        Entry {
            codes = List.copyOf(codes);
        }

        static Entry fresh(Instant now) {
            return new Entry(0, "", "", now, "", "", now, "", "", List.of());
        }

        Entry password(int iterations, String salt, String hash, Instant at) {
            return new Entry(iterations, salt, hash, at, pinSalt, pinHash, pinChanged, passkeySalt, passkeyHash, codes);
        }

        Entry pin(String salt, String hash, Instant at) {
            return new Entry(passwordIterations, passwordSalt, passwordHash, passwordChanged, salt, hash, at, passkeySalt,
                    passkeyHash, codes);
        }

        Entry passkey(String salt, String hash) {
            return new Entry(passwordIterations, passwordSalt, passwordHash, passwordChanged, pinSalt, pinHash, pinChanged,
                    salt, hash, codes);
        }

        Entry backupCodes(List<String> list) {
            return new Entry(passwordIterations, passwordSalt, passwordHash, passwordChanged, pinSalt, pinHash, pinChanged,
                    passkeySalt, passkeyHash, list);
        }

        boolean hasOwnSecrets() {
            return !passwordHash.isEmpty() || !pinHash.isEmpty();
        }
    }

    private final Path file;

    CredentialStore(Path file) {
        this.file = file;
    }

    Map<String, Entry> load() throws IOException {
        Map<String, Entry> out = new HashMap<>();
        if (file == null || !Files.isRegularFile(file)) {
            return out;
        }
        int n = 0;
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            n++;
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] f = line.split(SEP, -1);
            if (f.length != FIELDS) {
                throw new IllegalArgumentException("credentials file line " + n + " is invalid");
            }
            List<String> codes = f[10].isEmpty() ? List.of() : Arrays.asList(f[10].split(","));
            out.put(f[0], new Entry(Integer.parseInt(f[1]), f[2], f[3], Instant.parse(f[4]), f[5], f[6], Instant.parse(f[7]),
                    f[8], f[9], codes));
        }
        return out;
    }

    /** All or nothing: the old file stays until the new one is complete. */
    void save(Map<String, Entry> entries) throws IOException {
        if (file == null) {
            return;
        }
        Files.createDirectories(java.util.Objects.requireNonNull(file.getParent(), "credentials file has no folder"));
        StringBuilder sb = new StringBuilder("# id|iterations|password salt|password hash|changed|PIN salt|PIN hash|changed"
                + "|passkey salt|passkey hash|backup codes  (one-way hashes only)\n");
        entries.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(e -> {
            Entry x = e.getValue();
            sb.append(String.join("|", e.getKey(), Integer.toString(x.passwordIterations()), x.passwordSalt(), x.passwordHash(),
                    x.passwordChanged().toString(), x.pinSalt(), x.pinHash(), x.pinChanged().toString(), x.passkeySalt(),
                    x.passkeyHash(), String.join(",", x.codes()))).append('\n');
        });
        Path temp = file.resolveSibling(file.getFileName() + ".new");
        Files.writeString(temp, sb.toString(), StandardCharsets.UTF_8);
        OwnerOnly.restrict(temp);
        try {
            Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** Overwrites a person's plain first password and PIN in {@code people.txt}: they no longer work anyway. */
    void forgetFirstSecrets(String id) throws IOException {
        if (file == null) {
            return;
        }
        Path people = file.resolveSibling("people.txt");
        if (!Files.isRegularFile(people)) {
            return;
        }
        List<String> out = new ArrayList<>();
        for (String line : Files.readAllLines(people, StandardCharsets.UTF_8)) {
            String[] f = line.split(SEP, -1);
            out.add(f.length == 5 && f[0].equals(id) ? String.join("|", f[0], f[1], f[2], unusable(), unusable()) : line);
        }
        Files.write(people, out, StandardCharsets.UTF_8);
        OwnerOnly.restrict(people);
    }

    private static String unusable() {
        byte[] b = new byte[16];
        RANDOM.nextBytes(b);
        return "replaced-" + java.util.HexFormat.of().formatHex(b);
    }
}

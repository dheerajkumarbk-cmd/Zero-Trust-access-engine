package dev.dwarpal.lab;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.domain.Validate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The policy and playbook bundles an administrator installed, kept in the lab folder so that they survive a restart
 * and a lab reset. A file is sealed with HMAC-SHA256 under a seal key of its own, which sits in a separate owner-only
 * folder (made the first time, like the vault key). The administrators' signing keys are made fresh at every start,
 * so the original approvals cannot be checked again later; the seal and the audit record of the original approval
 * take their place. A file that is present but fails its seal is reported as refused and never installed; the lab
 * then refuses to start (see {@link LabWorld}). Nothing here ever logs the text or the key.
 */
public final class InstalledBundles {

    /** Which kind of bundle a file holds. */
    public enum Kind {
        POLICY, PLAYBOOK
    }

    /** A bundle read back from its file and found intact. */
    public record Saved(Kind kind, long sequence, String sha256, List<String> approvers, Instant installedAt,
                        String yaml) {
    }

    static final String DIR = "installed";
    static final String KEY_DIR = "installed-key";
    static final String KEY = "seal.key";
    private static final String MAGIC = "DWB1";
    private static final int MAX_FILE = 4 * 1024 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path dataDir;
    private final Path keyDir;
    private final Object lock = new Object();
    private final AtomicLong refused = new AtomicLong();
    private volatile String lastRefusal = "";

    public InstalledBundles(Path labDir) {
        this.dataDir = labDir.resolve(DIR);
        this.keyDir = labDir.resolve(KEY_DIR);
    }

    /** The file of this kind. */
    public Path file(Kind kind) {
        return dataDir.resolve(kind.name().toLowerCase(java.util.Locale.ROOT) + ".bundle");
    }

    /** True when a file of this kind exists (intact or not). */
    public boolean exists(Kind kind) {
        return Files.exists(file(kind));
    }

    /** How many times a saved file was refused since this object was made. */
    public long refusedCount() {
        return refused.get();
    }

    /** The plain reason of the latest refusal (never any content), or an empty text. */
    public String lastRefusal() {
        return lastRefusal;
    }

    /**
     * Keeps an installed bundle, replacing an earlier one of the same kind. The seal key is made on the first save; if
     * a saved file exists but the key does not, nothing is written (a new key would orphan that file).
     */
    public void save(Kind kind, long sequence, String yaml, List<String> approvers) throws IOException {
        if (sequence < 1 || yaml == null || yaml.isEmpty()) {
            throw new IllegalArgumentException("nothing to keep");
        }
        for (String a : approvers) {
            Validate.id(a, "approver");
        }
        synchronized (lock) {
            byte[] key = sealKey(true);
            Files.createDirectories(dataDir);
            String body = MAGIC + "\n"
                    + "kind=" + kind.name() + "\n"
                    + "sequence=" + sequence + "\n"
                    + "sha256=" + Digests.sha256Hex(yaml) + "\n"
                    + "approvers=" + String.join(",", approvers) + "\n"
                    + "installedAt=" + Instant.now() + "\n"
                    + "yaml=" + Base64.getEncoder().encodeToString(yaml.getBytes(StandardCharsets.UTF_8)) + "\n";
            String all = body + "mac=" + HexFormat.of().formatHex(mac(key, body.getBytes(StandardCharsets.ISO_8859_1)))
                    + "\n";
            Path target = file(kind);
            Path tmp = Files.createTempFile(dataDir, "bundle", ".tmp");
            try {
                LabPki.restrict(tmp);
                Files.write(tmp, all.getBytes(StandardCharsets.ISO_8859_1));
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } finally {
                Files.deleteIfExists(tmp);
            }
        }
    }

    /**
     * The saved bundle of this kind, or empty when there is none or it is refused (use {@link #exists} to tell the two
     * apart). A refusal is counted and its reason kept in {@link #lastRefusal()}; this method never throws.
     */
    public Optional<Saved> load(Kind kind) {
        Path f = file(kind);
        if (!Files.exists(f)) {
            return Optional.empty();
        }
        try {
            synchronized (lock) {
                return Optional.of(read(kind, f));
            }
        } catch (Refusal r) {
            refused.incrementAndGet();
            lastRefusal = kind.name().toLowerCase(java.util.Locale.ROOT) + " bundle: " + r.getMessage();
            return Optional.empty();
        } catch (IOException | RuntimeException e) {
            refused.incrementAndGet();
            lastRefusal = kind.name().toLowerCase(java.util.Locale.ROOT) + " bundle: the file cannot be read";
            return Optional.empty();
        }
    }

    private static final class Refusal extends RuntimeException {
        private static final long serialVersionUID = 1L;

        Refusal(String why) {
            super(why, null, false, false);
        }
    }

    private Saved read(Kind kind, Path f) throws IOException {
        if (Files.size(f) > MAX_FILE) {
            throw new Refusal("the file is too large");
        }
        byte[] key = sealKey(false);
        if (key == null) {
            throw new Refusal("the seal key is missing");
        }
        byte[] raw = Files.readAllBytes(f);
        String text = new String(raw, StandardCharsets.ISO_8859_1);
        int at = text.lastIndexOf("\nmac=");
        if (at < 0 || !text.endsWith("\n")) {
            throw new Refusal("the file is not in the expected form");
        }
        String body = text.substring(0, at + 1);
        String macHex = text.substring(at + 5, text.length() - 1);
        byte[] expected = mac(key, body.getBytes(StandardCharsets.ISO_8859_1));
        byte[] given;
        try {
            given = HexFormat.of().parseHex(macHex);
        } catch (IllegalArgumentException e) {
            throw new Refusal("the seal does not match");
        }
        if (!MessageDigest.isEqual(expected, given)) {
            throw new Refusal("the seal does not match");
        }
        String[] lines = body.split("\n", -1);
        if (lines.length != 8 || !lines[0].equals(MAGIC) || !lines[7].isEmpty()) {
            throw new Refusal("the file is not in the expected form");
        }
        String k = value(lines[1], "kind");
        if (!k.equals(kind.name())) {
            throw new Refusal("the file holds another kind of bundle");
        }
        long sequence;
        Instant at2;
        String yaml;
        try {
            sequence = Long.parseLong(value(lines[2], "sequence"));
            at2 = Instant.parse(value(lines[5], "installedAt"));
            yaml = new String(Base64.getDecoder().decode(value(lines[6], "yaml")), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException | java.time.DateTimeException e) {
            throw new Refusal("the file is not in the expected form");
        }
        if (sequence < 1) {
            throw new Refusal("the sequence is not valid");
        }
        String hash = value(lines[3], "sha256");
        if (!hash.equals(Digests.sha256Hex(yaml))) {
            throw new Refusal("the text does not match its hash");
        }
        String a = value(lines[4], "approvers");
        List<String> approvers = a.isEmpty() ? List.of() : List.of(a.split(",", -1));
        return new Saved(kind, sequence, hash, approvers, at2, yaml);
    }

    private static String value(String line, String name) {
        if (!line.startsWith(name + "=")) {
            throw new Refusal("the file is not in the expected form");
        }
        return line.substring(name.length() + 1);
    }

    private static byte[] mac(byte[] key, byte[] data) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            return m.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is not available", e);
        }
    }

    /** The seal key; with {@code create}, made once, owner-only (but never when a saved file already exists). */
    private byte[] sealKey(boolean create) throws IOException {
        Path keyFile = keyDir.resolve(KEY);
        if (Files.isRegularFile(keyFile)) {
            byte[] raw = Files.readAllBytes(keyFile);
            if (raw.length != 32) {
                if (create) {
                    throw new IOException("the seal key file is damaged");
                }
                throw new Refusal("the seal key is damaged");
            }
            return raw;
        }
        if (!create) {
            return null;
        }
        for (Kind k : Kind.values()) {
            if (Files.exists(file(k))) {
                throw new IOException("a saved bundle exists but its seal key is missing, so nothing was kept");
            }
        }
        Files.createDirectories(keyDir);
        LabPki.restrict(keyDir);
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        Files.write(keyFile, raw);
        LabPki.restrict(keyFile);
        return raw;
    }
}

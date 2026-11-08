package dev.dwarpal.console.vault;

import dev.dwarpal.console.OwnerOnly;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * The vault's file: everything in it sealed with AES-256-GCM (confidentiality and tamper detection in one), under a key of
 * its own that sits in a separate owner-only file. The passkey decides who may ask the vault; this layer decides that the
 * file alone, or a copy of it, tells nobody anything. A new random nonce is used for every save, and the file is replaced
 * whole (written beside it, then moved over it). A wrong key or a changed byte makes {@link #read} fail, and the console
 * refuses to start on a vault it cannot open.
 */
public final class VaultStore {

    static final String DATA = "vault.dat";
    static final String KEY = "vault.key";
    private static final byte[] MAGIC = "DWV1".getBytes(StandardCharsets.US_ASCII);
    private static final int NONCE = 12;
    private static final int TAG_BITS = 128;

    private final Path data;
    private final SecretKey key;
    private final Object lock = new Object();
    private static final SecureRandom KEY_RANDOM = new SecureRandom();
    private final SecureRandom random = new SecureRandom();

    private VaultStore(Path data, SecretKey key) {
        this.data = data;
        this.key = key;
    }

    /**
     * Opens the vault: the data in {@code dataDir} and the key in {@code keyDir}, two folders so that the key can be kept
     * somewhere the data is not. The key is made the first time. A vault with no key is refused, never remade.
     */
    public static VaultStore open(Path dataDir, Path keyDir) throws IOException {
        Files.createDirectories(dataDir);
        Files.createDirectories(keyDir);
        Path keyFile = keyDir.resolve(KEY);
        Path dataFile = dataDir.resolve(DATA);
        byte[] raw;
        if (Files.isRegularFile(keyFile)) {
            raw = Files.readAllBytes(keyFile);
            if (raw.length != 32) {
                throw new IOException("the vault key file is damaged");
            }
        } else {
            if (Files.exists(dataFile)) {
                throw new IOException("the vault has data but its key file is missing, so it cannot be opened");
            }
            raw = new byte[32];
            KEY_RANDOM.nextBytes(raw);
            Files.write(keyFile, raw);
            OwnerOnly.restrict(keyFile);
        }
        return new VaultStore(dataFile, new SecretKeySpec(raw, "AES"));
    }

    /** The sealed text, opened; an empty vault is {@code {}}. */
    public String read() throws IOException {
        synchronized (lock) {
            if (!Files.isRegularFile(data)) {
                return "{}";
            }
            byte[] all = Files.readAllBytes(data);
            if (all.length < MAGIC.length + NONCE + TAG_BITS / 8 || !Arrays.equals(Arrays.copyOf(all, MAGIC.length), MAGIC)) {
                throw new IOException("the vault file is damaged");
            }
            try {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, all, MAGIC.length, NONCE));
                c.updateAAD(MAGIC);
                return new String(c.doFinal(all, MAGIC.length + NONCE, all.length - MAGIC.length - NONCE), StandardCharsets.UTF_8);
            } catch (GeneralSecurityException e) {
                throw new IOException("the vault file does not open with its key: it was changed or the key is wrong", e);
            }
        }
    }

    /** Seals the text and replaces the file. */
    public void write(String plain) throws IOException {
        synchronized (lock) {
            try {
                byte[] nonce = new byte[NONCE];
                random.nextBytes(nonce);
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
                c.updateAAD(MAGIC);
                byte[] sealed = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
                byte[] out = new byte[MAGIC.length + NONCE + sealed.length];
                System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
                System.arraycopy(nonce, 0, out, MAGIC.length, NONCE);
                System.arraycopy(sealed, 0, out, MAGIC.length + NONCE, sealed.length);
                Path dir = data.toAbsolutePath().getParent();
                if (dir == null) {
                    throw new IOException("the vault file has no folder");
                }
                Path tmp = Files.createTempFile(dir, "vault", ".tmp");
                try {
                    OwnerOnly.restrict(tmp);
                    Files.write(tmp, out);
                    Files.move(tmp, data, StandardCopyOption.REPLACE_EXISTING);
                    OwnerOnly.restrict(data);
                } finally {
                    Files.deleteIfExists(tmp);
                }
            } catch (GeneralSecurityException e) {
                throw new IOException("the vault could not be sealed", e);
            }
        }
    }

    /** The data file, for tests that check what is on disk. */
    public Path dataFile() {
        return data;
    }
}

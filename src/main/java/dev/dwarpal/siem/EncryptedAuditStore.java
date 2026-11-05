package dev.dwarpal.siem;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.AuditSink;
import dev.dwarpal.audit.AuditSource;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The audit trail at rest: an append-only file in which every record is encrypted on its own with
 * AES-256-GCM (JDK provider), so a stolen disk or backup shows nothing, and a changed byte is caught.
 *
 * <pre>
 * file   = header frame*
 * header = "DWAS" version(1) storeId(16 random bytes)
 * frame  = length(4) nonce(12) ciphertext-and-tag(length - 12)
 * AAD    = "dwarpal/siem/store/v1" storeId sequence(8)
 * </pre>
 *
 * <ul>
 *   <li>A fresh random 96-bit nonce per record (NIST SP 800-38D 8.2.2; at most 2^31 records per file,
 *       far below the 2^32 bound for random nonces).</li>
 *   <li>The sequence number and the store id are associated data: a frame moved to another position,
 *       repeated (replayed), or copied from another store file fails authentication.</li>
 *   <li>The store accepts only the next record of the chain (sequence + 1, linked to the previous MAC),
 *       so the file can never hold a gap or a fork, whoever calls {@link #write}.</li>
 *   <li>The key is passed in (from a KMS or an environment secret) and never written anywhere.</li>
 *   <li>A record that fails to decrypt, a torn or oversized frame, or a broken link is <em>damage</em>:
 *       records before it stay readable, reading past it throws, and every later write is refused
 *       (fail closed). Removing whole frames from the end is not visible here: that is what
 *       {@link HeadAnchor} is for.</li>
 * </ul>
 *
 * Thread-safe; one writer per file (a file lock refuses a second store on the same file).
 */
public final class EncryptedAuditStore implements AuditSink, AuditSource, Closeable {

    /** Largest plaintext of one record. A payload is at most 256 KiB of JSON, up to 3 bytes a character. */
    public static final int MAX_RECORD_BYTES = 1 << 20;
    /** Index limit; keeps random nonces far below the 2^32 bound of SP 800-38D. */
    public static final int MAX_RECORDS = Integer.MAX_VALUE - 8;

    static final byte[] MAGIC = {'D', 'W', 'A', 'S'};
    static final byte VERSION = 1;
    static final int STORE_ID_BYTES = 16;
    static final int HEADER_BYTES = MAGIC.length + 1 + STORE_ID_BYTES;
    static final int NONCE_BYTES = 12;
    static final int TAG_BITS = 128;
    private static final int MAX_FRAME = NONCE_BYTES + MAX_RECORD_BYTES + TAG_BITS / 8;
    private static final int MIN_FRAME = NONCE_BYTES + TAG_BITS / 8 + 40;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] AAD_DOMAIN = "dwarpal/siem/store/v1".getBytes(StandardCharsets.US_ASCII);

    /** When a write counts as done. */
    public enum Durability {
        /** {@code fsync} after every record: survives a power cut. The default for production. */
        SYNC_EVERY_RECORD,
        /** Handed to the operating system only: survives a process crash, not a power cut. */
        OS_BUFFERED
    }

    private final Object lock = new Object();
    private final SecretKey key;
    private final Durability durability;
    private final FileChannel writer;
    private final FileChannel reader;
    private final FileLock writerLock;
    private final byte[] storeId;
    private long[] offsets = new long[1024];
    private int count;
    private long end;
    private String lastMac = AuditLog.GENESIS;
    private Instant lastAt;
    private String damage;
    private boolean closed;

    private EncryptedAuditStore(SecretKey key, Durability durability, FileChannel writer, FileChannel reader,
                                FileLock writerLock, byte[] storeId) {
        this.key = key;
        this.durability = durability;
        this.writer = writer;
        this.reader = reader;
        this.writerLock = writerLock;
        this.storeId = storeId;
    }

    /**
     * Opens the store at {@code file}, creating it if it does not exist, and checks every record in it.
     * Damage found here does not stop the open: {@link #damage()} reports it, the good records before it
     * stay readable, and writes are refused.
     *
     * @param key a 256-bit AES key
     * @throws IllegalArgumentException if the key is not a 256-bit AES key, or the file is not a store
     * @throws IllegalStateException    if another store already has the file open for writing
     */
    public static EncryptedAuditStore open(Path file, SecretKey key, Durability durability) {
        requireAesKey(key);
        Objects.requireNonNull(durability, "durability");
        Objects.requireNonNull(file, "file");
        FileChannel w = null;
        FileChannel r = null;
        try {
            if (Files.notExists(file)) {
                create(file);
            }
            w = FileChannel.open(file, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
            // Lock a byte far past the end, so readers of the data itself are never blocked (Windows locks
            // are mandatory) while a second writer is.
            FileLock l = w.tryLock(Long.MAX_VALUE - 1, 1, false);
            if (l == null) {
                throw new IllegalStateException("audit store is already open for writing elsewhere");
            }
            r = FileChannel.open(file, StandardOpenOption.READ);
            byte[] id = readHeader(r);
            EncryptedAuditStore s = new EncryptedAuditStore(key, durability, w, r, l, id);
            s.scan();
            return s;
        } catch (IOException e) {
            closeQuietly(w);
            closeQuietly(r);
            throw new UncheckedIOException("cannot open audit store", e);
        } catch (RuntimeException e) {
            closeQuietly(w);
            closeQuietly(r);
            throw e;
        }
    }

    private static void create(Path file) throws IOException {
        byte[] id = new byte[STORE_ID_BYTES];
        RANDOM.nextBytes(id);
        ByteBuffer h = ByteBuffer.allocate(HEADER_BYTES).put(MAGIC).put(VERSION).put(id).flip();
        try (FileChannel c = FileChannel.open(file, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            writeFully(c, h);
            c.force(true);
        }
    }

    private static byte[] readHeader(FileChannel r) throws IOException {
        ByteBuffer h = ByteBuffer.allocate(HEADER_BYTES);
        if (readFully(r, h, 0) < HEADER_BYTES) {
            throw new IllegalArgumentException("not an audit store: header too short");
        }
        h.flip();
        byte[] magic = new byte[MAGIC.length];
        h.get(magic);
        if (!Arrays.equals(magic, MAGIC) || h.get() != VERSION) {
            throw new IllegalArgumentException("not an audit store, or an unknown version");
        }
        byte[] id = new byte[STORE_ID_BYTES];
        h.get(id);
        return id;
    }

    /** Reads and checks every frame once, building the index of record offsets. */
    private void scan() throws IOException {
        synchronized (lock) {
            scanLocked();
        }
    }

    private void scanLocked() throws IOException {
        long size = reader.size();
        long pos = HEADER_BYTES;
        while (pos < size) {
            if (count >= MAX_RECORDS) {
                damage = "record " + (count + 1) + ": store holds more records than allowed";
                return;
            }
            Frame f;
            try {
                f = readFrame(pos, count + 1L);
            } catch (Damage d) {
                damage = "record " + (count + 1) + ": " + d.getMessage();
                return;
            }
            if (!f.record.previousMac().equals(lastMac)) {
                damage = "record " + (count + 1) + ": chain link broken";
                return;
            }
            index(pos);
            lastMac = f.record.mac();
            lastAt = f.record.at();
            pos = f.next;
        }
        end = pos;
    }

    private record Frame(AuditRecord record, long next) {
    }

    /** Detected damage of the file; never carries record content. */
    private static final class Damage extends Exception {
        private static final long serialVersionUID = 1L;

        Damage(String message) {
            super(message, null, false, false);
        }
    }

    private Frame readFrame(long pos, long expectedSequence) throws IOException, Damage {
        ByteBuffer len = ByteBuffer.allocate(4);
        if (readFully(reader, len, pos) < 4) {
            throw new Damage("torn frame at the end of the file");
        }
        int n = len.flip().getInt();
        if (n < MIN_FRAME || n > MAX_FRAME) {
            throw new Damage("frame length out of bounds");
        }
        ByteBuffer body = ByteBuffer.allocate(n);
        if (readFully(reader, body, pos + 4) < n) {
            throw new Damage("torn frame at the end of the file");
        }
        byte[] frame = body.array();
        byte[] plain;
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, frame, 0, NONCE_BYTES));
            c.updateAAD(aad(expectedSequence));
            plain = c.doFinal(frame, NONCE_BYTES, n - NONCE_BYTES);
        } catch (AEADBadTagException e) {
            throw new Damage("authentication failed: altered, moved, replayed or from another store");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM unavailable", e);
        }
        AuditRecord rec;
        try {
            rec = decode(plain);
        } catch (RuntimeException e) {
            throw new Damage("undecodable record");
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
        if (rec.sequence() != expectedSequence) {
            throw new Damage("sequence mismatch");
        }
        return new Frame(rec, pos + 4 + n);
    }

    private void index(long offset) {
        if (count == offsets.length) {
            offsets = Arrays.copyOf(offsets, (int) Math.min(MAX_RECORDS, offsets.length * 2L));
        }
        offsets[count++] = offset;
    }

    /**
     * Appends {@code record} durably, or throws. Only the next record of the chain is accepted.
     *
     * @throws IllegalStateException    if the store is closed or damaged, or the record is not the next one
     * @throws IllegalArgumentException if the record is larger than {@link #MAX_RECORD_BYTES}
     * @throws UncheckedIOException     if the file cannot be written (the store is then damaged)
     */
    @Override
    public void write(AuditRecord record) {
        Objects.requireNonNull(record, "record");
        synchronized (lock) {
            if (closed) {
                throw new IllegalStateException("audit store is closed");
            }
            if (damage != null) {
                throw new IllegalStateException("audit store is damaged; refusing to append");
            }
            if (count >= MAX_RECORDS) {
                throw new IllegalStateException("audit store is full; start a new file");
            }
            if (record.sequence() != count + 1L) {
                throw new IllegalStateException("expected sequence " + (count + 1L) + ", got " + record.sequence());
            }
            if (!record.previousMac().equals(lastMac)) {
                throw new IllegalStateException("record does not link to the stored chain");
            }
            byte[] plain = encode(record);
            byte[] nonce = new byte[NONCE_BYTES];
            RANDOM.nextBytes(nonce);
            byte[] sealed;
            try {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
                c.updateAAD(aad(record.sequence()));
                sealed = c.doFinal(plain);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("AES-GCM unavailable", e);
            } finally {
                Arrays.fill(plain, (byte) 0);
            }
            ByteBuffer frame = ByteBuffer.allocate(4 + NONCE_BYTES + sealed.length)
                    .putInt(NONCE_BYTES + sealed.length).put(nonce).put(sealed).flip();
            try {
                writeFully(writer, frame);
                if (durability == Durability.SYNC_EVERY_RECORD) {
                    writer.force(false);
                }
            } catch (IOException e) {
                damage = "record " + record.sequence() + ": write failed; the file may hold a torn frame";
                throw new UncheckedIOException("audit store write failed", e);
            }
            index(end);
            end += frame.limit();
            lastMac = record.mac();
            lastAt = record.at();
        }
    }

    /**
     * Records after {@code sequence}, decrypted and checked again on the way out (the file may have been
     * changed since it was opened).
     *
     * @throws IllegalStateException if the read reaches damage: what lies beyond cannot be trusted, and a
     *                               reader must not take the end of the good records for the end of the trail
     */
    @Override
    public List<AuditRecord> after(long sequence, int max) {
        synchronized (lock) {
            if (closed) {
                throw new IllegalStateException("audit store is closed");
            }
            long from = Math.max(0, sequence);
            int n = (int) Math.max(0, Math.min(Math.min(max, MAX_BATCH), count - from));
            if (n == 0) {
                if (damage != null && from >= count && max > 0) {
                    throw new IllegalStateException("audit store damaged: " + damage);
                }
                return List.of();
            }
            List<AuditRecord> out = new ArrayList<>(n);
            for (int i = 0; i < n; i++) {
                int idx = (int) from + i;
                try {
                    out.add(readFrame(offsets[idx], idx + 1L).record);
                } catch (Damage d) {
                    damage = "record " + (idx + 1) + ": " + d.getMessage();
                    if (out.isEmpty()) {
                        throw new IllegalStateException("audit store damaged: " + damage);
                    }
                    return List.copyOf(out);
                } catch (IOException e) {
                    throw new UncheckedIOException("audit store read failed", e);
                }
            }
            return List.copyOf(out);
        }
    }

    @Override
    public long lastSequence() {
        synchronized (lock) {
            return count;
        }
    }

    /** The newest stored record's position and MAC: what {@link HeadAnchor} writes down. */
    public AuditLog.Head head() {
        synchronized (lock) {
            return new AuditLog.Head(count, lastMac);
        }
    }

    /** Time of the newest stored record, if any. */
    public Optional<Instant> lastTime() {
        synchronized (lock) {
            return Optional.ofNullable(lastAt);
        }
    }

    /** Why the store refuses writes, if it found damage. */
    public Optional<String> damage() {
        synchronized (lock) {
            return Optional.ofNullable(damage);
        }
    }

    @Override
    public void close() throws IOException {
        synchronized (lock) {
            if (closed) {
                return;
            }
            closed = true;
            try {
                writerLock.release();
            } finally {
                try {
                    writer.close();
                } finally {
                    reader.close();
                }
            }
        }
    }

    // ---- encoding ------------------------------------------------------------------------------------

    private byte[] aad(long sequence) {
        return ByteBuffer.allocate(AAD_DOMAIN.length + STORE_ID_BYTES + 8).put(AAD_DOMAIN).put(storeId)
                .putLong(sequence).array();
    }

    static byte[] encode(AuditRecord r) {
        byte[][] parts = {utf8(r.type()), utf8(r.actor()), utf8(r.payloadJson()), utf8(r.previousMac()), utf8(r.mac())};
        long size = 8 + 8 + 4;
        for (byte[] p : parts) {
            size += 4L + p.length;
        }
        if (size > MAX_RECORD_BYTES) {
            throw new IllegalArgumentException("audit record larger than " + MAX_RECORD_BYTES + " bytes");
        }
        ByteBuffer b = ByteBuffer.allocate((int) size);
        b.putLong(r.sequence()).putLong(r.at().getEpochSecond()).putInt(r.at().getNano());
        for (byte[] p : parts) {
            b.putInt(p.length).put(p);
        }
        return b.array();
    }

    static AuditRecord decode(byte[] plain) {
        ByteBuffer b = ByteBuffer.wrap(plain);
        long seq = b.getLong();
        Instant at = Instant.ofEpochSecond(b.getLong(), b.getInt());
        String type = str(b);
        String actor = str(b);
        String payload = str(b);
        String prev = str(b);
        String mac = str(b);
        if (b.hasRemaining()) {
            throw new IllegalArgumentException("trailing bytes");
        }
        return new AuditRecord(seq, at, type, actor, payload, prev, mac);
    }

    private static String str(ByteBuffer b) {
        int n = b.getInt();
        if (n < 0 || n > b.remaining()) {
            throw new IllegalArgumentException("bad length");
        }
        byte[] s = new byte[n];
        b.get(s);
        return new String(s, StandardCharsets.UTF_8);
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // ---- io ------------------------------------------------------------------------------------------

    private static void writeFully(FileChannel c, ByteBuffer b) throws IOException {
        while (b.hasRemaining()) {
            c.write(b);
        }
    }

    private static int readFully(FileChannel c, ByteBuffer b, long pos) throws IOException {
        int total = 0;
        while (b.hasRemaining()) {
            int n = c.read(b, pos + total);
            if (n < 0) {
                break;
            }
            total += n;
        }
        return total;
    }

    private static void closeQuietly(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (IOException ignored) {
                // already failing
            }
        }
    }

    static void requireAesKey(SecretKey key) {
        Objects.requireNonNull(key, "store key");
        byte[] encoded = key.getEncoded();
        try {
            if (!"AES".equalsIgnoreCase(key.getAlgorithm()) || encoded == null || encoded.length != 32) {
                throw new IllegalArgumentException("store key must be a 256-bit AES key");
            }
            if (MessageDigest.isEqual(encoded, new byte[32])) {
                throw new IllegalArgumentException("store key must not be all zeros");
            }
        } finally {
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
        }
    }
}

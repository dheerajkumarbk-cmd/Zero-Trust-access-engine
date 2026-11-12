package dev.dwarpal.console;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.lab.LabAudit;
import dev.dwarpal.siem.EncryptedAuditStore;
import dev.dwarpal.siem.HeadAnchor;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * The console's own audit trail, kept on disk so it survives a restart. The simulated organisation's chain is a story
 * that is replayed at every start with a new random key; what people and administrators did on the console is not
 * a story and must not vanish when the lab stops. This trail is that record:
 *
 * <ul>
 *   <li>one hash chain (the same {@link AuditLog} as everywhere else), stored in an {@link EncryptedAuditStore}
 *       (AES-256-GCM, one authenticated frame per record, flushed before the console acts);</li>
 *   <li>three different keys (store encryption, chain MAC, head anchor) in {@code trail.keys}, owner-only, away
 *       from the database and from the records;</li>
 *   <li>the chain's head is anchored to a separate file every few seconds, so a truncated or replaced trail is
 *       caught at the next start;</li>
 *   <li>at start the whole trail is checked; a damaged or cut trail is <em>not</em> repaired or replaced: the start
 *       fails with a plain message and the files stay as they are for the owner to look at.</li>
 * </ul>
 *
 * <p>Record times are real UTC; the scenario clock's time is a field of the record.
 */
public final class ConsoleTrail implements Closeable {

    static final String STORE = "audit.store";
    static final String ANCHOR = "audit.anchor";
    static final String KEYS = "trail.keys";
    private static final Duration ANCHOR_EVERY = Duration.ofSeconds(5);
    private static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path dir;
    private final EncryptedAuditStore store;
    private final AuditLog log;
    private final LabAudit view;
    private final HeadAnchor anchor;
    private final ScheduledExecutorService schedule;
    private final AtomicLong anchorFailures = new AtomicLong();
    private final Object lock = new Object();
    private AuditLog.Head anchored;
    private boolean closed;

    private ConsoleTrail(Path dir, EncryptedAuditStore store, AuditLog log, LabAudit view, HeadAnchor anchor) {
        this.dir = dir;
        this.store = store;
        this.log = log;
        this.view = view;
        this.anchor = anchor;
        this.schedule = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "console-trail-anchor");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Opens the trail in {@code dir} (created on first use), resumes its chain and checks it.
     *
     * @throws IllegalStateException with a plain message if the saved trail is damaged, cut short, replaced or cannot be
     *                               read without its key file
     */
    public static ConsoleTrail open(Path dir, Clock clock) {
        Objects.requireNonNull(dir, "dir");
        Objects.requireNonNull(clock, "clock");
        EncryptedAuditStore store = null;
        try {
            Files.createDirectories(dir);
            OwnerOnly.restrict(dir);
            Path storeFile = dir.resolve(STORE);
            Path keyFile = dir.resolve(KEYS);
            Keys keys;
            if (Files.exists(keyFile)) {
                keys = readKeys(keyFile);
            } else if (Files.exists(storeFile)) {
                throw new IllegalStateException("The saved audit trail in " + dir + " cannot be read: its key file "
                        + KEYS + " is missing. Put the key file back, or move that folder aside to start a new trail.");
            } else {
                keys = createKeys(keyFile);
            }
            store = EncryptedAuditStore.open(storeFile, keys.store(), EncryptedAuditStore.Durability.SYNC_EVERY_RECORD);
            if (store.damage().isPresent()) {
                throw new IllegalStateException(refusal(dir, "it is damaged (" + store.damage().get() + ")"));
            }
            HeadAnchor anchor = new HeadAnchor(dir.resolve(ANCHOR), keys.anchor(), clock);
            LabAudit view = new LabAudit(store, keys.chain(), anchor);
            LabAudit.Verified v = view.verify();
            if (!v.intact()) {
                throw new IllegalStateException(refusal(dir, "it failed its check (" + v.reason() + ", first problem at record "
                        + v.firstBad() + ")"));
            }
            AuditLog log = new AuditLog(keys.chain(), store, store.head());
            ConsoleTrail trail = new ConsoleTrail(dir, store, log, view, anchor);
            trail.anchorNow();
            trail.schedule.scheduleWithFixedDelay(trail::anchorQuietly, ANCHOR_EVERY.toMillis(), ANCHOR_EVERY.toMillis(),
                    TimeUnit.MILLISECONDS);
            return trail;
        } catch (IOException e) {
            closeQuietly(store);
            throw new UncheckedIOException("cannot open the audit trail in " + dir, e);
        } catch (RuntimeException e) {
            closeQuietly(store);
            throw e;
        }
    }

    private static String refusal(Path dir, String why) {
        return "The saved audit trail in " + dir + " was not accepted: " + why + ". It is left exactly as it is. "
                + "Look into it, or move that folder aside to start a new trail.";
    }

    /** Where records are written. */
    public AuditLog log() {
        return log;
    }

    /** The read side (paging, one record, verify) over the saved trail. */
    public LabAudit view() {
        return view;
    }

    /** Records in the trail now. */
    public long records() {
        return store.lastSequence();
    }

    Path dir() {
        return dir;
    }

    /** Anchor runs that failed since the start (a full disk, a damaged anchor file). */
    public long anchorFailures() {
        return anchorFailures.get();
    }

    /** Writes the current head to the anchor now (nothing to anchor while the trail is empty). */
    public void anchorNow() {
        synchronized (lock) {
            AuditLog.Head head = log.head();
            if (head.sequence() < 1 || head.equals(anchored)) {
                return;
            }
            anchor.anchor(head);
            anchored = head;
        }
    }

    private void anchorQuietly() {
        try {
            anchorNow();
        } catch (RuntimeException e) {
            anchorFailures.incrementAndGet();
        }
    }

    @Override
    public void close() throws IOException {
        synchronized (lock) {
            if (closed) {
                return;
            }
            closed = true;
        }
        schedule.shutdown();
        try {
            anchorNow();
        } catch (RuntimeException e) {
            anchorFailures.incrementAndGet();
        } finally {
            store.close();
        }
    }

    // ---- keys ------------------------------------------------------------------------------------------------

    private record Keys(SecretKey store, SecretKey chain, SecretKey anchor) {
    }

    private static Keys createKeys(Path file) throws IOException {
        byte[][] raw = new byte[3][32];
        StringBuilder text = new StringBuilder("# Keys of the saved audit trail. Keep this file private and away from the trail.\n");
        String[] names = {"store", "chain", "anchor"};
        for (int i = 0; i < raw.length; i++) {
            RANDOM.nextBytes(raw[i]);
            text.append(names[i]).append(' ').append(HexFormat.of().formatHex(raw[i])).append('\n');
        }
        Files.createFile(file);
        OwnerOnly.restrict(file);
        Files.writeString(file, text, StandardCharsets.US_ASCII, StandardOpenOption.WRITE);
        return new Keys(new SecretKeySpec(raw[0], "AES"), new SecretKeySpec(raw[1], "HmacSHA256"),
                new SecretKeySpec(raw[2], "HmacSHA256"));
    }

    private static Keys readKeys(Path file) throws IOException {
        byte[][] raw = new byte[3][];
        String[] names = {"store", "chain", "anchor"};
        for (String line : Files.readAllLines(file, StandardCharsets.US_ASCII)) {
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] p = line.strip().split(" ", -1);
            for (int i = 0; i < names.length; i++) {
                if (p.length == 2 && p[0].equals(names[i]) && HEX64.matcher(p[1]).matches() && raw[i] == null) {
                    raw[i] = HexFormat.of().parseHex(p[1]);
                }
            }
        }
        for (byte[] k : raw) {
            if (k == null) {
                throw new IllegalStateException("The key file " + file + " of the audit trail is damaged.");
            }
        }
        return new Keys(new SecretKeySpec(raw[0], "AES"), new SecretKeySpec(raw[1], "HmacSHA256"),
                new SecretKeySpec(raw[2], "HmacSHA256"));
    }

    private static void closeQuietly(EncryptedAuditStore s) {
        if (s != null) {
            try {
                s.close();
            } catch (IOException e) {
                // the failure being reported is the one that matters
            }
        }
    }
}

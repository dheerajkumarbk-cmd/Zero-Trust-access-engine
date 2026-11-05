package dev.dwarpal.siem;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.crypto.Canonical;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Writes the audit chain's head (sequence and MAC of the newest record) to a separate file, so a
 * reader can tell a complete trail from a truncated or rewritten one ({@code AuditCursor.checkAgainst}).
 * The anchor file belongs somewhere the audit writer cannot change (another disk, another account, a
 * WORM share); this class makes it tamper-evident on top of that:
 *
 * <ul>
 *   <li>the line is authenticated with HMAC-SHA256 under an <em>anchor key</em>, separate from the
 *       audit and store keys (key separation);</li>
 *   <li>it is replaced atomically (temporary file, then move), so a crash leaves the old or the new
 *       anchor, never half of one;</li>
 *   <li>it only moves forward: an older head, or another MAC at the same position, is refused
 *       (rollback and rewrite);</li>
 *   <li>once this instance has written or read an anchor, a missing file is tampering, not "no anchor";</li>
 *   <li>every write (even of an unchanged head) renews its time, and {@link #readFresh} refuses an anchor
 *       older than the schedule allows, so an old anchor file put back after a restart is caught.</li>
 * </ul>
 *
 * <pre>dwarpal-anchor/v1 sequence mac writtenAt hmac</pre>
 */
public final class HeadAnchor {

    static final String VERSION = "dwarpal-anchor/v1";
    private static final String DOMAIN = "dwarpal/siem/anchor/v1";
    private static final int MAX_FILE_BYTES = 512;
    private static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");
    /** The shortest schedule accepted; anything faster only wears the disk. */
    public static final Duration MIN_INTERVAL = Duration.ofSeconds(1);
    private static final Duration MAX_SKEW = Duration.ofMinutes(2);

    private final Object lock = new Object();
    private final Path file;
    private final SecretKey key;
    private final Clock clock;
    private final AtomicLong failures = new AtomicLong();
    private AuditLog.Head last;

    /**
     * @param file the anchor file (its directory must exist)
     * @param key  at least 32 bytes, used for nothing else
     */
    public HeadAnchor(Path file, SecretKey key, Clock clock) {
        this.file = Objects.requireNonNull(file, "file").toAbsolutePath();
        this.key = requireKey(key);
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Writes {@code head} as the new anchor (on demand).
     *
     * @throws IllegalStateException if it would move the anchor back or rewrite it, or the current
     *                               anchor file is damaged
     * @throws UncheckedIOException  if the file cannot be written
     */
    public void anchor(AuditLog.Head head) {
        Objects.requireNonNull(head, "head");
        if (head.sequence() < 0 || !HEX64.matcher(head.mac()).matches()) {
            throw new IllegalArgumentException("not a chain head");
        }
        synchronized (lock) {
            Optional<AuditLog.Head> current = read();
            if (current.isPresent()) {
                AuditLog.Head c = current.get();
                if (head.sequence() < c.sequence()) {
                    throw new IllegalStateException("anchor rollback refused: " + head.sequence() + " < " + c.sequence());
                }
                if (head.sequence() == c.sequence() && !head.mac().equals(c.mac())) {
                    throw new IllegalStateException("anchor rewrite refused at " + c.sequence());
                }
                // The same head is written again with a new time: a heartbeat, so a reader can tell a live
                // anchor from an old copy put back (see readFresh, red-team R-A1).
            }
            String at = clock.instant().toString();
            String line = VERSION + " " + head.sequence() + " " + head.mac() + " " + at + " "
                    + hmac(head.sequence(), head.mac(), at) + "\n";
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            try {
                // A fresh temporary file every time (CREATE_NEW never follows a planted link or reuses a file).
                Files.deleteIfExists(tmp);
                Files.writeString(tmp, line, StandardCharsets.US_ASCII, StandardOpenOption.CREATE_NEW,
                        StandardOpenOption.WRITE);
                try {
                    Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (IOException e) {
                throw new UncheckedIOException("cannot write the audit anchor", e);
            }
            last = head;
        }
    }

    /**
     * The anchored head; empty only if no anchor was ever written (as far as this instance knows).
     *
     * @throws IllegalStateException if the anchor is damaged, forged, or gone after it existed
     */
    public Optional<AuditLog.Head> read() {
        return readAnchored().map(Anchored::head);
    }

    /**
     * The anchored head, which must have been written within {@code maxAge} (the schedule interval plus a
     * margin). An older anchor means the schedule stopped, or an old copy of the file was put back to hide
     * a truncation: both count as tampering.
     *
     * @throws IllegalStateException if the anchor is missing, stale, dated in the future, damaged or forged
     */
    public AuditLog.Head readFresh(Duration maxAge) {
        Objects.requireNonNull(maxAge, "maxAge");
        Anchored a = readAnchored().orElseThrow(() -> new IllegalStateException("no audit anchor"));
        Instant now = clock.instant();
        if (a.writtenAt().isBefore(now.minus(maxAge))) {
            throw new IllegalStateException("audit anchor is stale (written " + a.writtenAt()
                    + "): the schedule stopped or an old copy was restored");
        }
        if (a.writtenAt().isAfter(now.plus(MAX_SKEW))) {
            throw new IllegalStateException("audit anchor is dated in the future");
        }
        return a.head();
    }

    /** An anchor and when it was written. */
    record Anchored(AuditLog.Head head, Instant writtenAt) {
    }

    private Optional<Anchored> readAnchored() {
        synchronized (lock) {
            byte[] raw;
            try (InputStream in = Files.newInputStream(file)) {
                raw = in.readNBytes(MAX_FILE_BYTES + 1);
            } catch (NoSuchFileException e) {
                if (last != null) {
                    throw new IllegalStateException("audit anchor removed after " + last.sequence());
                }
                return Optional.empty();
            } catch (IOException e) {
                throw new UncheckedIOException("cannot read the audit anchor", e);
            }
            if (raw.length > MAX_FILE_BYTES) {
                throw new IllegalStateException("audit anchor damaged: too long");
            }
            Anchored a = parse(new String(raw, StandardCharsets.US_ASCII).strip());
            AuditLog.Head h = a.head();
            if (last != null && h.sequence() < last.sequence()) {
                throw new IllegalStateException("audit anchor rolled back from " + last.sequence() + " to " + h.sequence());
            }
            if (last != null && h.sequence() == last.sequence() && !h.mac().equals(last.mac())) {
                throw new IllegalStateException("audit anchor rewritten at " + h.sequence());
            }
            last = h;
            return Optional.of(a);
        }
    }

    private Anchored parse(String line) {
        String[] p = line.split(" ", -1);
        if (p.length != 5 || !VERSION.equals(p[0]) || !HEX64.matcher(p[2]).matches() || !HEX64.matcher(p[4]).matches()) {
            throw new IllegalStateException("audit anchor damaged: unreadable");
        }
        long seq;
        Instant at;
        try {
            seq = Long.parseLong(p[1]);
            at = Instant.parse(p[3]);
        } catch (NumberFormatException | DateTimeParseException e) {
            throw new IllegalStateException("audit anchor damaged: unreadable", e);
        }
        if (seq < 0 || !MessageDigest.isEqual(hmac(seq, p[2], p[3]).getBytes(StandardCharsets.US_ASCII),
                p[4].getBytes(StandardCharsets.US_ASCII))) {
            throw new IllegalStateException("audit anchor forged or altered");
        }
        return new Anchored(new AuditLog.Head(seq, p[2]), at);
    }

    /**
     * Anchors {@code head} every {@code interval} (on a schedule). A failed run is counted
     * ({@link #failures()}) and the schedule keeps going.
     */
    public ScheduledFuture<?> schedule(ScheduledExecutorService executor, Supplier<AuditLog.Head> head,
                                       Duration interval) {
        Objects.requireNonNull(executor, "executor");
        Objects.requireNonNull(head, "head");
        if (interval.compareTo(MIN_INTERVAL) < 0) {
            throw new IllegalArgumentException("interval must be at least " + MIN_INTERVAL);
        }
        long ms = interval.toMillis();
        return executor.scheduleWithFixedDelay(() -> {
            try {
                anchor(head.get());
            } catch (RuntimeException e) {
                failures.incrementAndGet();
            }
        }, ms, ms, TimeUnit.MILLISECONDS);
    }

    /** Scheduled runs that failed (a damaged anchor, a full disk, a rollback attempt). */
    public long failures() {
        return failures.get();
    }

    private String hmac(long seq, String mac, String at) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(key);
            return HexFormat.of().formatHex(m.doFinal(Canonical.encode(DOMAIN, Long.toString(seq), mac, at)));
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("unusable anchor key", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    private static SecretKey requireKey(SecretKey key) {
        Objects.requireNonNull(key, "anchor key");
        byte[] encoded = key.getEncoded();
        try {
            if (encoded == null || encoded.length < AuditLog.MIN_KEY_BYTES) {
                throw new IllegalArgumentException("anchor key must be at least " + AuditLog.MIN_KEY_BYTES + " bytes");
            }
        } finally {
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
        }
        return key;
    }
}

package dev.dwarpal.audit;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Reads an {@link AuditSource} in order and checks the chain on the way: every record must carry the
 * next sequence number and link to the MAC of the one before; with the audit key, its own MAC must be
 * right too. At the first break the cursor stops for good and reports why: whatever follows a gap or a
 * forged record cannot be trusted, and a reader that skipped over it could be fed invented events.
 *
 * <p>Without the key the cursor proves order and continuity only: someone who can write to the store
 * and knows the format could build a consistent fake chain. With the key it proves that Dwarpal wrote
 * every record. Detection and export should run with the key where they can.
 */
public final class AuditCursor {

    /** One read: the events that passed the checks, and the reason the chain broke, if it did. */
    public record Batch(List<AuditEvent> events, Optional<String> problem) {
        public Batch {
            events = List.copyOf(events);
            Objects.requireNonNull(problem, "problem");
        }
    }

    private final Object lock = new Object();
    private final AuditSource source;
    private final SecretKey key;
    private long position;
    private String lastMac;
    private String broken;

    private AuditCursor(AuditSource source, SecretKey key, AuditLog.Head start) {
        this.source = Objects.requireNonNull(source, "source");
        this.key = key;
        this.position = start.sequence();
        this.lastMac = start.mac();
    }

    /** From the first record, checking order and links only. */
    public static AuditCursor fromStart(AuditSource source) {
        return new AuditCursor(source, null, new AuditLog.Head(0, AuditLog.GENESIS));
    }

    /** From the first record, checking order, links and every MAC with the audit key. */
    public static AuditCursor fromStart(AuditSource source, SecretKey key) {
        return new AuditCursor(source, Objects.requireNonNull(key, "key"), new AuditLog.Head(0, AuditLog.GENESIS));
    }

    /**
     * After a head that was verified earlier (for example the checkpoint a reader saved), so a restarted
     * reader does not re-read the whole trail. The head must come from a trusted place, not from the source.
     */
    public static AuditCursor resume(AuditSource source, SecretKey key, AuditLog.Head verified) {
        Objects.requireNonNull(verified, "verified");
        if (verified.sequence() < 0) {
            throw new IllegalArgumentException("sequence must not be negative");
        }
        return new AuditCursor(source, key, verified);
    }

    /** Up to {@code max} events after the current position; empty once the chain has broken. */
    public Batch next(int max) {
        synchronized (lock) {
            if (broken != null) {
                return new Batch(List.of(), Optional.of(broken));
            }
            if (max < 1) {
                throw new IllegalArgumentException("max must be positive");
            }
            int limit = Math.min(max, AuditSource.MAX_BATCH);
            List<AuditRecord> records = source.after(position, limit);
            List<AuditEvent> events = new ArrayList<>(Math.min(records.size(), limit));
            for (AuditRecord r : records) {
                Optional<String> problem = events.size() >= limit ? Optional.of("source returned more records than asked")
                        : check(r);
                if (problem.isPresent()) {
                    broken = "record " + (position + 1) + ": " + problem.get();
                    return new Batch(events, Optional.of(broken));
                }
                AuditEvent e;
                try {
                    e = AuditEvent.of(r);
                } catch (IllegalArgumentException unreadable) {
                    broken = "record " + r.sequence() + ": payload unreadable";
                    return new Batch(events, Optional.of(broken));
                }
                events.add(e);
                position = r.sequence();
                lastMac = r.mac();
            }
            return new Batch(events, Optional.empty());
        }
    }

    private Optional<String> check(AuditRecord r) {
        if (r.sequence() != position + 1) {
            return Optional.of("expected sequence " + (position + 1) + ", found " + r.sequence());
        }
        if (!r.previousMac().equals(lastMac)) {
            return Optional.of("chain link broken");
        }
        if (key != null && !AuditLog.macValid(key, r)) {
            return Optional.of("MAC mismatch: record altered or forged");
        }
        return Optional.empty();
    }

    /** The last verified position: save it to resume later, or compare it with an anchored head. */
    public AuditLog.Head checkpoint() {
        synchronized (lock) {
            return new AuditLog.Head(position, lastMac);
        }
    }

    /**
     * Compares the trail read so far with a head anchored elsewhere (for example written to a separate
     * file or system). Call it once {@link #next} returns nothing more: a trail that stops short of the
     * anchor was truncated, one that disagrees at the anchor was rewritten.
     */
    public Optional<String> checkAgainst(AuditLog.Head anchored) {
        synchronized (lock) {
            Objects.requireNonNull(anchored, "anchored");
            if (broken != null) {
                return Optional.of(broken);
            }
            if (position < anchored.sequence()) {
                return Optional.of("trail ends at " + position + " but the anchor is at " + anchored.sequence()
                        + ": truncated");
            }
            if (position == anchored.sequence() && !lastMac.equals(anchored.mac())) {
                return Optional.of("trail disagrees with the anchor at " + position + ": rewritten");
            }
            return Optional.empty();
        }
    }

    /** Why the chain broke, if it did. */
    public Optional<String> broken() {
        synchronized (lock) {
            return Optional.ofNullable(broken);
        }
    }
}

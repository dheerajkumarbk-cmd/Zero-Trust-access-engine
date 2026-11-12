package dev.dwarpal.lab;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.AuditSource;
import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.siem.HeadAnchor;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The audit explorer's read side. An analyst must be able to verify the trail, not only read it (NIST AU-9, AU-10;
 * SP 800-92): paging shows records, {@link #verify()} re-computes every link and MAC from the first record with the
 * key and compares the end of the chain with the anchored head.
 *
 * <p>Everything returned is plain data. Text in a record can come from outside (a host name, a note), so summaries
 * are cut and stripped of control characters here; the console still treats every string as untrusted.
 */
public final class LabAudit {

    public static final int MAX_PAGE = 500;
    static final int SUMMARY = 200;

    /** One line of the trail. */
    public record Entry(long sequence, Instant at, String type, String actor, String summary, String mac) {
    }

    /** A page: records after a sequence number, and whether more follow. */
    public record Page(List<Entry> entries, long head, boolean more) {
        public Page {
            entries = List.copyOf(entries);
        }
    }

    /** One record in full. */
    public record Detail(Entry entry, String payloadJson, String previousMac) {
    }

    /**
     * The result of checking the trail.
     *
     * @param intact          every link and MAC verified from record 1
     * @param records         how many records were checked
     * @param firstBad        sequence number of the first problem, -1 if none
     * @param reason          plain words
     * @param anchoredSeq     the sequence number the external anchor holds, if there is one
     * @param anchorAgrees    the chain reaches the anchored head at that sequence number
     */
    public record Verified(boolean intact, long records, long firstBad, String reason, Optional<Long> anchoredSeq,
                           boolean anchorAgrees) {
    }

    private final AuditSource source;
    private final SecretKey key;
    private final HeadAnchor anchor;

    public LabAudit(AuditSource source, SecretKey key, HeadAnchor anchor) {
        this.source = Objects.requireNonNull(source, "source");
        this.key = Objects.requireNonNull(key, "key");
        this.anchor = Objects.requireNonNull(anchor, "anchor");
    }

    /** Records after {@code after} (0 for the start), oldest first, at most {@code limit}, optionally one type. */
    public Page page(long after, int limit, Optional<String> type) {
        if (after < 0 || limit < 1 || limit > MAX_PAGE) {
            throw new IllegalArgumentException("after is 0 or more; limit is 1 to " + MAX_PAGE);
        }
        List<Entry> out = new ArrayList<>();
        long cursor = after;
        boolean more = false;
        long head = source.lastSequence();
        while (cursor < head && out.size() < limit) {
            List<AuditRecord> batch = source.after(cursor, 1_000);
            if (batch.isEmpty()) {
                break;
            }
            for (AuditRecord r : batch) {
                cursor = r.sequence();
                if (type.isPresent() && !type.get().equals(r.type())) {
                    continue;
                }
                if (out.size() == limit) {
                    more = true;
                    break;
                }
                out.add(entry(r));
            }
            if (more) {
                break;
            }
        }
        return new Page(out, head, more || cursor < head && out.size() == limit);
    }

    /** One record, or empty if the sequence number does not exist. */
    public Optional<Detail> record(long sequence) {
        if (sequence < 1) {
            return Optional.empty();
        }
        List<AuditRecord> one = source.after(sequence - 1, 1);
        if (one.isEmpty() || one.getFirst().sequence() != sequence) {
            return Optional.empty();
        }
        AuditRecord r = one.getFirst();
        return Optional.of(new Detail(entry(r), r.payloadJson(), r.previousMac()));
    }

    /** Re-computes the whole chain and compares its end with the anchored head. */
    public Verified verify() {
        Optional<AuditLog.Head> anchored;
        try {
            anchored = anchor.read();
        } catch (IllegalStateException e) {
            // a damaged, forged or vanished anchor is tampering until shown otherwise; never "no anchor"
            return new Verified(false, 0, -1, "the anchor is damaged or gone: " + Sanitize.text(e.getMessage(), SUMMARY),
                    Optional.empty(), false);
        }
        AuditCursor cursor = AuditCursor.fromStart(source, key);
        long records = 0;
        while (true) {
            AuditCursor.Batch b = cursor.next(AuditSource.MAX_BATCH);
            records += b.events().size();
            if (b.problem().isPresent()) {
                return new Verified(false, records, records + 1, Sanitize.text(b.problem().get(), SUMMARY),
                        anchored.map(AuditLog.Head::sequence), false);
            }
            if (b.events().isEmpty()) {
                break;
            }
        }
        if (anchored.isEmpty()) {
            return new Verified(true, records, -1, "intact; no anchor to compare with", Optional.empty(), false);
        }
        Optional<String> mismatch = cursor.checkAgainst(anchored.get());
        if (mismatch.isPresent()) {
            return new Verified(false, records, anchored.get().sequence(), Sanitize.text(mismatch.get(), SUMMARY),
                    Optional.of(anchored.get().sequence()), false);
        }
        // The cursor compares the anchor only when the chain ends exactly there. The chain has grown since, so
        // compare the record AT the anchored sequence number: a history rewritten and then extended must not pass.
        List<AuditRecord> at = source.after(anchored.get().sequence() - 1, 1);
        if (at.isEmpty() || at.getFirst().sequence() != anchored.get().sequence()
                || !at.getFirst().mac().equals(anchored.get().mac())) {
            return new Verified(false, records, anchored.get().sequence(),
                    "the chain differs from the anchor at " + anchored.get().sequence() + ": history was rewritten",
                    Optional.of(anchored.get().sequence()), false);
        }
        return new Verified(true, records, -1, "intact and reaches the anchored head",
                Optional.of(anchored.get().sequence()), true);
    }

    private static Entry entry(AuditRecord r) {
        return new Entry(r.sequence(), r.at(), r.type(), r.actor(), Sanitize.text(r.payloadJson(), SUMMARY), r.mac());
    }
}

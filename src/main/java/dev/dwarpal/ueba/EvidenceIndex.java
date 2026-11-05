package dev.dwarpal.ueba;

import java.util.Collection;
import java.util.Objects;
import java.util.Optional;

import dev.dwarpal.soc.SecurityEvent;

/**
 * The provenance of the most recent audit records, by sequence number, so ranking can compute whether an
 * alert's evidence is {@code actionable} from the records themselves instead of trusting the rule. A fixed ring
 * of one byte per record: two million records cost two megabytes. A sequence number that is too old or was
 * never read is unknown, and unknown counts as not actionable (fail closed).
 */
public final class EvidenceIndex {

    private final byte[] ring;
    private long newest;

    public EvidenceIndex(int capacity) {
        if (capacity < 1 || capacity > 50_000_000) {
            throw new IllegalArgumentException("capacity 1 to 50,000,000");
        }
        this.ring = new byte[capacity];
    }

    /** Records the provenance of one audit record; sequence numbers arrive in increasing order. */
    public synchronized void put(long sequence, SecurityEvent.Provenance provenance) {
        Objects.requireNonNull(provenance, "provenance");
        if (sequence < 1 || sequence <= newest - ring.length) {
            return;
        }
        if (sequence > newest) {
            long from = Math.max(newest + 1, sequence - ring.length + 1);
            for (long s = from; s < sequence; s++) {
                ring[slot(s)] = 0;
            }
            newest = sequence;
        }
        ring[slot(sequence)] = (byte) (provenance.ordinal() + 1);
    }

    /** The provenance of a record, if it is still remembered. */
    public synchronized Optional<SecurityEvent.Provenance> provenance(long sequence) {
        if (sequence < 1 || sequence > newest || sequence <= newest - ring.length) {
            return Optional.empty();
        }
        byte b = ring[slot(sequence)];
        return b == 0 ? Optional.empty() : Optional.of(SecurityEvent.Provenance.values()[b - 1]);
    }

    /** Whether at least one record is known and more than {@code COLLECTED}; unknown records never count. */
    public boolean anyActionable(Collection<Long> sequences) {
        for (long s : sequences) {
            if (provenance(s).map(SecurityEvent.Provenance::actionable).orElse(false)) {
                return true;
            }
        }
        return false;
    }

    /** How many of the records are unknown to this index. */
    public long unknown(Collection<Long> sequences) {
        return sequences.stream().filter(s -> provenance(s).isEmpty()).count();
    }

    private int slot(long sequence) {
        return (int) Math.floorMod(sequence, (long) ring.length);
    }
}

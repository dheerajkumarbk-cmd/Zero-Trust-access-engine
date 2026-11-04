package dev.dwarpal.audit;

import java.util.ArrayList;
import java.util.List;

/** Thread-safe in-memory sink for tests and the simulator; also readable as an {@link AuditSource}. */
public final class InMemoryAuditSink implements AuditSink, AuditSource {

    private final List<AuditRecord> records = new ArrayList<>();

    @Override
    public synchronized void write(AuditRecord record) {
        records.add(record);
    }

    /** A copy: callers cannot alter the stored trail. */
    public synchronized List<AuditRecord> snapshot() {
        return List.copyOf(records);
    }

    /**
     * Records are kept in the order written; an {@link AuditLog} writes rising sequence numbers, so the
     * start is found by binary search. A sink fed out of order gives out of order batches, which
     * {@link AuditCursor} reports as a break.
     */
    @Override
    public synchronized List<AuditRecord> after(long sequence, int max) {
        int lo = 0;
        int hi = records.size();
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (records.get(mid).sequence() <= sequence) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        int n = Math.max(0, Math.min(Math.min(max, MAX_BATCH), records.size() - lo));
        return List.copyOf(records.subList(lo, lo + n));
    }

    @Override
    public synchronized long lastSequence() {
        return records.isEmpty() ? 0 : records.getLast().sequence();
    }
}

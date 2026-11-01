package dev.dwarpal.audit;

import java.util.ArrayList;
import java.util.List;

/** Thread-safe in-memory sink for tests and the simulator. */
public final class InMemoryAuditSink implements AuditSink {

    private final List<AuditRecord> records = new ArrayList<>();

    @Override
    public synchronized void write(AuditRecord record) {
        records.add(record);
    }

    /** A copy: callers cannot alter the stored trail. */
    public synchronized List<AuditRecord> snapshot() {
        return List.copyOf(records);
    }
}

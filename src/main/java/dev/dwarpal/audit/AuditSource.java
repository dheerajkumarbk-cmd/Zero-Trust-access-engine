package dev.dwarpal.audit;

import java.util.List;

/**
 * Read side of an audit trail: the records an {@link AuditSink} received, in order. Readers (the SIEM
 * export, detection rules, analytics) never trust a source on its own; they read it through an
 * {@link AuditCursor}, which checks the chain as it goes.
 */
public interface AuditSource {

    /** Hard cap on one batch, whatever a caller asks for. */
    int MAX_BATCH = 10_000;

    /**
     * The records with sequence numbers greater than {@code sequence}, in order, at most {@code max}
     * (and at most {@link #MAX_BATCH}). Empty when there is nothing newer.
     */
    List<AuditRecord> after(long sequence, int max);

    /** The sequence number of the newest record, 0 when the trail is empty. */
    long lastSequence();
}

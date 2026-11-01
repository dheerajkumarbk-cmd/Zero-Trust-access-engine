package dev.dwarpal.audit;

/**
 * Where audit records are persisted (memory, append-only file, SIEM). Implementations must be
 * append-only: no update, no delete. In a database this means the writer account has INSERT
 * privilege only (least privilege); see docs/security-architecture.md.
 */
public interface AuditSink {

    /** Persist the record durably or throw; a silent failure would break the chain unnoticed. */
    void write(AuditRecord record);
}

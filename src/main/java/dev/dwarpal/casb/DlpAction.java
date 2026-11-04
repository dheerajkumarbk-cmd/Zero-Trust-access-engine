package dev.dwarpal.casb;

/** What happens to content with findings, from mildest to strictest. */
public enum DlpAction {
    /** Let it through and record the findings in the audit trail. */
    AUDIT,
    /** Replace each finding with a marker, let the rest through, and record the findings. */
    REDACT,
    /** Refuse the upload. */
    BLOCK;

    public DlpAction stricter(DlpAction other) {
        return compareTo(other) >= 0 ? this : other;
    }
}

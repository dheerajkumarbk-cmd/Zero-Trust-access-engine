package dev.dwarpal.behavior;

import java.time.Instant;

/** Read-only view of recent authentication failures: scorers can count them but not forge or erase them. */
public interface FailureView {

    long subjectFailures(String subjectId, Instant from, Instant to);

    long distinctSubjectsFromIp(String ip, Instant from, Instant to);

    /** All failures in the organisation within [from, to], counted without per-key storage. */
    long totalFailures(Instant from, Instant to);
}

package dev.dwarpal.soc;

import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * One alert raised by a detection rule.
 *
 * @param id       unique id (for example {@code al-<rule>-<sequence>}), used by cases and verdicts
 * @param rule     the rule that raised it (stable id, for example {@code break-glass-used})
 * @param severity how urgently a person must look
 * @param raisedAt time of the newest evidence (audit time, not wall-clock time, so a replayed trail gives
 *                 the same alerts)
 * @param entities who and what it is about, at most {@link #MAX_ENTITIES}
 * @param evidence audit sequence numbers that support it, at most {@link #MAX_EVIDENCE}, so an analyst can
 *                 look up the records (alerts never copy payloads)
 * @param count    how many occurrences this alert stands for (deduplicated alerts count up instead of
 *                 repeating)
 * @param summary  one short line for a person, sanitised (no line breaks, bidi or control characters),
 *                 at most {@link #MAX_SUMMARY} characters; never secrets or raw payload values
 */
public record Alert(String id, String rule, Severity severity, Instant raisedAt, List<Entity> entities,
                    List<Long> evidence, long count, String summary) {

    public static final int MAX_ENTITIES = 16;
    public static final int MAX_EVIDENCE = 100;
    public static final int MAX_SUMMARY = 200;

    public Alert {
        Validate.id(id, "alert.id");
        Validate.id(rule, "alert.rule");
        Objects.requireNonNull(severity, "alert.severity");
        Objects.requireNonNull(raisedAt, "alert.raisedAt");
        entities = List.copyOf(entities);
        evidence = List.copyOf(evidence);
        if (entities.isEmpty() || entities.size() > MAX_ENTITIES) {
            throw new IllegalArgumentException("an alert names 1 to " + MAX_ENTITIES + " entities");
        }
        if (evidence.isEmpty() || evidence.size() > MAX_EVIDENCE) {
            throw new IllegalArgumentException("an alert cites 1 to " + MAX_EVIDENCE + " audit records");
        }
        for (long seq : evidence) {
            if (seq < 1) {
                throw new IllegalArgumentException("audit sequence numbers start at 1");
            }
        }
        if (count < 1) {
            throw new IllegalArgumentException("count must be at least 1");
        }
        String clean = Sanitize.text(Objects.requireNonNull(summary, "alert.summary"), MAX_SUMMARY);
        summary = clean.length() > MAX_SUMMARY ? clean.substring(0, MAX_SUMMARY) : clean;
    }
}

package dev.dwarpal.ueba;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Technique;

/**
 * One finding of a UEBA detector about one entity, with the numbers an analyst needs to check it by hand.
 *
 * @param entity     who or what it is about
 * @param detector   which detector found it
 * @param group      what it counts as in the entity's risk: anomalies with the same group are one piece of
 *                   evidence (for example the event count and the bytes of one burst of downloads), so only the
 *                   strongest counts; an id
 * @param weight     its log-likelihood ratio (log-odds), above 0, capped by the settings
 * @param at         time of the event that triggered it
 * @param evidence   audit sequence numbers of the events behind it (1 to {@link Alert#MAX_EVIDENCE})
 * @param actionable whether any of those events is more than {@code COLLECTED}
 * @param technique  the MITRE technique the anomaly points to, or null
 * @param reason     one sanitised line with the numbers (observed, expected, formula result)
 */
public record Anomaly(Entity entity, Detector detector, String group, double weight, Instant at, List<Long> evidence,
                      boolean actionable, Technique technique, String reason) {

    public static final int MAX_REASON = 160;

    /** The detectors; each is a statistic an analyst can recompute from the listed numbers. */
    public enum Detector {
        /** Events of one action in one hour against the hourly baseline: Poisson z-score and likelihood ratio. */
        VOLUME,
        /** Bytes of one action in one hour against the usual hour's bytes: the ratio. */
        DATA_VOLUME,
        /** A value never seen for this entity: rule of succession (M1). */
        FIRST_SEEN,
        /** An unusual time of day for this entity: von Mises density (M6). */
        TIME_OF_DAY,
        /** Connections to one destination new for the entity at machine-regular intervals: beaconing. */
        BEACON,
        /** The volume baseline itself grew too fast: slow poisoning. */
        DRIFT
    }

    public Anomaly {
        Objects.requireNonNull(entity, "entity");
        Objects.requireNonNull(detector, "detector");
        Validate.id(group, "anomaly.group");
        Validate.finite(weight, "anomaly.weight");
        if (weight <= 0) {
            throw new IllegalArgumentException("an anomaly adds risk");
        }
        Objects.requireNonNull(at, "anomaly.at");
        evidence = List.copyOf(evidence);
        if (evidence.isEmpty() || evidence.size() > Alert.MAX_EVIDENCE || evidence.stream().anyMatch(s -> s < 1)) {
            throw new IllegalArgumentException("1 to " + Alert.MAX_EVIDENCE + " audit sequence numbers");
        }
        String clean = Sanitize.text(Objects.requireNonNull(reason, "anomaly.reason"), MAX_REASON);
        reason = clean.length() > MAX_REASON ? clean.substring(0, MAX_REASON) : clean;
    }

    /** The risk source id: {@code ueba:<detector>}, for example {@code ueba:first_seen}. */
    public String source() {
        return "ueba:" + detector.name().toLowerCase(java.util.Locale.ROOT);
    }
}

package dev.dwarpal.domain;

/** Sensitivity of a resource, ordered from least to most sensitive. */
public enum DataClassification {
    PUBLIC,
    INTERNAL,
    CONFIDENTIAL,
    RESTRICTED;

    public boolean atLeast(DataClassification other) {
        return compareTo(other) >= 0;
    }

    public boolean atMost(DataClassification other) {
        return compareTo(other) <= 0;
    }
}

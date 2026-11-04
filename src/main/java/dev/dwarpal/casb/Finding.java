package dev.dwarpal.casb;

import java.util.Objects;

/**
 * One piece of sensitive data found in a text: its type and where it is ({@code start} inclusive,
 * {@code end} exclusive, in characters of the inspected text). Deliberately <em>not</em> the value: a
 * finding can be logged, audited and shown to an analyst without spreading the card number it is about.
 */
public record Finding(FindingType type, int start, int end) {

    public Finding {
        Objects.requireNonNull(type, "type");
        if (start < 0 || end <= start) {
            throw new IllegalArgumentException("finding position out of range");
        }
    }

    public int length() {
        return end - start;
    }
}

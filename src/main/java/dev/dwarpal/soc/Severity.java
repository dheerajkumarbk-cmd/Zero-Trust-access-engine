package dev.dwarpal.soc;

/** How urgently an alert needs a person. Ordered: a later constant is more severe. */
public enum Severity {
    LOW, MEDIUM, HIGH, CRITICAL;

    public boolean atLeast(Severity other) {
        return compareTo(other) >= 0;
    }
}

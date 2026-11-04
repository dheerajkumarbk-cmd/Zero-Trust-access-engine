package dev.dwarpal.soc;

/**
 * Where detection rules send alerts (the case book, a SIEM, a test list). Implementations must be
 * bounded and must not throw for a well-formed alert; a sink that is full refuses and counts.
 */
@FunctionalInterface
public interface AlertSink {
    /** @return false if the alert was refused (for example because the sink is full) */
    boolean raise(Alert alert);
}

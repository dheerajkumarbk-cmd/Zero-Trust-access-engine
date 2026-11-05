package dev.dwarpal.soc;

import java.time.Instant;
import java.util.Objects;

/**
 * A {@link SecurityEvent} as read back from the audit chain: the record's sequence number (what an
 * {@link Alert} cites as evidence), when the record was written, and the event.
 */
public record ChainedEvent(long sequence, Instant recordedAt, SecurityEvent event) {

    public ChainedEvent {
        if (sequence < 1) {
            throw new IllegalArgumentException("audit sequence numbers start at 1");
        }
        Objects.requireNonNull(recordedAt, "recordedAt");
        Objects.requireNonNull(event, "event");
    }
}

package dev.dwarpal.swg;

import dev.dwarpal.domain.Validate;
import dev.dwarpal.edge.EdgeResult;

import java.util.Objects;
import java.util.Optional;

/**
 * The gateway's answer for one request: allowed or not, why not (for counters, never for the user), the
 * destination, and the generic message and reference the user sees.
 */
public record WebVerdict(boolean allowed, Optional<BlockReason> reason, Optional<Destination> destination,
                         String reference, String userMessage) {

    public WebVerdict {
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(destination, "destination");
        Validate.id(reference, "reference");
        Objects.requireNonNull(userMessage, "userMessage");
        if (allowed == reason.isPresent()) {
            throw new IllegalArgumentException("a verdict is allowed exactly when it has no block reason");
        }
        if (allowed && destination.isEmpty()) {
            throw new IllegalArgumentException("an allowed verdict has a destination");
        }
    }

    static WebVerdict allow(Destination d, String reference) {
        return new WebVerdict(true, Optional.empty(), Optional.of(d), reference,
                EdgeResult.genericMessage(EdgeResult.Status.GRANTED, reference));
    }

    static WebVerdict block(BlockReason reason, Optional<Destination> d, String reference) {
        EdgeResult.Status s = reason == BlockReason.STEP_UP_REQUIRED ? EdgeResult.Status.STEP_UP : EdgeResult.Status.DENIED;
        return new WebVerdict(false, Optional.of(reason), d, reference, EdgeResult.genericMessage(s, reference));
    }
}

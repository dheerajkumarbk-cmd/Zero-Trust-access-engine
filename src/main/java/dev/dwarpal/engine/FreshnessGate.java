package dev.dwarpal.engine;

import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.risk.SignalSnapshot;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Denies requests whose timestamp is too far from the engine's clock: stale requests (replayed
 * from a capture) and future-dated ones (skewing time-of-day or travel-velocity scoring).
 *
 * <p>This is the one place the engine reads a clock, which is why it is an optional gate:
 * live deployments install it; What-If replay of recorded traffic must not, or every historical
 * request would be "stale".
 */
public final class FreshnessGate implements HardGate {

    private final Clock clock;
    private final Duration maxSkew;

    public FreshnessGate(Clock clock, Duration maxSkew) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.maxSkew = Objects.requireNonNull(maxSkew, "maxSkew");
        if (maxSkew.isNegative() || maxSkew.isZero()) {
            throw new IllegalArgumentException("maxSkew must be positive");
        }
    }

    @Override
    public String name() {
        return "freshness";
    }

    @Override
    public Optional<String> check(AccessRequest request, SignalSnapshot signals) {
        Instant now = clock.instant();
        Duration skew = Duration.between(now, request.timestamp()).abs();
        if (skew.compareTo(maxSkew) > 0) {
            return Optional.of("request timestamp is " + skew.toSeconds() + "s from engine time (max "
                    + maxSkew.toSeconds() + "s): stale or forged");
        }
        return Optional.empty();
    }
}

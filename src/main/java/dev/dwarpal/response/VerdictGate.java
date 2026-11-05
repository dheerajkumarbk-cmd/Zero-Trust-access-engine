package dev.dwarpal.response;

import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.guard.NonceCache;
import dev.dwarpal.soc.Verdict;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Decides whether a verdict may count: signed by a {@code SOC_ANALYST} key bound to the named analyst
 * (checked by {@link Verdict#verify}), at most {@link Verdict#MAX_AGE} old by this gate's clock, and
 * used once. The signature is checked before single use is recorded, so nobody can burn an analyst's
 * verdict by sending a forged copy first.
 */
public final class VerdictGate {

    public static final int CAPACITY = 100_000;

    private final KeyRing keys;
    private final Clock clock;
    /** Remembered for as long as a verdict could still verify: its maximum age plus clock skew. */
    private final NonceCache spent;

    public VerdictGate(KeyRing keys, Clock clock) {
        this(keys, clock, CAPACITY);
    }

    VerdictGate(KeyRing keys, Clock clock, int capacity) {
        this.keys = Objects.requireNonNull(keys, "keys");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.spent = new NonceCache(Verdict.MAX_AGE.plus(KeyRing.MAX_CLOCK_SKEW).plus(KeyRing.MAX_CLOCK_SKEW),
                capacity);
    }

    /** Empty if the verdict counts (and is now spent); otherwise why not. */
    public Optional<String> admit(Verdict v) {
        Objects.requireNonNull(v, "verdict");
        Instant now = clock.instant();
        KeyRing.Result r = v.verify(keys, now);
        if (!r.valid()) {
            return Optional.of("verdict not verified: " + r.reason());
        }
        // Keyed by the signed claim, not the signature bytes: a re-encoded signature over the same claim is
        // still a replay.
        if (!spent.firstUse(v.alertId() + "|" + v.analystId() + "|" + v.outcome() + "|" + v.proof().signedAt(), now)) {
            return Optional.of("verdict already used (or the replay store is full)");
        }
        return Optional.empty();
    }
}

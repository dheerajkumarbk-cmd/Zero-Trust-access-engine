package dev.dwarpal.response;

import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.soc.Entity;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * What a playbook does when an analyst confirms an alert (a true-positive verdict): a list of steps,
 * each applied to every entity of its kind that the alert names.
 */
public record Play(List<Step> steps) {

    public static final int MAX_STEPS = 16;

    public Play {
        steps = List.copyOf(steps);
        if (steps.size() > MAX_STEPS) {
            throw new IllegalArgumentException("a play has at most " + MAX_STEPS + " steps");
        }
    }

    public static Play of(Step... steps) {
        return new Play(List.of(steps));
    }

    /** One step. Revocations and denies are destructive (guard rails apply); watches only add risk. */
    public sealed interface Step permits Revoke, Deny, Watch {
        Entity.Kind target();

        default boolean destructive() {
            return !(this instanceof Watch);
        }
    }

    /** End the sessions of a person, a device or one session (and a person's elevation grants). */
    public record Revoke(Entity.Kind target) implements Step {
        public Revoke {
            Objects.requireNonNull(target, "target");
            if (target != Entity.Kind.SUBJECT && target != Entity.Kind.DEVICE && target != Entity.Kind.SESSION) {
                throw new IllegalArgumentException("only a person, a device or a session can be revoked");
            }
        }
    }

    /** Deny a person, a device or an address for a while (never longer than {@link ResponseSettings#HARD_MAX_DENY}). */
    public record Deny(Entity.Kind target, Duration duration) implements Step {
        public Deny {
            feedKind(target);
            Objects.requireNonNull(duration, "duration");
            if (duration.isNegative() || duration.isZero() || duration.compareTo(ResponseSettings.HARD_MAX_DENY) > 0) {
                throw new IllegalArgumentException("a playbook deny lasts more than zero and at most 7 days");
            }
        }
    }

    /** Watch a person, a device or an address with a decaying weight (a log-likelihood ratio). */
    public record Watch(Entity.Kind target, double logLr, Duration halfLife) implements Step {
        public Watch {
            feedKind(target);
            Objects.requireNonNull(halfLife, "halfLife");
            if (!Double.isFinite(logLr) || logLr <= 0 || logLr > SignalFeed.MAX_WATCH_LOG_LR) {
                throw new IllegalArgumentException("a watch adds risk: 0 < logLr <= ln(1000)");
            }
            if (halfLife.compareTo(SignalFeed.MIN_HALF_LIFE) < 0 || halfLife.compareTo(SignalFeed.MAX_HALF_LIFE) > 0) {
                throw new IllegalArgumentException("half-life must be between 1 minute and 90 days");
            }
        }
    }

    /** The feed's kind for an entity kind the feed knows. */
    static SignalFeed.Kind feedKind(Entity.Kind k) {
        return switch (Objects.requireNonNull(k, "target")) {
            case SUBJECT -> SignalFeed.Kind.SUBJECT;
            case DEVICE -> SignalFeed.Kind.DEVICE;
            case IP -> SignalFeed.Kind.IP;
            case SESSION, RESOURCE -> throw new IllegalArgumentException("the signal feed holds people, devices and addresses");
        };
    }
}

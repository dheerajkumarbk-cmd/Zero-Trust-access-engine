package dev.dwarpal.engine;

import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.Validate;

import java.time.Duration;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * How much the engine trusts signed evidence, and for how long.
 *
 * @param maxAuthenticationAge a step-up older than this no longer counts (re-authentication window)
 * @param maxPostureAge        a posture report older than this is not believed
 * @param bypassProbability    per-method beta: P(attacker passes this authenticator)
 */
public record AssuranceSettings(Duration maxAuthenticationAge, Duration maxPostureAge,
                                Map<AuthMethod, Double> bypassProbability) {

    public AssuranceSettings {
        requirePositive(maxAuthenticationAge, "maxAuthenticationAge");
        requirePositive(maxPostureAge, "maxPostureAge");
        Map<AuthMethod, Double> copy = new EnumMap<>(AuthMethod.class);
        for (AuthMethod m : AuthMethod.values()) {
            Double beta = Objects.requireNonNull(bypassProbability.get(m), "bypassProbability missing " + m);
            copy.put(m, Validate.probability(beta, "bypassProbability." + m));
        }
        bypassProbability = Map.copyOf(copy);
    }

    /** 15-minute step-up window, 24-hour posture freshness, documented default betas. */
    public static AssuranceSettings defaults() {
        Map<AuthMethod, Double> betas = new EnumMap<>(AuthMethod.class);
        for (AuthMethod m : AuthMethod.values()) {
            betas.put(m, m.defaultBypassProbability());
        }
        return new AssuranceSettings(Duration.ofMinutes(15), Duration.ofHours(24), betas);
    }

    public double bypass(AuthMethod method) {
        return bypassProbability.get(method);
    }

    private static void requirePositive(Duration d, String name) {
        Objects.requireNonNull(d, name);
        if (d.isNegative() || d.isZero()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
}

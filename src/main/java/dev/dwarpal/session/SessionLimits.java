package dev.dwarpal.session;

import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Validate;

import java.time.Duration;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * How long a session may live and how often its user must prove themselves again.
 *
 * @param idleTimeout         a session unused for this long is closed
 * @param absoluteLifetime    no session outlives this, however active (one working day)
 * @param reauthInterval      per data classification: after this long without a fresh, verified
 *                            authentication the session needs a step-up before it continues
 * @param maxSessionsPerSubject opening one more closes the oldest
 * @param maxSessions         hard bound on the store; when full of live sessions, new ones are refused
 * @param maxProofAge         a proof-of-possession signature older than this is not accepted
 * @param revokeAboveRisk     a DENY on a use ends the session when the action was READ, a hard gate
 *                            fired, or P(attack) is at least this; set it below the cost model's
 *                            deny threshold so every risk-driven denial ends the session
 */
public record SessionLimits(Duration idleTimeout, Duration absoluteLifetime,
                            Map<DataClassification, Duration> reauthInterval,
                            int maxSessionsPerSubject, int maxSessions, Duration maxProofAge,
                            double revokeAboveRisk) {

    public SessionLimits {
        positive(idleTimeout, "idleTimeout");
        positive(absoluteLifetime, "absoluteLifetime");
        Map<DataClassification, Duration> copy = new EnumMap<>(DataClassification.class);
        for (DataClassification c : DataClassification.values()) {
            Duration d = Objects.requireNonNull(reauthInterval.get(c), "reauthInterval missing " + c);
            copy.put(c, positive(d, "reauthInterval." + c));
        }
        reauthInterval = Map.copyOf(copy);
        if (maxSessionsPerSubject < 1 || maxSessions < 1) {
            throw new IllegalArgumentException("session counts must be at least 1");
        }
        positive(maxProofAge, "maxProofAge");
        Validate.probability(revokeAboveRisk, "revokeAboveRisk");
    }

    /**
     * Idle 30 min, at most 10 h, re-authentication every 8 h (PUBLIC), 4 h (INTERNAL), 1 h
     * (CONFIDENTIAL) or 15 min (RESTRICTED); 5 sessions per subject, 100,000 in total; proofs at most
     * 2 min old; revoke on risk-driven denials from P(attack) 0.05.
     */
    public static SessionLimits defaults() {
        Map<DataClassification, Duration> reauth = new EnumMap<>(DataClassification.class);
        reauth.put(DataClassification.PUBLIC, Duration.ofHours(8));
        reauth.put(DataClassification.INTERNAL, Duration.ofHours(4));
        reauth.put(DataClassification.CONFIDENTIAL, Duration.ofHours(1));
        reauth.put(DataClassification.RESTRICTED, Duration.ofMinutes(15));
        return new SessionLimits(Duration.ofMinutes(30), Duration.ofHours(10), reauth, 5, 100_000,
                Duration.ofMinutes(2), 0.05);
    }

    public Duration reauthFor(DataClassification classification) {
        return reauthInterval.get(classification);
    }

    private static Duration positive(Duration d, String name) {
        Objects.requireNonNull(d, name);
        if (d.isNegative() || d.isZero()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return d;
    }
}

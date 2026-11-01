package dev.dwarpal.behavior;

import java.util.List;
import java.util.Optional;

/**
 * Read-only view of users' behavioural baselines. Scorers get this interface, not the store,
 * so a scorer can never write to (poison) the history it reads: least privilege between
 * components.
 */
public interface BehaviorHistory {

    /** Number of trusted logins remembered for the subject. */
    long logins(String subjectId);

    /** Number of distinct values of {@code feature} the subject has used. */
    long distinct(String subjectId, Feature feature);

    boolean seen(String subjectId, Feature feature, String value);

    /**
     * How often the subject's recent logins brought a value of {@code feature} they had not used
     * before: {@code newValues} out of the last {@code window} logins.
     */
    Novelty novelty(String subjectId, Feature feature);

    /** Recent novelty counts, with Laplace's rule of succession as the estimate. */
    record Novelty(long newValues, long window) {
        /** P(next login brings a new value) = (newValues + 1) / (window + 2). */
        public double pNew() {
            return (newValues + 1.0) / (window + 2.0);
        }
    }

    Optional<LoginEvent> lastLogin(String subjectId);

    /** Recent login times (minute of day, UTC), oldest first. */
    List<Integer> loginMinutes(String subjectId);
}

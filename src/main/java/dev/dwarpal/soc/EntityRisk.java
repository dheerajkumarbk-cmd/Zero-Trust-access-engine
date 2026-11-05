package dev.dwarpal.soc;

import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * One risk score per person, device, address, session or resource, built from alerts, anomalies and
 * watches (part E), and read by ranking, cases and the SOC API (part F). Every score lists what raised it.
 */
public interface EntityRisk {

    int MAX_TOP = 100;

    /** The entity's risk now; an entity nothing is known about has score 0 and no contributions. */
    RiskView view(Entity entity, Instant now);

    /** The {@code n} riskiest entities now, riskiest first, at most {@link #MAX_TOP}. */
    List<RiskView> top(int n, Instant now);

    enum Level { NONE, LOW, MEDIUM, HIGH, CRITICAL;

        /** The level for a score: 0 none, below 25 low, below 50 medium, below 75 high, else critical. */
        public static Level of(double score) {
            if (score <= 0) {
                return NONE;
            }
            return score < 25 ? LOW : score < 50 ? MEDIUM : score < 75 ? HIGH : CRITICAL;
        }
    }

    /**
     * One thing that raised an entity's risk.
     *
     * @param source   what it came from, for example {@code alert:deny-storm-ip} or {@code ueba:volume}; an id
     * @param weight   its current weight in log-odds, already decayed, at least 0
     * @param at       when it happened
     * @param evidence audit sequence numbers behind it (0 to {@link Alert#MAX_EVIDENCE})
     * @param reason   one short sanitised line for a person
     */
    record Contribution(String source, double weight, Instant at, List<Long> evidence, String reason) {
        public static final int MAX_REASON = 160;

        public Contribution {
            Validate.id(source, "contribution.source");
            Validate.finite(weight, "contribution.weight");
            if (weight < 0) {
                throw new IllegalArgumentException("contributions only add risk");
            }
            Objects.requireNonNull(at, "contribution.at");
            evidence = List.copyOf(evidence);
            if (evidence.size() > Alert.MAX_EVIDENCE || evidence.stream().anyMatch(s -> s < 1)) {
                throw new IllegalArgumentException("0 to " + Alert.MAX_EVIDENCE + " audit sequence numbers, each at least 1");
            }
            String clean = Sanitize.text(Objects.requireNonNull(reason, "contribution.reason"), MAX_REASON);
            reason = clean.length() > MAX_REASON ? clean.substring(0, MAX_REASON) : clean;
        }
    }

    /**
     * @param score         0 to 100
     * @param contributions the largest contributions first, at most {@link #MAX_CONTRIBUTIONS}
     */
    record RiskView(Entity entity, double score, Level level, Instant asOf, List<Contribution> contributions) {
        public static final int MAX_CONTRIBUTIONS = 20;

        public RiskView {
            Objects.requireNonNull(entity, "entity");
            Validate.finite(score, "score");
            if (score < 0 || score > 100) {
                throw new IllegalArgumentException("score must be 0 to 100");
            }
            Objects.requireNonNull(level, "level");
            if (level != Level.of(score)) {
                throw new IllegalArgumentException("level " + level + " does not match score " + score);
            }
            Objects.requireNonNull(asOf, "asOf");
            contributions = List.copyOf(contributions);
            if (contributions.size() > MAX_CONTRIBUTIONS) {
                throw new IllegalArgumentException("at most " + MAX_CONTRIBUTIONS + " contributions");
            }
        }

        public static RiskView none(Entity entity, Instant now) {
            return new RiskView(entity, 0, Level.NONE, now, List.of());
        }
    }
}

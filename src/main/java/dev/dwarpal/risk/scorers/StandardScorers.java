package dev.dwarpal.risk.scorers;

import dev.dwarpal.behavior.BehaviorHistory;
import dev.dwarpal.behavior.FailureView;
import dev.dwarpal.behavior.TrustView;
import dev.dwarpal.pip.ThreatIntel;
import dev.dwarpal.risk.RiskScorer;

import java.util.List;
import java.util.function.Supplier;

/**
 * The Layer 2 scorer suite with its documented default parameters. Scorers receive read-only views
 * of the behaviour stores: only the learning loop and the authentication layer can write.
 */
public final class StandardScorers {

    private StandardScorers() {
    }

    public static List<RiskScorer> all(BehaviorHistory history, TrustView trust, FailureView failures,
                                       Supplier<ThreatIntel> threatIntel) {
        return List.of(
                NoveltyScorer.network(history),
                NoveltyScorer.device(history),
                ImpossibleTravelScorer.withDefaults(history),
                LoginTimeScorer.withDefaults(history),
                new TrustScorer(trust, TrustScorer.Entity.SUBJECT),
                new TrustScorer(trust, TrustScorer.Entity.DEVICE),
                FailureRateScorer.bruteForce(failures),
                FailureRateScorer.passwordSpray(failures),
                AttackSurgeScorer.withDefaults(failures),
                IpReputationScorer.withDefaults(threatIntel));
    }
}

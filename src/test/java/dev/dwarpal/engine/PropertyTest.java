package dev.dwarpal.engine;

import dev.dwarpal.Fixtures;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.risk.RiskAssessment;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.RiskScorer;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Properties that must hold for every input, checked on thousands of random cases (seeded, so a
 * failure is reproducible). Example-based tests show the engine works on cases we thought of;
 * these show the maths cannot be pushed the wrong way by cases we did not.
 */
class PropertyTest {

    private static final Random R = new Random(42);

    private static double randomLlr() {
        return (R.nextDouble() * 2 - 1) * 8;          // -8 .. +8, beyond the caps on purpose
    }

    @Test
    void higherAttackProbabilityNeverGivesAMorePermissiveAction() {
        for (int m = 0; m < 300; m++) {
            CostModel c = new CostModel(1 + R.nextDouble() * 5000, 0.1 + R.nextDouble() * 10,
                    0.1 + R.nextDouble() * 100, R.nextDouble());
            Outcome previous = Outcome.ALLOW;
            for (int i = 0; i <= 2000; i++) {
                Outcome now = c.bestAction(i / 2000.0);
                assertTrue(now.compareTo(previous) >= 0, c + " went from " + previous + " to " + now + " at p=" + i / 2000.0);
                previous = now;
            }
        }
    }

    @Test
    void moreAttackEvidenceNeverLowersTheProbability() {
        BayesianRiskAggregator agg = new BayesianRiskAggregator(0.001, Math.log(1000));
        for (int t = 0; t < 2000; t++) {
            List<RiskFactor> factors = new ArrayList<>();
            int n = 1 + R.nextInt(8);
            for (int i = 0; i < n; i++) {
                factors.add(new RiskFactor("f" + i, randomLlr(), "x"));
            }
            double before = agg.aggregate(factors, List.of()).posteriorAttack();
            int k = R.nextInt(n);
            List<RiskFactor> stronger = new ArrayList<>(factors);
            stronger.set(k, new RiskFactor("f" + k, factors.get(k).logLikelihoodRatio() + R.nextDouble() * 3, "x"));
            double after = agg.aggregate(stronger, List.of()).posteriorAttack();
            // Relative tolerance: when total reassurance sits at its cap, raising one reassuring factor
            // leaves the total unchanged and only the last binary digit can differ.
            assertTrue(after >= before * (1 - 1e-12), "raising factor " + k + " lowered P(attack): " + before + " -> " + after);

            List<RiskFactor> extra = new ArrayList<>(factors);
            extra.add(new RiskFactor("extra", R.nextDouble() * 8, "x"));
            assertTrue(agg.aggregate(extra, List.of()).posteriorAttack() >= before * (1 - 1e-12), "an extra attack factor lowered P(attack)");
        }
    }

    @Test
    void scorerOrderNeverChangesTheResult() {
        BayesianRiskAggregator agg = new BayesianRiskAggregator(0.001, Math.log(1000));
        for (int t = 0; t < 2000; t++) {
            List<RiskFactor> factors = new ArrayList<>();
            int n = 1 + R.nextInt(8);
            for (int i = 0; i < n; i++) {
                factors.add(new RiskFactor("f" + i, randomLlr(), "x"));
            }
            RiskAssessment a = agg.aggregate(factors, List.of());
            List<RiskFactor> shuffled = new ArrayList<>(factors);
            Collections.shuffle(shuffled, R);
            RiskAssessment b = agg.aggregate(shuffled, List.of());
            assertEquals(a.totalLogLikelihoodRatio(), b.totalLogLikelihoodRatio(), 1e-9);
            assertTrue(Double.isFinite(a.posteriorAttack()) && a.posteriorAttack() >= 0 && a.posteriorAttack() <= 1);
        }
    }

    private static RiskScorer fixed(String name, double llr) {
        return new RiskScorer() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public java.util.Optional<RiskFactor> score(AccessRequest r, dev.dwarpal.risk.SignalSnapshot s) {
                return java.util.Optional.of(new RiskFactor(name, llr, "x"));
            }
        };
    }

    private static AccessRequest randomRequest() {
        Fixtures.RequestBuilder b = Fixtures.request().action(Action.values()[R.nextInt(Action.values().length)]);
        switch (R.nextInt(4)) {
            case 0 -> b.resource("wiki", ResourceKind.PRIVATE_APP, DataClassification.INTERNAL);
            case 1 -> b.roles("finance").resource("payroll", ResourceKind.PRIVATE_APP, DataClassification.RESTRICTED);
            case 2 -> b.resource("crm", ResourceKind.SAAS_DATA, DataClassification.INTERNAL);
            default -> b.resource("news", ResourceKind.WEB, DataClassification.PUBLIC);
        }
        if (R.nextBoolean()) {
            b.unmanaged();
        }
        if (R.nextBoolean()) {
            b.unsignedPosture();
        }
        return b.build();
    }

    @Test
    void addingAttackEvidenceNeverMakesTheWholeEngineMorePermissive() {
        for (int t = 0; t < 1500; t++) {
            AccessRequest r = randomRequest();
            List<RiskScorer> base = new ArrayList<>();
            for (int i = 0; i < R.nextInt(5); i++) {
                base.add(fixed("s" + i, randomLlr()));
            }
            List<RiskScorer> more = new ArrayList<>(base);
            more.add(fixed("attack", R.nextDouble() * 8));
            Decision before = PolicyEngineTest.decide(PolicyEngineTest.engine(base.toArray(RiskScorer[]::new)), r);
            Decision after = PolicyEngineTest.decide(PolicyEngineTest.engine(more.toArray(RiskScorer[]::new)), r);
            assertTrue(after.outcome().compareTo(before.outcome()) >= 0,
                    "attack evidence loosened the decision: " + before.outcome() + " -> " + after.outcome() + "\n" + after.analystReport());
            // A restriction only matters while access is possible; once the outcome is DENY it is moot.
            assertTrue(!before.restricted() || after.restricted() || after.outcome() == Outcome.DENY,
                    "attack evidence lifted a restriction without denying");
        }
    }
}

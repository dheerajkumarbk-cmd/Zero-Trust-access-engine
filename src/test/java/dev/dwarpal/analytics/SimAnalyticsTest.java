package dev.dwarpal.analytics;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.sim.SimOrganisation;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.OptionalDouble;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * All of part C on the simulated organisation (seed 7, 60 users, 8 days of traffic), as in the plan: the live
 * pipeline with a recorder in front, then What-If, accuracy, calibration and sensitivity on the results. The
 * reports are written to {@code target/analytics-reports} for the notes file. These numbers measure
 * consistency with the threat model, not real-world accuracy.
 */
class SimAnalyticsTest {

    static final long SEED = 7;
    static final int USERS = 60;
    static final int DAYS = 8;
    static final CostModel COSTS = new CostModel(1000, 1, 20, 0.05);

    static SimOrganisation org;
    static RequestRecorder recorder;
    static List<SimOrganisation.Result> results;
    static List<Observation> observations;
    static DataSource source;

    @BeforeAll
    static void run() {
        org = SimOrganisation.create(SEED, USERS);
        recorder = new RequestRecorder(org.pipeline(org.engine()), 10_000, 100);
        results = org.run(recorder, org.traffic());
        observations = results.stream().map(r -> Observation.of(r.labelled().scenario().name(),
                r.labelled().scenario().attack(), r.decision())).toList();
        source = DataSource.simulated(SEED, USERS, DAYS, results.size());
    }

    private static void save(String name, Report r) throws IOException {
        Path dir = Path.of("target", "analytics-reports");
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(name + ".txt"), r.text(), StandardCharsets.UTF_8);
        Files.writeString(dir.resolve(name + ".json"), r.json(), StandardCharsets.UTF_8);
    }

    @Test
    void accuracyMatchesTheThreatModelsPromises() throws IOException {
        Accuracy a = Accuracy.of(observations, COSTS);
        Report r = a.report(source);
        save("accuracy", r);
        for (Accuracy.ScenarioStats s : a.scenarios()) {
            if (!s.attack()) {
                assertEquals(0L, s.outcomes().getOrDefault(Outcome.DENY, 0L), "legitimate never denied: " + s.scenario());
            }
            if (List.of("A1_FOREIGN_STUFFING", "A4_IMPOSSIBLE_TRAVEL", "A5_TOR", "A7_SPRAY_IP").contains(s.scenario())) {
                assertEquals(s.count(), s.outcomes().getOrDefault(Outcome.DENY, 0L), "always denied: " + s.scenario());
            }
        }
        assertEquals(results.size(), a.observations());
        // Better than chance, but not near 1: A6 (stolen laptop used at home) looks exactly like its owner.
        assertTrue(a.auc().getAsDouble() > 0.75, "AUC " + a.auc());
        assertTrue(r.text().contains("seed 7, 60 users, 8 days"));
    }

    @Test
    void calibrationOfFactorsAndBaseRate() throws IOException {
        List<Calibration.FactorCheck> f = Calibration.factors(observations);
        assertTrue(f.stream().anyMatch(c -> c.factor().equals("impossible-travel")), f.toString());
        Calibration.Estimate base = Calibration.baseRate(observations, 0.001);
        assertTrue(base.consistent().isPresent() && !base.consistent().get(),
                "the simulation is attack-enriched; its base rate must not be mistaken for the prior");
        // Poisson rate of password-spray failures per 15-minute window, from the simulation's failure steps:
        // 15 failures before each of 60 spray logins, in one window each.
        Calibration.Estimate spray = Calibration.rate("spray-failures-per-window", 15L * USERS, USERS, OptionalDouble.of(10));
        Report r = Calibration.report(source, List.of(base, spray), f);
        assertTrue(r.text().contains("impossible-travel"));
        save("calibration", r);
    }

    @Test
    void sensitivityOnTheObservedPosteriors() throws IOException {
        List<Double> ps = observations.stream().filter(o -> !o.gated()).map(Observation::posterior).toList();
        double[] betas = {0.01, 0.05, 0.10, 0.20, 0.30, 0.50};
        List<Sensitivity.Point> beta = Sensitivity.sweepBeta(COSTS, ps, betas);
        assertEquals(0, beta.get(1).changed(), "the base beta changes nothing");
        double[] k = {0.1, 0.5, 1, 2, 10};
        Report r = Sensitivity.report(source.withRequests(ps.size()), COSTS,
                java.util.Arrays.stream(betas).mapToObj(b -> Sensitivity.thresholds(COSTS, b)).toList(),
                List.of(beta, Sensitivity.sweepCost(COSTS, Sensitivity.Cost.BREACH, ps, k),
                        Sensitivity.sweepCost(COSTS, Sensitivity.Cost.FRICTION, ps, k),
                        Sensitivity.sweepCost(COSTS, Sensitivity.Cost.WRONG_DENY, ps, k)),
                Sensitivity.sweepMfa(COSTS, ps, betas));
        save("sensitivity", r);
    }

    @Test
    void whatIfOnRecordedTrafficHasNoSideEffects() throws IOException {
        assertEquals(results.size(), recorder.stats().kept());
        long audit = org.sink.lastSequence();
        int users = org.history.userCount();
        PolicyEngine engine = org.engine();
        WhatIf.Result w = new WhatIf(engine, new AnalyticsRedTeamTest.PolicySetEdits().withoutInternalApps(), org.directory)
                .replayRecorded(recorder.snapshot(), SignalSnapshot.empty());
        assertTrue(w.valid());
        assertTrue(w.losses() > 0);
        assertEquals(0, w.gains());
        assertTrue(w.fidelityMismatches().isPresent());
        assertEquals(audit, org.sink.lastSequence());
        assertEquals(users, org.history.userCount());
        save("whatif-recorded", w.report(new DataSource(DataSource.Kind.RECORDED, "SimOrganisation seed 7 via recorder",
                -1, USERS, DAYS, 0)));
    }

    @Test
    void auditTrailReadBackMatchesTheDecisions() {
        AuditDecisions.Result r = AuditDecisions.read(AuditCursor.fromStart(org.sink, org.auditKey), AuditDecisions.MAX_ENTRIES);
        assertTrue(r.problem().isEmpty());
        assertEquals(results.size(), r.entries().size());
        assertEquals(0, r.malformed());
        for (int i = 0; i < results.size(); i++) {
            assertEquals(results.get(i).decision().outcome(), r.entries().get(i).outcome());
        }
    }
}

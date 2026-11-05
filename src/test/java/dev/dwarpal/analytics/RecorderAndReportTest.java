package dev.dwarpal.analytics;

import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.OptionalDouble;
import java.util.Set;

import static dev.dwarpal.analytics.SmallWorld.ENGINEERING_READS_CONFIDENTIAL;
import static dev.dwarpal.analytics.SmallWorld.INTERNAL_APPS;
import static dev.dwarpal.analytics.SmallWorld.policies;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RecorderAndReportTest {

    private final DecisionPoint engine = SmallWorld.engine(policies("v1", INTERNAL_APPS));

    @Test
    void recorderLimitsAreChecked() {
        assertThrows(IllegalArgumentException.class, () -> new RequestRecorder(engine, 0, 1));
        assertThrows(IllegalArgumentException.class, () -> new RequestRecorder(engine, RequestRecorder.MAX_CAPACITY + 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new RequestRecorder(engine, 10, 0));
        assertThrows(IllegalArgumentException.class, () -> new RequestRecorder(engine, 10, 11));
        assertThrows(NullPointerException.class, () -> new RequestRecorder(null, 10, 1));
    }

    @Test
    void recorderReturnsTheDelegatesDecisionAndKeepsARing() {
        RequestRecorder rec = new RequestRecorder(engine, 5, 5);
        AccessRequest r = SmallWorld.request("a", SmallWorld.ALICE, SmallWorld.WIKI, Action.READ);
        Decision direct = engine.decide(r, SignalSnapshot.empty());
        assertEquals(direct, rec.decide(r, SignalSnapshot.empty()));
        for (int i = 0; i < 6; i++) {
            rec.decide(SmallWorld.request("b" + i, i % 2 == 0 ? SmallWorld.ALICE : SmallWorld.BOB, SmallWorld.WIKI,
                    Action.READ), SignalSnapshot.empty());
        }
        RequestRecorder.Stats s = rec.stats();
        assertEquals(5, s.kept());
        assertEquals(7, s.recorded());
        assertEquals(2, s.evicted());
        assertEquals(0, s.dropped());
        assertTrue(s.oldest().isPresent() && s.newest().isPresent());
        assertEquals("b1", rec.snapshot().getFirst().request().requestId());
        assertEquals(3, rec.forget("bob"));
        assertEquals(2, rec.snapshot().size());
        rec.clear();
        assertEquals(0, rec.stats().kept());
        assertTrue(rec.stats().oldest().isEmpty());
    }

    @Test
    void recorderFailureNeverChangesTheDecision() {
        // A decision whose policy id is not a valid identifier cannot be recorded: it is dropped, not denied.
        Decision odd = new Decision("x", Outcome.ALLOW, false, true, "", "v",
                dev.dwarpal.risk.RiskAssessment.notEvaluated(0.001), List.of(), dev.dwarpal.Fixtures.T0);
        RequestRecorder rec = new RequestRecorder((req, sig) -> odd, 5, 5);
        Decision out = rec.decide(SmallWorld.request("a", SmallWorld.ALICE, SmallWorld.WIKI, Action.READ),
                SignalSnapshot.empty());
        assertSame(odd, out);
        assertEquals(1, rec.stats().dropped());
        assertEquals(0, rec.stats().kept());
    }

    @Test
    void recordedTrafficReplaysWithFidelityMeasured() {
        RequestRecorder rec = new RequestRecorder(engine, 100, 50);
        for (AccessRequest r : SmallWorld.everything()) {
            rec.decide(r, SignalSnapshot.empty());
        }
        WhatIf.Result r = new WhatIf(SmallWorld.engine(policies("v1", INTERNAL_APPS)),
                policies("v2", INTERNAL_APPS, ENGINEERING_READS_CONFIDENTIAL), SmallWorld.DIRECTORY)
                .replayRecorded(rec.snapshot(), SignalSnapshot.empty());
        assertEquals(1, r.gains());
        // no device or posture condition in these policies and no scorers: stripping evidence changes nothing
        assertEquals(0L, r.fidelityMismatches().orElseThrow());
        assertEquals(18, r.liveVerifiedDevices());
        String text = r.report(new DataSource(DataSource.Kind.RECORDED, "recorder", -1, 2, 1, 0)).text();
        assertTrue(text.contains("replayed without evidence"), text);
        assertTrue(text.contains("without ground-truth labels"), text);
    }

    @Test
    void reportRendersNumbersRatesAndUndefinedValues() {
        Report r = Report.builder("T", DataSource.simulated(1, 2, 3, 4)).section("S")
                .number("pi", Math.PI).number("inf", Double.POSITIVE_INFINITY).rate("none", OptionalDouble.empty())
                .rate("half", OptionalDouble.of(0.5)).count("n", 3).text("t", "x").build();
        assertEquals("3.141593", r.line("S", "pi").orElseThrow().text());
        assertEquals("n/a", r.line("S", "inf").orElseThrow().text());
        assertTrue(r.line("S", "inf").orElseThrow().number().isEmpty());
        assertTrue(r.line("S", "missing").isEmpty());
        assertEquals("T", r.title());
        assertEquals(1, r.sections().size());
        assertEquals(1, r.source().seed());
        String json = r.json();
        assertTrue(json.contains("{\"label\":\"pi\",\"text\":\"3.141593\",\"value\":3.141593}"), json);
        assertTrue(json.contains("{\"label\":\"none\",\"text\":\"n/a\",\"value\":null}"), json);
        assertThrows(IllegalStateException.class, () -> Report.builder("T", DataSource.simulated(1, 1, 1, 1)).text("a", "b"));
        assertThrows(IllegalArgumentException.class, () -> new Report.Line("a", "b", OptionalDouble.of(Double.NaN)));
        Report.Builder many = Report.builder("T", DataSource.simulated(1, 1, 1, 1));
        assertThrows(IllegalStateException.class, () -> {
            for (int i = 0; i <= Report.MAX_SECTIONS; i++) {
                many.section("s" + i);
            }
        });
    }

    @Test
    void dataSourceStatementsAlwaysCarryACaveat() {
        for (DataSource.Kind k : DataSource.Kind.values()) {
            String s = new DataSource(k, "d", k == DataSource.Kind.SIMULATED || k == DataSource.Kind.SYNTHETIC ? 3 : -1,
                    1, 1, 1).statement();
            assertTrue(s.startsWith("Data: ") && s.contains("Caveat: "), s);
            assertFalse(s.toLowerCase(java.util.Locale.ROOT).contains("real-world accuracy") && k != DataSource.Kind.SIMULATED);
        }
        assertThrows(IllegalArgumentException.class, () -> DataSource.simulated(-1, 1, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new DataSource(DataSource.Kind.RECORDED, "d", -2, 1, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new DataSource(DataSource.Kind.RECORDED, "d", -1, -1, 1, 1));
        assertEquals(DataSource.MAX_DESCRIPTION + "...[truncated]".length(),
                new DataSource(DataSource.Kind.RECORDED, "x".repeat(500), -1, 0, 0, 0).description().length());
    }
}

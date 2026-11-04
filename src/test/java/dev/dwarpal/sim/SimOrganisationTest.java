package dev.dwarpal.sim;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.engine.DecisionPoint;
import org.junit.jupiter.api.Test;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static dev.dwarpal.sim.SimOrganisation.Scenario.A1_FOREIGN_STUFFING;
import static dev.dwarpal.sim.SimOrganisation.Scenario.A4_IMPOSSIBLE_TRAVEL;
import static dev.dwarpal.sim.SimOrganisation.Scenario.A5_TOR;
import static dev.dwarpal.sim.SimOrganisation.Scenario.A7_SPRAY_IP;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Layer 5 part 0: the simulated organisation is reproducible and labelled, and its traffic goes through
 * the real engine and the real audit trail. The checks repeat the accuracy invariants of Layer 2.
 */
class SimOrganisationTest {

    private static List<String> shape(SimOrganisation org) {
        return org.traffic().stream().map(s -> switch (s) {
            case SimOrganisation.RequestStep r -> r.labelled().request().requestId() + "@" + r.at() + "/"
                    + r.labelled().request().network().ip();
            case SimOrganisation.FailureStep f -> "fail@" + f.at();
        }).toList();
    }

    @Test
    void theSameSeedGivesTheSameOrganisationAndTraffic() {
        SimOrganisation a = SimOrganisation.create(42, 12);
        SimOrganisation b = SimOrganisation.create(42, 12);
        assertEquals(a.users.stream().map(u -> u.id() + u.kind() + u.city() + u.isp() + u.habit1() + u.habit2()).toList(),
                b.users.stream().map(u -> u.id() + u.kind() + u.city() + u.isp() + u.habit1() + u.habit2()).toList());
        assertEquals(shape(a), shape(b));
        assertNotEquals(shape(SimOrganisation.create(42, 12)), shape(SimOrganisation.create(43, 12)));
        assertThrows(IllegalArgumentException.class, () -> SimOrganisation.create(1, 5));
    }

    @Test
    void trafficIsLabelledAndInTimeOrder() {
        SimOrganisation org = SimOrganisation.create(5, 12);
        List<SimOrganisation.Step> steps = org.traffic();
        for (int i = 1; i < steps.size(); i++) {
            assertTrue(!steps.get(i).at().isBefore(steps.get(i - 1).at()), "time order at " + i);
        }
        long requests = steps.stream().filter(s -> s instanceof SimOrganisation.RequestStep).count();
        assertEquals(12L * SimOrganisation.Scenario.values().length, requests, "every scenario once per user");
        assertEquals(12L * 15, steps.size() - requests, "15 spray failures per user");
    }

    @Test
    void theEngineSeparatesLegitimateTrafficFromTheClearAttacks() {
        SimOrganisation org = SimOrganisation.create(7, 60);
        DecisionPoint pdp = org.pipeline(org.engine());
        List<SimOrganisation.Result> results = org.run(pdp, org.traffic());
        Map<SimOrganisation.Scenario, EnumMap<Outcome, Integer>> table = new EnumMap<>(SimOrganisation.Scenario.class);
        for (SimOrganisation.Result r : results) {
            table.computeIfAbsent(r.labelled().scenario(), k -> new EnumMap<>(Outcome.class))
                    .merge(r.decision().outcome(), 1, Integer::sum);
        }
        for (SimOrganisation.Scenario s : SimOrganisation.Scenario.values()) {
            if (!s.attack()) {
                assertEquals(0, table.get(s).getOrDefault(Outcome.DENY, 0), s + ": a legitimate user was denied");
            }
        }
        for (SimOrganisation.Scenario s : List.of(A1_FOREIGN_STUFFING, A4_IMPOSSIBLE_TRAVEL, A5_TOR, A7_SPRAY_IP)) {
            assertEquals(60, table.get(s).getOrDefault(Outcome.DENY, 0), s + ": not always denied " + table.get(s));
        }

        // Every decision is in the audit trail, intact, in order.
        AuditCursor c = AuditCursor.fromStart(org.sink, org.auditKey);
        int decisions = 0;
        for (AuditCursor.Batch b = c.next(5000); !b.events().isEmpty(); b = c.next(5000)) {
            assertTrue(b.problem().isEmpty());
            decisions += (int) b.events().stream().filter(e -> e.type().equals("ACCESS_DECISION")).count();
        }
        assertEquals(results.size(), decisions);
        assertTrue(c.checkAgainst(org.audit.head()).isEmpty());
    }
}

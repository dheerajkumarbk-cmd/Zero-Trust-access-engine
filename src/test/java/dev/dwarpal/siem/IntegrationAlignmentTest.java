package dev.dwarpal.siem;

import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.response.Playbooks;
import dev.dwarpal.sim.SimOrganisation;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Layer 5 integration: part A's rules and part B's playbooks agree on names, and the rules match on the
 * machine-readable fields other packages now write, not on wording.
 */
class IntegrationAlignmentTest {

    private static final Set<String> ALL_RULE_IDS = Set.of(Rules.BREAK_GLASS, Rules.HONEYTOKEN, Rules.STOLEN_TOKEN,
            Rules.DENY_STORM_SUBJECT, Rules.DENY_STORM_IP, Rules.MFA_FATIGUE, Rules.TRAVEL_THEN_ALLOW, Rules.DLP_SPIKE,
            Rules.PAM_REFUSED, Rules.BREAK_GLASS_REFUSED, DetectionEngine.CHAIN_BREAK, DetectionEngine.ANCHOR_MISMATCH,
            DetectionEngine.ALERT_FLOOD, DetectionEngine.STATE_FULL);

    /** Probe (before integration): four plays were keyed by names no rule raised, so they never ran. */
    @Test
    void everyRuleHasItsOwnPlayAndEveryPlayHasARule() {
        assertEquals(ALL_RULE_IDS, Playbooks.referencePlays().keySet());
    }

    private static AuditEvent event(String type, Map<String, String> fields) {
        String payload = dev.dwarpal.audit.Json.object(fields);
        return AuditEvent.of(new AuditRecord(1, Instant.EPOCH, type, "t", payload, "0".repeat(64), "1".repeat(64)));
    }

    @Test
    void tokenTheftIsMatchedOnTheCauseNotTheWording() {
        assertTrue(Rules.tokenTheft(event("SESSION_REVOKED", Map.of("cause", "token-theft", "reason", "reworded"))));
        assertFalse(Rules.tokenTheft(event("SESSION_REVOKED",
                Map.of("cause", "other", "reason", "possible token theft"))), "the cause decides when present");
        assertTrue(Rules.tokenTheft(event("SESSION_REVOKED", Map.of("reason", "x: possible token theft"))),
                "older trails without a cause still work");
    }

    @Test
    void travelIsMatchedOnTheSignalNames() {
        assertTrue(Rules.impossibleTravel(event("ACCESS_DECISION", Map.of("signals", "impossible-travel,network-novelty"))));
        assertFalse(Rules.impossibleTravel(event("ACCESS_DECISION", Map.of("signals", "impossible-travel-ish"))),
                "exact names only");
        assertFalse(Rules.impossibleTravel(event("ACCESS_DECISION", Map.of("signals", "",
                "factors", "[RiskFactor[name=impossible-travel, logLikelihoodRatio=3.0, evidence=x]]"))),
                "the signals field decides when present");
    }

    /** The decisions Dwarpal writes carry the signals field, and travel shows up in it on the simulation. */
    @Test
    void decisionsOnTheSimulatedOrganisationCarrySignals() {
        SimOrganisation org = SimOrganisation.create(7, 60);
        org.run(org.pipeline(org.engine()), org.traffic());
        long decisions = 0;
        long travel = 0;
        for (AuditRecord r : org.sink.snapshot()) {
            AuditEvent e = AuditEvent.of(r);
            if (e.type().equals("ACCESS_DECISION")) {
                decisions++;
                assertTrue(e.field("signals").isPresent());
                travel += Rules.impossibleTravel(e) ? 1 : 0;
            }
        }
        assertTrue(decisions > 0);
        assertTrue(travel > 0, "scenario A2 (impossible travel) is visible to the rule");
    }
}

package dev.dwarpal.behavior;

import dev.dwarpal.Fixtures;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.risk.RiskAssessment;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Memory bounds of the stores and the anti-poisoning rules of the learning loop. */
class BehaviorStoresTest {

    private static final Instant T = Fixtures.T0;

    private static LoginEvent login(String user, String ip, Instant at) {
        return new LoginEvent(user, "dev-" + user, new NetworkContext(ip, "AS1", "IN", 0, 0, 1), at);
    }

    // ---- bounds (attacker-chosen keys must not exhaust memory) ---------------------------------

    @Test
    void perUserValuesAreBounded() {
        InMemoryBehaviorHistory h = new InMemoryBehaviorHistory();
        for (int i = 0; i < 300; i++) {
            h.record(login("alice", "10.0." + (i / 250) + "." + (i % 250), T.plusSeconds(i)));
        }
        assertEquals(InMemoryBehaviorHistory.MAX_VALUES_PER_FEATURE, h.distinct("alice", Feature.IP));
        assertEquals(300, h.logins("alice"));
        assertEquals(InMemoryBehaviorHistory.MAX_TIMES, h.loginMinutes("alice").size(),
                "only the most recent login times are kept");
    }

    @Test
    void userCountIsBoundedWithLeastRecentlyUsedEviction() {
        InMemoryBehaviorHistory h = new InMemoryBehaviorHistory(3);
        for (String u : List.of("a", "b", "c")) {
            h.record(login(u, "1.1.1.1", T));
        }
        h.logins("a");                            // touch a: b is now the eldest
        h.record(login("d", "1.1.1.1", T));
        assertEquals(3, h.userCount());
        assertEquals(0, h.logins("b"));
        assertEquals(1, h.logins("a"));
    }

    @Test
    void lastLoginIsTheNewestEvenIfEventsArriveOutOfOrder() {
        InMemoryBehaviorHistory h = new InMemoryBehaviorHistory();
        h.record(login("alice", "1.1.1.1", T));
        h.record(login("alice", "2.2.2.2", T.minusSeconds(60)));
        assertEquals("1.1.1.1", h.lastLogin("alice").orElseThrow().network().ip());
        h.forget("alice");
        assertTrue(h.lastLogin("alice").isEmpty());
        assertFalse(h.seen("alice", Feature.IP, "1.1.1.1"));
        assertEquals(0, h.distinct("nobody", Feature.IP));
        assertTrue(h.loginMinutes("nobody").isEmpty());
    }

    @Test
    void failureLogAndLedgerAreBoundedPerKey() {
        FailureLog log = new FailureLog();
        for (int i = 0; i < FailureLog.MAX_PER_KEY + 50; i++) {
            log.recordFailure("alice", "1.2.3.4", T);
        }
        assertEquals(FailureLog.MAX_PER_KEY, log.subjectFailures("alice", T.minusSeconds(1), T));
        assertEquals(0, log.subjectFailures("nobody", T.minusSeconds(1), T));
        assertEquals(0, log.distinctSubjectsFromIp("9.9.9.9", T.minusSeconds(1), T));
        assertThrows(IllegalArgumentException.class, () -> log.recordFailure("bad\nid", "1.2.3.4", T));

        TrustLedger ledger = new TrustLedger(Duration.ofDays(3650));
        for (int i = 0; i < TrustLedger.MAX_EVENTS_PER_ENTITY + 10; i++) {
            ledger.recordGood("subject:alice", T);
        }
        assertEquals(TrustLedger.MAX_EVENTS_PER_ENTITY, ledger.trust("subject:alice", T).good(), 1e-6);
    }

    // ---- learning loop -------------------------------------------------------------------------

    private final InMemoryBehaviorHistory history = new InMemoryBehaviorHistory();
    private final TrustLedger trust = new TrustLedger(Duration.ofDays(30));

    private Decision run(Outcome outcome, boolean restricted, double posterior, List<String> failed, String policy) {
        return run(outcome, restricted, posterior, failed, policy, true);
    }

    private Decision run(Outcome outcome, boolean restricted, double posterior, List<String> failed, String policy,
                         boolean deviceVerified) {
        Decision fixed = new Decision("req-1", outcome, restricted, deviceVerified, policy, "v",
                new RiskAssessment(List.of(), 0.001, 0, posterior, failed), List.of(), T);
        LearningDecisionPoint pdp = new LearningDecisionPoint((r, s) -> fixed, history, trust, 0.01,
                Clock.fixed(T, ZoneOffset.UTC), Duration.ofMinutes(5));
        Decision out = pdp.decide(Fixtures.request().build(), SignalSnapshot.empty());
        assertSame(fixed, out, "learning never changes the decision");
        assertEquals(0, pdp.learningFailures());
        return out;
    }

    private boolean learned() {
        return history.logins("alice") > 0;
    }

    private boolean trusted() {
        return trust.trust(TrustLedger.subjectKey("alice"), T).good() > 0;
    }

    @Test
    void lowRiskAllowTeachesBaselineAndTrust() {
        run(Outcome.ALLOW, false, 0.0001, List.of(), "P-01");
        assertTrue(learned());
        assertTrue(trusted());
        assertTrue(trust.trust(TrustLedger.deviceKey("laptop-alice"), T).good() > 0);
    }

    @Test
    void allowAfterStepUpTeachesBaselineButNotTrust() {
        run(Outcome.ALLOW, false, 0.06, List.of(), "P-01");
        assertTrue(learned(), "a verified traveller's new location becomes familiar");
        assertFalse(trusted(), "but earns no reputation from a risky-looking login");
    }

    @Test
    void stepUpDenyRestrictedAndDegradedDecisionsTeachNothing() {
        run(Outcome.STEP_UP, false, 0.05, List.of(), "P-01");
        run(Outcome.DENY, false, 0.99, List.of(), "P-01");
        run(Outcome.ALLOW_LIMITED, true, 0.0001, List.of(), "P-21");
        run(Outcome.ALLOW, false, 0.0001, List.of("geoip"), "P-01");
        assertFalse(learned());
        assertFalse(trusted());
    }

    @Test
    void ordinaryDenialsNeverDamageTheVictimsReputation() {
        for (int i = 0; i < 50; i++) {
            run(Outcome.DENY, false, 0.999, List.of(), "P-90-very-high-risk");
        }
        assertFalse(trust.trust(TrustLedger.subjectKey("alice"), T).hasEvidence(),
                "an attacker spamming bad logins as alice must not lock alice out");
    }

    @Test
    void honeytokenHitMarksTheDeviceBad() {
        run(Outcome.DENY, false, 0.001, List.of(), "hard-gate:honeytoken");
        assertTrue(trust.trust(TrustLedger.deviceKey("laptop-alice"), T).bad() > 0);
        assertFalse(trust.trust(TrustLedger.subjectKey("alice"), T).hasEvidence());
    }

    @Test
    void futureOrStaleRequestsAreNeverLearned() {
        // Red-team finding: one ALLOW stamped years ahead became the "last login" and silenced
        // impossible-travel detection for the user. The learner now checks its own clock.
        Decision allow = new Decision("req-f", Outcome.ALLOW, false, true, "P-01", "v",
                new RiskAssessment(List.of(), 0.001, 0, 0.0001, List.of()), List.of(), T);
        LearningDecisionPoint pdp = new LearningDecisionPoint((r, s) -> allow, history, trust, 0.01,
                Clock.fixed(T, ZoneOffset.UTC), Duration.ofMinutes(5));
        pdp.decide(Fixtures.request().at(T.plus(Duration.ofDays(1500))).build(), SignalSnapshot.empty());
        pdp.decide(Fixtures.request().at(T.minus(Duration.ofDays(3))).build(), SignalSnapshot.empty());
        assertFalse(learned());
        assertEquals(2, pdp.rejectedTimestamps());
        pdp.decide(Fixtures.request().at(T.plusSeconds(30)).build(), SignalSnapshot.empty());
        assertTrue(learned(), "a fresh request is still learned");
    }

    @Test
    void unprovenDevicesAreLearnedAsOneBucketAndEarnNoReputation() {
        run(Outcome.ALLOW, false, 0.0001, List.of(), "P-01", false);
        assertTrue(history.seen("alice", Feature.DEVICE, LoginEvent.UNVERIFIED_DEVICE));
        assertFalse(history.seen("alice", Feature.DEVICE, "laptop-alice"), "a typed device id is never learned");
        assertFalse(trust.trust(TrustLedger.deviceKey("laptop-alice"), T).hasEvidence());
        assertTrue(trusted(), "the user still earns reputation");
    }

    @Test
    void honeytokenWithAnUnprovenDeviceIdDoesNotFrameTheRealDevice() {
        // Attacker uses a honeytoken while typing alice's laptop id: the laptop must not be marked.
        run(Outcome.DENY, false, 0.001, List.of(), "hard-gate:honeytoken", false);
        assertFalse(trust.trust(TrustLedger.deviceKey("laptop-alice"), T).hasEvidence());
    }

    @Test
    void floodingCannotEvictRecentAttackEvidence() {
        // Red-team finding C2: an LRU store could be flushed with junk to erase spray evidence.
        FailureLog log = new FailureLog(50);
        for (int i = 0; i < 12; i++) {
            log.recordFailure("user" + i, "198.51.100.66", T.minusSeconds(100 + i));
        }
        for (int i = 0; i < 500; i++) {
            log.recordFailure("noise" + i, "10.0." + (i / 250) + "." + (i % 250), T.minusSeconds(50));
        }
        assertEquals(12, log.distinctSubjectsFromIp("198.51.100.66", T.minus(Duration.ofMinutes(15)), T),
                "spray evidence survives the flood");
        assertTrue(log.droppedKeys() > 0, "the flood is visible as dropped keys");
        assertEquals(512, log.totalFailures(T.minus(Duration.ofMinutes(15)), T), "and fully counted org-wide");
    }

    @Test
    void staleEvidenceIsStillEvictedSoTheStoreStaysBounded() {
        FailureLog log = new FailureLog(10);
        for (int i = 0; i < 10; i++) {
            log.recordFailure("old" + i, "10.9.9." + i, T.minus(Duration.ofHours(3)));
        }
        log.recordFailure("new", "10.8.8.8", T);
        assertEquals(1, log.subjectFailures("new", T.minusSeconds(1), T));
        assertEquals(0, log.subjectFailures("old0", T.minus(Duration.ofHours(4)), T), "eldest stale entry evicted");
        assertEquals(0, log.droppedKeys());
        // The org-wide ring has 120 minute slots: a minute two hours later reuses the slot and must
        // replace the old count, never add to it.
        FailureLog ring = new FailureLog();
        ring.recordFailure("a", "1.1.1.1", T);
        ring.recordFailure("b", "1.1.1.2", T.plus(Duration.ofMinutes(120)));
        assertEquals(0, ring.totalFailures(T, T.plusSeconds(59)), "overwritten slot no longer reports the old minute");
        assertEquals(1, ring.totalFailures(T.plus(Duration.ofMinutes(120)), T.plus(Duration.ofMinutes(120)).plusSeconds(59)));
    }

    @Test
    void noveltyCountsRecentNewValues() {
        InMemoryBehaviorHistory h = new InMemoryBehaviorHistory();
        assertEquals(0.5, h.novelty("nobody", Feature.IP).pNew(), 1e-12, "no history: a coin flip");
        h.record(login("alice", "1.1.1.1", T));
        h.record(login("alice", "1.1.1.1", T.plusSeconds(1)));
        h.record(login("alice", "2.2.2.2", T.plusSeconds(2)));
        assertEquals(new BehaviorHistory.Novelty(2, 3), h.novelty("alice", Feature.IP));
    }

    @Test
    void validation() {
        assertThrows(IllegalArgumentException.class,
                () -> new LearningDecisionPoint((r, s) -> null, history, trust, 1.5, Clock.systemUTC(), Duration.ofMinutes(5)));
        assertThrows(IllegalArgumentException.class,
                () -> new LearningDecisionPoint((r, s) -> null, history, trust, 0.01, Clock.systemUTC(), Duration.ZERO));
        AccessRequest r = Fixtures.request().build();
        assertEquals("AS64500", LoginEvent.of(r, true).value(Feature.ASN));
        assertEquals(9 * 60 + 30, LoginEvent.of(r, true).minuteOfDayUtc());
    }
}

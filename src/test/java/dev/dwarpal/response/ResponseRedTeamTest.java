package dev.dwarpal.response;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.casb.DataGuard;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static dev.dwarpal.soc.Verdict.Outcome.FALSE_POSITIVE;
import static dev.dwarpal.soc.Verdict.Outcome.TRUE_POSITIVE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Red-team pass on part B. Each test is a probe that worked against the first version (see the notes
 * file, findings B-R1 to B-R8), kept as a regression test after the fix. Most are attacks on the SOC
 * itself: turning the response loop against innocent people, or using it to free an attacker.
 */
class ResponseRedTeamTest {

    private final ResponseWorld w = new ResponseWorld();

    @Test
    void r1_aRequestDatedInTheFutureCannotMakeAWatchLookFaded() {
        w.feed.watch(SignalFeed.Kind.SUBJECT, "alice", Math.log(1000), Duration.ofHours(1), "soc-ana", "case-1");
        AccessRequest fromTheFuture = Fixtures.request().at(w.now().plus(Duration.ofDays(30))).build();
        double llr = new WatchlistScorer(w.feed, w.clock).score(fromTheFuture, SignalSnapshot.empty())
                .orElseThrow().logLikelihoodRatio();
        assertEquals(Math.log(1000), llr, 1e-9);
    }

    @Test
    void r2_aFalsePositiveOnOneCaseDoesNotFreeThePersonFromAnother() {
        String real = w.raise("break-glass-used", Severity.HIGH, Entity.subject("carol"));
        assertEquals(Playbooks.Status.APPLIED, w.decide("ana", real, TRUE_POSITIVE).status());
        w.later(Duration.ofHours(2));
        // the attacker gets a second, harmless-looking alert about the same person raised and called a false positive
        String decoy = w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("carol"));
        w.decide("ben", decoy, TRUE_POSITIVE);
        w.later(Duration.ofMinutes(1));
        assertEquals(Playbooks.Status.UNDONE, w.decide("cleo", decoy, FALSE_POSITIVE).status());
        assertTrue(w.feed.denied(SignalFeed.Kind.SUBJECT, "carol", w.now()), "case 1's deny stays");
        w.later(Duration.ofHours(22).minusMinutes(2));
        assertTrue(w.feed.denied(SignalFeed.Kind.SUBJECT, "carol", w.now()), "with the time it had left");
        w.later(Duration.ofMinutes(2));
        assertFalse(w.feed.denied(SignalFeed.Kind.SUBJECT, "carol", w.now()));
    }

    @Test
    void r3_theTwoPersonRuleCoversThePrivilegedPersonsDeviceAndAddressToo() {
        String id = w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("root"), Entity.device("laptop-root"),
                Entity.ip("192.0.2.200"));
        assertEquals(Playbooks.Status.AWAITING_SECOND_ANALYST, w.decide("ana", id, TRUE_POSITIVE).status());
        assertEquals(0, w.enforcement.destructive(), "no revoke of root's laptop on one analyst's word");
        assertFalse(w.feed.denied(SignalFeed.Kind.DEVICE, "laptop-root", w.now()));
        assertFalse(w.feed.denied(SignalFeed.Kind.IP, "192.0.2.200", w.now()));
    }

    @Test
    void r4_oneStolenAnalystKeyCannotLiftWhatTwoAnalystsConfirmed() {
        String id = w.raise("break-glass-used", Severity.HIGH, Entity.subject("root"));
        w.decide("ana", id, TRUE_POSITIVE);
        w.decide("ben", id, TRUE_POSITIVE);
        assertTrue(w.feed.denied(SignalFeed.Kind.SUBJECT, "root", w.now()));
        w.decide("cleo", id, FALSE_POSITIVE);
        assertTrue(w.feed.denied(SignalFeed.Kind.SUBJECT, "root", w.now()));
    }

    @Test
    void r5_anAnalystNamedAnywhereInACaseCannotDecideIt() {
        // the case is keyed on alice, but the alert also names ana (they shared a laptop)
        String id = w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("alice"), Entity.subject("ana"));
        w.decide("ben", id, TRUE_POSITIVE);
        assertTrue(w.feed.denied(SignalFeed.Kind.SUBJECT, "ana", w.now()) || w.playbooks.pending().size() == 1);
        w.later(Duration.ofMinutes(1));
        Playbooks.Result r = w.decide("ana", id, FALSE_POSITIVE);
        assertEquals(Playbooks.Status.REFUSED, r.status(), "ana cannot clear herself");
        // and an alert that only later names her joins the case and still makes her a party to it
        String later = w.raise("pam-refused", Severity.LOW, Entity.subject("dave"));
        Alert second = w.alert("pam-refused", Severity.LOW, Entity.subject("dave"), Entity.subject("cleo"));
        assertTrue(w.book.raise(second));
        assertEquals(Playbooks.Status.REFUSED, w.decide("cleo", later, FALSE_POSITIVE).status());
    }

    @Test
    void r6_aFloodOfLowAlertsCannotShutOutACriticalOne() {
        ResponseWorld small = new ResponseWorld(ResponseSettings.defaults().withLimits(20, 10, 50, 5));
        for (int i = 0; small.book.size() < 50; i++) {
            small.book.raise(small.alert("deny-storm-ip", Severity.LOW, Entity.ip("192.0.2." + i)));
        }
        Alert critical = small.alert("honeytoken-touched", Severity.CRITICAL, Entity.subject("alice"));
        assertTrue(small.book.raise(critical));
        assertEquals(1, small.book.dropped());
        assertEquals(1, small.audited("CASE_DROPPED"));
        assertFalse(small.book.raise(small.alert("deny-storm-ip", Severity.LOW, Entity.ip("192.0.3.1"))),
                "the flood itself is refused, not the other way round");
    }

    @Test
    void r7_dlpRecordsWithoutAValidMacDoNotRaiseAnyonesRisk() {
        // someone with write access to the audit store (but not the key) appends a convincing DLP record
        InMemoryAuditSink store = new InMemoryAuditSink();
        AuditLog forger = new AuditLog(ResponseWorld.newKey(), store);
        for (int i = 0; i < 5; i++) {
            forger.append(DataGuard.AUDIT_TYPE, "alice", w.now(), Map.of("action", "BLOCK",
                    "classification", "RESTRICTED"));
        }
        DlpFeedback fb = new DlpFeedback(store, w.auditKey, w.ledger, w.clock);
        assertTrue(fb.poll(100).problem().isPresent());
        assertEquals(0, w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "alice", w.now()));
        assertEquals(Outcome.ALLOW, w.aliceAsks().outcome());
    }

    @Test
    void r8_oneVerdictOnAnAlertNamingManyPeopleIsLimitedPerTarget() {
        ResponseWorld small = new ResponseWorld(ResponseSettings.defaults().withLimits(6, 6, 100, 100));
        List<Entity> many = new ArrayList<>();
        for (int i = 0; i < Alert.MAX_ENTITIES; i++) {
            many.add(Entity.subject("staff-" + i));
        }
        String id = small.raise("break-glass-used", Severity.HIGH, many.toArray(Entity[]::new));
        Playbooks.Result r = small.decide("ana", id, TRUE_POSITIVE);
        assertEquals(Playbooks.Status.PARTIAL, r.status());
        assertEquals(6, small.enforcement.destructive() + small.audited("SIGNAL_DENY"));
    }
}

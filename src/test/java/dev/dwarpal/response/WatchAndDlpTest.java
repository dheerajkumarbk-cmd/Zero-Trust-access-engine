package dev.dwarpal.response;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.casb.DataGuard;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 5 part B: the watch list as a risk factor, and DLP findings fed back as decaying evidence. */
class WatchAndDlpTest {

    private final ResponseWorld w = new ResponseWorld();
    private final WatchlistScorer scorer = new WatchlistScorer(w.feed, w.clock);

    private Optional<RiskFactor> score() {
        AccessRequest r = Fixtures.request().at(w.now()).build();
        return scorer.score(r, SignalSnapshot.empty());
    }

    private void dlp(String subject, String action, String classification) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("reference", "rq-1");
        f.put("resource", "saas:drive");
        f.put("classification", classification);
        f.put("action", action);
        f.put("inspectable", "true");
        f.put("count", "1");
        f.put("types", "CARD_NUMBER");
        f.put("findings", "CARD_NUMBER@0-16");
        w.audit.append(DataGuard.AUDIT_TYPE, subject, w.now(), f);
    }

    @Test
    void theScorerIsSilentWithoutAWatchAndAddsUpPersonDeviceAndAddress() {
        assertEquals(WatchlistScorer.NAME, scorer.name());
        assertTrue(score().isEmpty());
        w.feed.watch(SignalFeed.Kind.SUBJECT, "alice", Math.log(10), Duration.ofDays(1), "soc-ana", "case-1");
        w.feed.watch(SignalFeed.Kind.DEVICE, "laptop-alice", Math.log(2), Duration.ofDays(1), "soc-ana", "case-1");
        w.feed.watch(SignalFeed.Kind.IP, "203.0.113.10", Math.log(3), Duration.ofDays(1), "soc-ana", "case-1");
        RiskFactor f = score().orElseThrow();
        assertEquals(Math.log(60), f.logLikelihoodRatio(), 1e-9);
        assertTrue(f.evidence().contains("person 2.30"), f.evidence());
        assertFalse(f.evidence().contains("case-1"), "analysts' reasons stay in the audit trail");
    }

    @Test
    void theScorerIsCapped() {
        for (SignalFeed.Kind k : SignalFeed.Kind.values()) {
            String id = switch (k) {
                case SUBJECT -> "alice";
                case DEVICE -> "laptop-alice";
                case IP -> "203.0.113.10";
            };
            w.feed.watch(k, id, SignalFeed.MAX_WATCH_LOG_LR, Duration.ofDays(1), "soc-ana", "x");
        }
        assertEquals(WatchlistScorer.MAX_LOG_LR, score().orElseThrow().logLikelihoodRatio(), 1e-12);
    }

    @Test
    void theScorerFollowsTheDecay() {
        w.feed.watch(SignalFeed.Kind.SUBJECT, "alice", Math.log(100), Duration.ofHours(6), "soc-ana", "x");
        w.later(Duration.ofHours(12));
        assertEquals(Math.log(100) / 4, score().orElseThrow().logLikelihoodRatio(), 1e-9);
        w.later(Duration.ofDays(30));
        assertTrue(score().isEmpty(), "faded away");
    }

    @Test
    void repeatedDlpAttemptsRaiseRiskAndASingleOneFades() {
        DlpFeedback fb = new DlpFeedback(w.sink, w.auditKey, w.ledger, w.clock);
        dlp("carol", "BLOCK", "INTERNAL");
        DlpFeedback.Poll p = fb.poll(100);
        assertEquals(1, p.applied());
        double one = w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "carol", w.now());
        assertEquals(Math.log(4), one, 1e-9);
        dlp("carol", "BLOCK", "INTERNAL");
        dlp("carol", "REDACT", "CONFIDENTIAL");
        fb.poll(100);
        double three = w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "carol", w.now());
        assertEquals(Math.log(4) * 2 + Math.log(2) * 1.5, three, 1e-9);
        w.later(DlpFeedback.HALF_LIFE);
        assertEquals(three / 2, w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "carol", w.now()), 1e-9);
        assertTrue(score().isEmpty(), "alice is not carol");
    }

    @Test
    void dlpAloneNeverReachesTheLevelOfAConfirmedAttack() {
        DlpFeedback fb = new DlpFeedback(w.sink, w.auditKey, w.ledger, w.clock);
        for (int i = 0; i < 15; i++) {
            dlp("dave", "BLOCK", "RESTRICTED");
        }
        DlpFeedback.Poll p = fb.poll(1000);
        assertEquals(DlpFeedback.MAX_DLP_LOG_LR, w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "dave", w.now()), 1e-9);
        assertTrue(p.skipped() > 0);
    }

    @Test
    void dlpUpdatesAreLimitedPerPerson() {
        DlpFeedback fb = new DlpFeedback(w.sink, w.auditKey, w.ledger, w.clock);
        for (int i = 0; i < 30; i++) {
            dlp("erin", "AUDIT", "INTERNAL");
        }
        DlpFeedback.Poll p = fb.poll(1000);
        assertEquals(DlpFeedback.UPDATES_PER_HOUR, p.applied());
        assertEquals(20, p.limited());
    }

    @Test
    void onlyDlpRecordsWeUnderstandCount() {
        DlpFeedback fb = new DlpFeedback(w.sink, w.auditKey, w.ledger, w.clock);
        dlp("carol", "SHRUG", "INTERNAL");
        w.audit.append("SESSION_OPENED", "carol", w.now(), Map.of("session", "s-1"));
        DlpFeedback.Poll p = fb.poll(100);
        assertEquals(0, p.applied());
        assertEquals(1, p.skipped());
        assertEquals(2, p.read());
        assertEquals(0, w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "carol", w.now()));
        assertEquals(0, DlpFeedback.weight(AuditEvent.of(w.sink.snapshot().getFirst())));
    }

    @Test
    void itResumesFromACheckpointWithoutCountingTwice() {
        DlpFeedback fb = new DlpFeedback(w.sink, w.auditKey, w.ledger, w.clock);
        dlp("carol", "BLOCK", "INTERNAL");
        fb.poll(100);
        AuditLog.Head head = fb.checkpoint();
        dlp("carol", "BLOCK", "INTERNAL");
        DlpFeedback resumed = new DlpFeedback(w.sink, w.auditKey, head, w.ledger, w.clock);
        DlpFeedback.Poll p = resumed.poll(100);
        // only the second DLP record (and the feed's own SIGNAL_WATCH record) are new
        assertEquals(1, p.applied());
        assertEquals(Math.log(4) * 2, w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "carol", w.now()), 1e-9);
    }

    @Test
    void aBrokenTrailStopsTheFeedbackForGood() {
        InMemoryAuditSink forged = new InMemoryAuditSink();
        AuditLog other = new AuditLog(ResponseWorld.newKey(), forged);
        other.append(DataGuard.AUDIT_TYPE, "alice", w.now(), Map.of("action", "BLOCK", "classification", "RESTRICTED"));
        DlpFeedback fb = new DlpFeedback(forged, w.auditKey, w.ledger, w.clock);
        DlpFeedback.Poll p = fb.poll(100);
        assertTrue(p.problem().isPresent());
        assertEquals(0, p.applied());
        assertTrue(fb.broken().isPresent());
        assertEquals(0, w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "alice", w.now()));
        List<AuditRecord> none = forged.after(1, 10);
        assertTrue(none.isEmpty());
    }

    @Test
    void aFalsePositiveDoesNotLiftDlpEvidence() {
        DlpFeedback fb = new DlpFeedback(w.sink, w.auditKey, w.ledger, w.clock);
        dlp("carol", "BLOCK", "INTERNAL");
        fb.poll(100);
        String id = w.raise("pam-refused", dev.dwarpal.soc.Severity.LOW, dev.dwarpal.soc.Entity.subject("carol"));
        w.decide("ana", id, dev.dwarpal.soc.Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(Math.log(40), w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "carol", w.now()), 1e-9);
        w.later(Duration.ofMinutes(1));
        w.decide("ben", id, dev.dwarpal.soc.Verdict.Outcome.FALSE_POSITIVE);
        assertEquals(Math.log(4), w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "carol", w.now()), 1e-3,
                "the case's watch is gone, the DLP evidence stays");
    }
}

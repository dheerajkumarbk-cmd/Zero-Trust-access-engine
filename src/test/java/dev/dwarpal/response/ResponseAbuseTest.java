package dev.dwarpal.response;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Verdict;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import static dev.dwarpal.soc.Verdict.Outcome.BENIGN;
import static dev.dwarpal.soc.Verdict.Outcome.FALSE_POSITIVE;
import static dev.dwarpal.soc.Verdict.Outcome.TRUE_POSITIVE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 5 part B, abuse cases first: the SOC loop must not be usable against the people it protects. */
class ResponseAbuseTest {

    private final ResponseWorld w = new ResponseWorld();

    private String honeytokenOnAlice() {
        return w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("alice"), Entity.device("laptop-alice"),
                Entity.ip("203.0.113.10"));
    }

    private void nothingHappened() {
        assertEquals(0, w.enforcement.destructive());
        assertFalse(w.feed.denied(SignalFeed.Kind.SUBJECT, "alice", w.now()));
        assertEquals(0, w.audited("RESPONSE_ACTION"));
    }

    @Test
    void aForgedVerdictDoesNothing() {
        String id = honeytokenOnAlice();
        Verdict real = w.verdict("ana", id, TRUE_POSITIVE);
        // signed by ben's key but naming ana; ana's key over another outcome; garbage signature
        Verdict benAsAna = new Verdict(id, "ana", TRUE_POSITIVE, new SignatureProof("soc-ben", w.now(),
                Ed25519.sign(SimOrganisation.ANALYST_BEN.getPrivate(),
                        SignedMessages.socVerdict(id, "ana", "TRUE_POSITIVE", w.now()))));
        Verdict otherOutcome = new Verdict(id, "ana", TRUE_POSITIVE, w.verdict("ana", id, BENIGN).proof());
        Verdict junk = new Verdict(id, "ana", TRUE_POSITIVE, new SignatureProof("soc-ana", w.now(), "AAAA"));
        Verdict unknownKey = new Verdict(id, "ana", TRUE_POSITIVE, new SignatureProof("soc-mallory", w.now(),
                real.proof().signature()));
        for (Verdict v : List.of(benAsAna, otherOutcome, junk, unknownKey)) {
            assertEquals(Playbooks.Status.REFUSED, w.playbooks.handle(v).status());
        }
        nothingHappened();
        assertEquals(4, w.playbooks.refusedVerdicts());
        assertEquals(4, w.audited("VERDICT_REFUSED"));
        // the forgeries did not burn the real verdict
        assertEquals(Playbooks.Status.APPLIED, w.playbooks.handle(real).status());
    }

    @Test
    void aVerdictSignedWithAKeyOfAnotherPurposeDoesNotCount() {
        String id = honeytokenOnAlice();
        Verdict v = new Verdict(id, "ana", TRUE_POSITIVE, new SignatureProof("idp-ana", w.now(),
                Ed25519.sign(ResponseWorld.ANA_IDP.getPrivate(), SignedMessages.socVerdict(id, "ana", "TRUE_POSITIVE",
                        w.now()))));
        Playbooks.Result r = w.playbooks.handle(v);
        assertEquals(Playbooks.Status.REFUSED, r.status());
        assertTrue(r.message().contains("IDENTITY_PROVIDER"), r.message());
        nothingHappened();
    }

    @Test
    void aReplayedVerdictCountsOnce() {
        String id = honeytokenOnAlice();
        Verdict v = w.verdict("ana", id, FALSE_POSITIVE);
        assertEquals(Playbooks.Status.CLOSED, w.playbooks.handle(v).status());
        String again = w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("carol"));
        Verdict tp = w.verdict("ana", again, TRUE_POSITIVE);
        assertEquals(Playbooks.Status.APPLIED, w.playbooks.handle(tp).status());
        w.later(Duration.ofMinutes(1));
        assertEquals(Playbooks.Status.REFUSED, w.playbooks.handle(v).status());
        Playbooks.Result replay = w.playbooks.handle(tp);
        assertEquals(Playbooks.Status.REFUSED, replay.status());
        assertTrue(replay.message().contains("already used"), replay.message());
        assertEquals(1, w.enforcement.subjects.get(), "carol was revoked once, not once per replay");
    }

    @Test
    void staleAndFutureVerdictsAreRefused() {
        String id = honeytokenOnAlice();
        Verdict stale = w.verdict("ana", id, TRUE_POSITIVE, w.now().minus(Verdict.MAX_AGE).minusSeconds(1));
        Verdict future = w.verdict("ana", id, TRUE_POSITIVE, w.now().plus(Duration.ofMinutes(10)));
        assertEquals(Playbooks.Status.REFUSED, w.playbooks.handle(stale).status());
        assertEquals(Playbooks.Status.REFUSED, w.playbooks.handle(future).status());
        nothingHappened();
    }

    @Test
    void aVerdictOnAnAlertNoCaseHoldsIsRefused() {
        Playbooks.Result r = w.decide("ana", "al-invented-1", TRUE_POSITIVE);
        assertEquals(Playbooks.Status.REFUSED, r.status());
        assertTrue(r.caseId().isEmpty());
        nothingHappened();
    }

    @Test
    void anAnalystCannotDecideACaseAboutThemselves() {
        String id = w.raise("mfa-fatigue", Severity.HIGH, Entity.subject("ana"));
        for (Verdict.Outcome o : Verdict.Outcome.values()) {
            Playbooks.Result r = w.playbooks.handle(w.verdict("ana", id, o, w.now().minusSeconds(o.ordinal())));
            assertEquals(Playbooks.Status.REFUSED, r.status());
            assertTrue(r.message().contains("themselves"));
        }
        assertEquals(Case.State.OPEN, w.book.caseOf(id).orElseThrow().state());
    }

    @Test
    void anAlertFloodCannotDenyTheWholeCompany() {
        ResponseWorld small = new ResponseWorld(ResponseSettings.defaults().withLimits(5, 3, 10_000, 100));
        int applied = 0;
        for (int i = 0; i < 40; i++) {
            String id = small.raise("break-glass-used", Severity.HIGH, Entity.subject("user-" + i));
            String analyst = i % 2 == 0 ? "ben" : "cleo";
            if (small.decide(analyst, id, TRUE_POSITIVE).status() == Playbooks.Status.APPLIED) {
                applied++;
            }
            small.later(Duration.ofSeconds(1));
        }
        // each play is a revoke and a deny: 5 destructive actions an hour in all, 3 per analyst
        assertEquals(5, small.enforcement.destructive() + small.audited("SIGNAL_DENY"));
        assertTrue(applied <= 3, "applied " + applied);
        assertTrue(small.playbooks.heldBack() > 0);
        small.later(Duration.ofHours(1));
        String later = small.raise("break-glass-used", Severity.HIGH, Entity.subject("user-late"));
        assertEquals(Playbooks.Status.APPLIED, small.decide("ben", later, TRUE_POSITIVE).status(),
                "the limit is per hour, not for good");
    }

    @Test
    void junkVerdictsInAnAnalystsNameDoNotUseUpTheirQuota() {
        ResponseWorld small = new ResponseWorld(ResponseSettings.defaults().withLimits(5, 2, 10_000, 100));
        String id = small.raise("break-glass-used", Severity.HIGH, Entity.subject("dave"));
        for (int i = 0; i < 50; i++) {
            small.playbooks.handle(new Verdict(id, "ben", TRUE_POSITIVE,
                    new SignatureProof("soc-ben", small.now(), "AAAA" + i)));
        }
        assertEquals(20, small.audited("VERDICT_REFUSED"), "refusals are audited, throttled");
        assertEquals(Playbooks.Status.APPLIED, small.decide("ben", id, TRUE_POSITIVE).status());
    }

    @Test
    void noAuditNoAction() {
        String id = honeytokenOnAlice();
        Alert later = w.alert("deny-storm-ip", Severity.LOW, Entity.ip("192.0.2.9"));
        w.auditDown.set(true);
        assertEquals(Playbooks.Status.REFUSED, w.decide("ana", id, TRUE_POSITIVE).status());
        assertFalse(w.book.raise(later), "the case book needs the trail too");
        w.auditDown.set(false);
        nothingHappened();
        assertTrue(w.book.caseOf(later.id()).isEmpty());
    }

    @Test
    void anActionThatCannotBeAuditedIsNotTaken() {
        String id = honeytokenOnAlice();
        int[] revokes = {0};
        Playbooks pb = w.playbooks(b -> b.enforcement(new Enforcement() {
            @Override
            public int revokeSession(String s, String a, String r) {
                return 0;
            }

            @Override
            public int revokeSubject(String s, String a, String r) {
                revokes[0]++;
                w.auditDown.set(true);     // the trail fails right after the first action
                return 0;
            }

            @Override
            public int revokeDevice(String s, String a, String r) {
                return 0;
            }

            @Override
            public Set<String> rolesOf(String s, java.time.Instant n) {
                return Set.of();
            }
        }));
        Playbooks.Result r = pb.handle(w.verdict("ana", id, TRUE_POSITIVE));
        w.auditDown.set(false);
        assertEquals(Playbooks.Status.PARTIAL, r.status());
        assertEquals(1, revokes[0]);
        assertFalse(w.feed.denied(SignalFeed.Kind.SUBJECT, "alice", w.now()), "the deny was never audited, so never set");
        assertEquals(Case.State.OPEN, w.book.caseOf(id).orElseThrow().state(), "nor was the state change");
    }

    @Test
    void enforcementDownIsReportedAndCanBeRetried() {
        String id = honeytokenOnAlice();
        w.enforcement.down.set(true);
        Playbooks.Result r = w.decide("ana", id, TRUE_POSITIVE);
        assertEquals(Playbooks.Status.PARTIAL, r.status());
        assertEquals(Case.State.TRIAGED, w.book.caseOf(id).orElseThrow().state());
        w.enforcement.down.set(false);
        w.later(Duration.ofSeconds(5));
        Playbooks.Result retry = w.decide("ana", id, TRUE_POSITIVE);
        assertEquals(Playbooks.Status.APPLIED, retry.status());
        assertEquals(5, retry.actions());
        assertTrue(w.feed.denied(SignalFeed.Kind.SUBJECT, "alice", w.now()));
    }

    @Test
    void whenTheDirectoryCannotTellWhoIsPrivilegedTwoAnalystsAreNeeded() {
        w.enforcement.directoryDown.set(true);
        String id = w.raise("break-glass-used", Severity.HIGH, Entity.subject("carol"));
        assertEquals(Playbooks.Status.AWAITING_SECOND_ANALYST, w.decide("ben", id, TRUE_POSITIVE).status());
        assertEquals(0, w.enforcement.destructive());
        assertEquals(Playbooks.Status.APPLIED, w.decide("cleo", id, TRUE_POSITIVE).status());
        assertEquals(1, w.enforcement.subjects.get());
    }

    @Test
    void aBenignVerdictCannotQuietlyKeepActionsInForce() {
        String id = w.raise("mfa-fatigue", Severity.HIGH, Entity.subject("root"));
        assertEquals(Playbooks.Status.AWAITING_SECOND_ANALYST, w.decide("ben", id, TRUE_POSITIVE).status());
        assertTrue(w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "root", w.now()) > 0, "the watch applies at once");
        Playbooks.Result benign = w.decide("cleo", id, BENIGN);
        assertEquals(Playbooks.Status.REFUSED, benign.status(), benign.message());
        assertEquals(Playbooks.Status.UNDONE, w.decide("cleo", id, FALSE_POSITIVE).status());
        assertEquals(0, w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "root", w.now()));
        assertEquals(0, w.enforcement.destructive());
    }
}

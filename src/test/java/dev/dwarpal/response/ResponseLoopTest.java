package dev.dwarpal.response;

import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.session.SessionGrant;
import dev.dwarpal.session.SessionResult;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static dev.dwarpal.soc.Verdict.Outcome.BENIGN;
import static dev.dwarpal.soc.Verdict.Outcome.FALSE_POSITIVE;
import static dev.dwarpal.soc.Verdict.Outcome.TRUE_POSITIVE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 5 part B: an alert becomes a case, an analyst decides, and the decision changes what the engine does. */
class ResponseLoopTest {

    private final ResponseWorld w = new ResponseWorld();

    @Test
    void alertsAreGroupedIntoCasesByThePersonTheyAreAbout() {
        String a1 = w.raise("deny-storm-ip", Severity.LOW, Entity.ip("192.0.2.7"), Entity.subject("carol"));
        String a2 = w.raise("mfa-fatigue", Severity.HIGH, Entity.subject("carol"));
        String a3 = w.raise("deny-storm-ip", Severity.MEDIUM, Entity.ip("192.0.2.8"));
        Case c = w.book.caseOf(a1).orElseThrow();
        assertEquals(c.id(), w.book.caseOf(a2).orElseThrow().id());
        assertEquals(Entity.subject("carol"), c.key());
        assertEquals(Severity.HIGH, w.book.caseOf(a1).orElseThrow().severity(), "a case is as severe as its worst alert");
        assertEquals(2, w.book.get(c.id()).orElseThrow().alerts().size());
        assertTrue(c.entities().contains(Entity.ip("192.0.2.7")));
        assertEquals(Entity.ip("192.0.2.8"), w.book.caseOf(a3).orElseThrow().key());
        assertEquals(2, w.book.unresolved().size());
        assertFalse(w.book.raise(w.book.alert(a1).orElseThrow()), "an alert id is accepted once");
        assertEquals(2, w.audited("CASE_OPENED"));
        assertEquals(1, w.audited("CASE_ALERT"));
        assertTrue(w.book.get("case-404").isEmpty());
        assertTrue(w.book.alert("al-none").isEmpty());
    }

    @Test
    void aTruePositiveRevokesDeniesAndWatchesAndTheEngineSeesIt() {
        SessionGrant g = ResponseWorld.grant(w.aliceLogsIn());
        assertEquals(Outcome.ALLOW, w.aliceAsks().outcome());
        assertEquals(1, w.pa.activeSessions());
        String id = w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("alice"), Entity.device("laptop-alice"),
                Entity.ip("203.0.113.10"));
        Playbooks.Result r = w.decide("ana", id, TRUE_POSITIVE);
        assertEquals(Playbooks.Status.APPLIED, r.status(), r.message());
        assertEquals(5, r.actions());
        assertEquals(0, w.pa.activeSessions(), "alice's session ended");
        assertEquals(List.of("subject:alice", "device:laptop-alice"), w.enforcement.revoked);
        assertEquals(Outcome.DENY, w.aliceAsks().outcome());
        assertTrue(w.aliceLogsIn().grant().isEmpty(), "and she cannot open a new one while denied");
        Case c = w.book.caseOf(id).orElseThrow();
        assertEquals(Case.State.CLOSED, c.state());
        assertTrue(c.holdsActions());
        // every action is audited with the case and the analyst
        List<AuditEvent> actions = w.records("RESPONSE_ACTION").stream().map(AuditEvent::of).toList();
        assertEquals(5, actions.size());
        for (AuditEvent e : actions) {
            assertEquals("ana", e.actor());
            assertEquals(c.id(), e.field("case").orElseThrow());
            assertEquals(id, e.field("alert").orElseThrow());
        }
        assertTrue(g.sessionId().length() > 0);
    }

    @Test
    void aDenyEndsOnTimeAndNeverOutlastsTheMaximum() {
        String id = w.raise("deny-storm-ip", Severity.MEDIUM, Entity.ip("192.0.2.66"), Entity.subject("carol"));
        assertEquals(Playbooks.Status.APPLIED, w.decide("ben", id, TRUE_POSITIVE).status());
        assertTrue(w.feed.denied(SignalFeed.Kind.IP, "192.0.2.66", w.now()));
        w.later(Duration.ofHours(4).minusSeconds(1));
        assertTrue(w.feed.denied(SignalFeed.Kind.IP, "192.0.2.66", w.now()));
        w.later(Duration.ofSeconds(1));
        assertFalse(w.feed.denied(SignalFeed.Kind.IP, "192.0.2.66", w.now()), "four hours, to the second");
        assertThrows(IllegalArgumentException.class, () -> new Play.Deny(Entity.Kind.SUBJECT, Duration.ofDays(8)));
        assertThrows(IllegalArgumentException.class, () -> new Play.Deny(Entity.Kind.SUBJECT, Duration.ZERO));
        ResponseSettings oneDay = new ResponseSettings(Duration.ofDays(1), 20, 10, Duration.ofHours(1), Set.of("admin"),
                Set.of(), Set.of(), 100, 10);
        assertThrows(IllegalArgumentException.class, () -> Playbooks.builder(w.audit, w.ledger).settings(oneDay).cases(w.book)
                .verdicts(w.gate).enforcement(w.enforcement).clock(w.clock)
                .play("x", Play.of(new Play.Deny(Entity.Kind.SUBJECT, Duration.ofDays(2)))).build(),
                "a play longer than the settings allow is refused at start-up, not cut short silently");
    }

    @Test
    void aWatchDecaysWithItsHalfLife() {
        String id = w.raise("pam-refused", Severity.LOW, Entity.subject("carol"));
        assertEquals(Playbooks.Status.APPLIED, w.decide("ben", id, TRUE_POSITIVE).status());
        double w0 = w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "carol", w.now());
        assertEquals(Math.log(10), w0, 1e-9);
        w.later(Duration.ofDays(1));
        assertEquals(w0 / 2, w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "carol", w.now()), 1e-9);
        w.later(Duration.ofDays(2));
        assertEquals(w0 / 8, w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "carol", w.now()), 1e-9);
        assertEquals(w0 / 8, w.ledger.weightOf("case-1", SignalFeed.Kind.SUBJECT, "carol"), 1e-9);
    }

    @Test
    void aFalsePositiveLiftsWhatThePlaybookDid() {
        String id = w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("alice"), Entity.device("laptop-alice"),
                Entity.ip("203.0.113.10"));
        w.decide("ana", id, TRUE_POSITIVE);
        assertEquals(Outcome.DENY, w.aliceAsks().outcome());
        w.later(Duration.ofMinutes(20));
        Playbooks.Result r = w.decide("ben", id, FALSE_POSITIVE);
        assertEquals(Playbooks.Status.UNDONE, r.status(), r.message());
        assertEquals(3, r.actions(), "three denies lifted; revocations cannot be undone");
        assertEquals(Outcome.ALLOW, w.aliceAsks().outcome());
        assertEquals(SessionResult.Status.OPENED, w.aliceLogsIn().status(), "alice simply logs in again");
        assertFalse(w.book.caseOf(id).orElseThrow().holdsActions());
        assertEquals(3, w.audited("RESPONSE_UNDONE"));
        assertEquals(1, w.audited("CASE_RELEASED"));
        assertEquals(Playbooks.Status.REFUSED, w.decide("cleo", id, FALSE_POSITIVE).status(), "nothing left to lift");
    }

    @Test
    void benignAndFalsePositiveWithoutActionsJustClose() {
        String a = w.raise("deny-storm-ip", Severity.LOW, Entity.ip("192.0.2.1"));
        String b = w.raise("deny-storm-ip", Severity.LOW, Entity.ip("192.0.2.2"));
        assertEquals(Playbooks.Status.CLOSED, w.decide("ana", a, BENIGN).status());
        assertEquals(Playbooks.Status.CLOSED, w.decide("ana", b, FALSE_POSITIVE).status());
        assertEquals(0, w.enforcement.destructive());
        assertTrue(w.book.unresolved().isEmpty());
        assertEquals(Playbooks.Status.REFUSED, w.decide("ben", a, BENIGN).status(), "already decided");
        assertEquals(Playbooks.Status.REFUSED, w.decide("ben", a, TRUE_POSITIVE).status(), "already decided");
        String c = w.raise("deny-storm-ip", Severity.LOW, Entity.ip("192.0.2.1"));
        assertTrue(!w.book.caseOf(c).orElseThrow().id().equals(w.book.caseOf(a).orElseThrow().id()),
                "a new alert after a closed case opens a new one");
    }

    @Test
    void privilegedAccountsNeedASecondAnalystForDestructiveSteps() {
        SessionGrant g = ResponseWorld.grant(w.logIn("root", "laptop-alice", dev.dwarpal.crypto.Ed25519.generateKeyPair()));
        String id = w.raise("mfa-fatigue", Severity.HIGH, Entity.subject("root"));
        Playbooks.Result first = w.decide("ana", id, TRUE_POSITIVE);
        assertEquals(Playbooks.Status.AWAITING_SECOND_ANALYST, first.status());
        assertEquals(1, first.actions(), "the watch applies at once");
        assertEquals(0, w.enforcement.destructive());
        assertEquals(1, w.playbooks.pending().size());
        assertEquals(Case.State.TRIAGED, w.book.caseOf(id).orElseThrow().state());
        assertEquals(Playbooks.Status.REFUSED, w.playbooks.handle(w.verdict("ana", id, TRUE_POSITIVE,
                w.now().plusSeconds(1))).status(), "not the same analyst twice");
        String other = w.raise("pam-refused", Severity.LOW, Entity.subject("root"));
        assertEquals(Playbooks.Status.REFUSED, w.decide("ben", other, TRUE_POSITIVE).status(),
                "the second analyst confirms the same alert");
        w.later(Duration.ofMinutes(5));
        Playbooks.Result second = w.decide("ben", id, TRUE_POSITIVE);
        assertEquals(Playbooks.Status.APPLIED, second.status(), second.message());
        assertEquals(1, w.enforcement.subjects.get());
        assertEquals(0, w.pa.activeSessions());
        assertTrue(w.playbooks.pending().isEmpty());
        assertTrue(g.sessionId().length() > 0);
        assertEquals("true", AuditEvent.of(w.records("RESPONSE_ACTION").getLast()).field("twoAnalysts").orElseThrow());
    }

    @Test
    void aFirstVerdictWaitsOnlySoLong() {
        String id = w.raise("break-glass-used", Severity.HIGH, Entity.subject("root"));
        assertEquals(Playbooks.Status.AWAITING_SECOND_ANALYST, w.decide("ana", id, TRUE_POSITIVE).status());
        w.later(Duration.ofHours(1));
        assertTrue(w.playbooks.pending().isEmpty());
        assertEquals(Playbooks.Status.AWAITING_SECOND_ANALYST, w.decide("ben", id, TRUE_POSITIVE).status(),
                "the old first verdict lapsed: ben's is a new first verdict");
        assertEquals(1, w.audited("RESPONSE_PENDING_LAPSED"));
        assertEquals(0, w.enforcement.destructive());
    }

    @Test
    void analystsWhoDisagreeCancelTheWaitingAction() {
        String id = w.raise("break-glass-used", Severity.HIGH, Entity.subject("root"));
        w.decide("ana", id, TRUE_POSITIVE);
        Playbooks.Result r = w.decide("ben", id, FALSE_POSITIVE);
        assertEquals(Playbooks.Status.CLOSED, r.status(), "nothing was done, so the false positive closes it");
        assertTrue(w.playbooks.pending().isEmpty());
        assertEquals(0, w.enforcement.destructive());
    }

    @Test
    void liftingWhatTwoAnalystsConfirmedNeedsTwoAnalysts() {
        String id = w.raise("break-glass-used", Severity.HIGH, Entity.subject("root"));
        w.decide("ana", id, TRUE_POSITIVE);
        w.decide("ben", id, TRUE_POSITIVE);
        assertTrue(w.feed.denied(SignalFeed.Kind.SUBJECT, "root", w.now()));
        Playbooks.Result one = w.decide("cleo", id, FALSE_POSITIVE);
        assertEquals(Playbooks.Status.AWAITING_SECOND_ANALYST, one.status());
        assertTrue(w.feed.denied(SignalFeed.Kind.SUBJECT, "root", w.now()), "one analyst cannot lift it");
        assertEquals(Playbooks.Status.REFUSED, w.playbooks.handle(w.verdict("cleo", id, FALSE_POSITIVE,
                w.now().plusSeconds(1))).status());
        Playbooks.Result disagree = w.playbooks.handle(w.verdict("ana", id, TRUE_POSITIVE, w.now().plusSeconds(2)));
        assertEquals(Playbooks.Status.REFUSED, disagree.status(), "a true positive cancels the waiting lift");
        assertEquals(1, w.audited("RESPONSE_PENDING_CANCELLED"));
        w.later(Duration.ofMinutes(1));
        w.decide("cleo", id, FALSE_POSITIVE);
        assertEquals(Playbooks.Status.UNDONE, w.decide("ana", id, FALSE_POSITIVE).status());
        assertFalse(w.feed.denied(SignalFeed.Kind.SUBJECT, "root", w.now()));
    }

    @Test
    void sharedAddressesNeedTwoAnalystsTooButOrdinaryOnesDoNot() {
        String id = w.raise("deny-storm-ip", Severity.MEDIUM, Entity.ip("198.51.100.1"), Entity.ip("192.0.2.99"));
        Playbooks.Result r = w.decide("ana", id, TRUE_POSITIVE);
        assertEquals(Playbooks.Status.AWAITING_SECOND_ANALYST, r.status());
        assertTrue(w.feed.denied(SignalFeed.Kind.IP, "192.0.2.99", w.now()));
        assertFalse(w.feed.denied(SignalFeed.Kind.IP, "198.51.100.1", w.now()), "the office egress waits");
        assertEquals(Playbooks.Status.APPLIED, w.decide("ben", id, TRUE_POSITIVE).status());
        assertTrue(w.feed.denied(SignalFeed.Kind.IP, "198.51.100.1", w.now()));
    }

    @Test
    void rulesWithoutAPlayOnlyWatch() {
        String id = w.raise("something-new", Severity.HIGH, Entity.subject("dave"), Entity.device("laptop-dave"));
        Playbooks.Result r = w.decide("ana", id, TRUE_POSITIVE);
        assertEquals(Playbooks.Status.APPLIED, r.status());
        assertEquals(1, r.actions());
        assertEquals(0, w.enforcement.destructive());
        assertEquals(Math.log(10), w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "dave", w.now()), 1e-9);
        String chain = w.raise("audit-chain-break", Severity.CRITICAL, new Entity(Entity.Kind.RESOURCE, "audit-trail"));
        assertEquals(0, w.decide("ana", chain, TRUE_POSITIVE).actions(), "an empty play does nothing");
        Playbooks custom = w.playbooks(b -> b.play("something-new", Play.of(new Play.Revoke(Entity.Kind.DEVICE)))
                .defaultPlay(Play.of()));
        String again = w.raise("something-new", Severity.HIGH, Entity.subject("erin"), Entity.device("laptop-erin"));
        assertEquals(Playbooks.Status.APPLIED, custom.handle(w.verdict("ana", again, TRUE_POSITIVE)).status());
        assertEquals(List.of("device:laptop-erin"), w.enforcement.revoked);
        assertEquals(14, Playbooks.referencePlays().size());
    }

    @Test
    void aStolenTokenPlayEndsTheSession() {
        SessionGrant g = ResponseWorld.grant(w.aliceLogsIn());
        String id = w.raise("stolen-token-revoked", Severity.HIGH, Entity.subject("alice"),
                new Entity(Entity.Kind.SESSION, g.sessionId()));
        assertEquals(Playbooks.Status.APPLIED, w.decide("ben", id, TRUE_POSITIVE).status());
        assertEquals(List.of("session:" + g.sessionId(), "subject:alice"), w.enforcement.revoked);
        assertEquals(0, w.pa.activeSessions());
    }

    @Test
    void theCaseBookIsBoundedAndForgetsOnlyWhatIsSafeToForget() {
        ResponseWorld small = new ResponseWorld(ResponseSettings.defaults().withLimits(20, 10, 3, 2));
        String a = small.raise("deny-storm-ip", Severity.LOW, Entity.ip("192.0.2.1"));
        small.raise("deny-storm-ip", Severity.LOW, Entity.ip("192.0.2.1"));
        assertFalse(small.book.raise(small.alert("deny-storm-ip", Severity.LOW, Entity.ip("192.0.2.1"))),
                "two alerts per case");
        String held = small.raise("pam-refused", Severity.LOW, Entity.subject("carol"));
        small.raise("deny-storm-ip", Severity.LOW, Entity.ip("192.0.2.3"));
        assertFalse(small.book.raise(small.alert("deny-storm-ip", Severity.LOW, Entity.ip("192.0.2.4"))),
                "full of open cases, and nothing less severe to drop");
        assertEquals(2, small.book.refused());
        small.decide("ana", a, BENIGN);
        small.decide("ana", held, TRUE_POSITIVE);
        assertTrue(small.book.caseOf(held).orElseThrow().holdsActions());
        assertTrue(small.book.raise(small.alert("deny-storm-ip", Severity.LOW, Entity.ip("192.0.2.4"))),
                "the benign case is forgotten to make room");
        assertTrue(small.book.caseOf(a).isEmpty());
        assertFalse(small.book.raise(small.alert("deny-storm-ip", Severity.LOW, Entity.ip("192.0.2.5"))),
                "a case whose actions are in force is never forgotten");
        assertTrue(small.book.caseOf(held).isPresent());
        assertEquals(3, small.book.size());
    }

    @Test
    void settingsAndPlaysAreChecked() {
        assertThrows(IllegalArgumentException.class, () -> new ResponseSettings(Duration.ofDays(8), 20, 10,
                Duration.ofHours(1), Set.of(), Set.of(), Set.of(), 10, 10));
        assertThrows(IllegalArgumentException.class, () -> new ResponseSettings(Duration.ofDays(1), 5, 10,
                Duration.ofHours(1), Set.of(), Set.of(), Set.of(), 10, 10));
        assertThrows(IllegalArgumentException.class, () -> new ResponseSettings(Duration.ofDays(1), 5, 1,
                Duration.ofSeconds(1), Set.of(), Set.of(), Set.of(), 10, 10));
        assertThrows(IllegalArgumentException.class, () -> new ResponseSettings(Duration.ofDays(1), 5, 1,
                Duration.ofHours(1), Set.of(), Set.of(), Set.of(), 0, 10));
        assertThrows(IllegalArgumentException.class, () -> new ResponseSettings(Duration.ofDays(1), 5, 1,
                Duration.ofHours(1), Set.of("bad role"), Set.of(), Set.of(), 1, 10));
        assertThrows(IllegalArgumentException.class, () -> new Play.Revoke(Entity.Kind.IP));
        assertThrows(IllegalArgumentException.class, () -> new Play.Deny(Entity.Kind.SESSION, Duration.ofHours(1)));
        assertThrows(IllegalArgumentException.class, () -> new Play.Watch(Entity.Kind.SUBJECT, 0, Duration.ofDays(1)));
        assertThrows(IllegalArgumentException.class, () -> new Play.Watch(Entity.Kind.SUBJECT, 8, Duration.ofDays(1)));
        assertThrows(IllegalArgumentException.class, () -> new Play.Watch(Entity.Kind.SUBJECT, 1, Duration.ofSeconds(5)));
        assertThrows(IllegalArgumentException.class, () -> new Play.Watch(Entity.Kind.RESOURCE, 1, Duration.ofDays(1)));
        assertThrows(IllegalArgumentException.class, () -> new Play(java.util.Collections.nCopies(17,
                new Play.Revoke(Entity.Kind.SUBJECT))));
        assertThrows(NullPointerException.class, () -> Playbooks.builder(w.audit, w.ledger).build());
        assertThrows(IllegalArgumentException.class, () -> Playbooks.builder(w.audit, w.ledger).play("bad rule", Play.of()));
        assertFalse(new Play.Watch(Entity.Kind.IP, 1, Duration.ofDays(1)).destructive());
        assertTrue(new Play.Revoke(Entity.Kind.SUBJECT).destructive());
        assertEquals(Map.of(), Map.copyOf(Map.of()));
        Alert a = w.alert("x", Severity.LOW, Entity.subject("carol"));
        assertTrue(a.id().startsWith("al-x-"));
    }
}

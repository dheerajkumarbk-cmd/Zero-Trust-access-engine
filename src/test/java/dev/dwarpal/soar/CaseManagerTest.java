package dev.dwarpal.soar;

import dev.dwarpal.response.Case;
import dev.dwarpal.response.CaseBook;
import dev.dwarpal.response.ResponseSettings;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Verdict;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Case management: abuse cases first (working your own case, reading others' cases), then the service levels. */
class CaseManagerTest {

    private final SoarWorld w = new SoarWorld();

    // ---- abuse ------------------------------------------------------------------------------------------------

    @Test
    void anAnalystCannotTakeSeeOrAnnotateACaseAboutThemselves() {
        String al = w.raise("impossible-travel-allow", Severity.HIGH, Entity.subject("ben"));
        String c = w.caseOf(al);
        assertFalse(w.cases.canSee(SoarWorld.BEN, c));
        assertEquals(CaseManager.Outcome.NOT_FOUND, w.cases.assign(c, SoarWorld.BEN, "ben"));
        assertEquals(CaseManager.Outcome.NOT_FOUND, w.cases.note(c, SoarWorld.BEN, "nothing to see here"));
        // a lead cannot hand it to them either
        assertEquals(CaseManager.Outcome.FORBIDDEN, w.cases.assign(c, SoarWorld.LEAD, "ben"));
        // and the playbooks refuse ben's verdict on it (part B)
        assertEquals(dev.dwarpal.response.Playbooks.Status.REFUSED,
                w.decide("ben", al, Verdict.Outcome.FALSE_POSITIVE).status());
    }

    @Test
    void casesAboutAnyAnalystAreForLeadsOnly() {
        String c = w.caseOf(w.raise("dlp-block-spike", Severity.MEDIUM, Entity.subject("ben")));
        assertFalse(w.cases.canSee(SoarWorld.ANA, c), "ana cannot read about her colleague");
        assertTrue(w.cases.canSee(SoarWorld.LEAD, c));
        String own = w.caseOf(w.raise("dlp-block-spike", Severity.MEDIUM, Entity.subject("cleo")));
        assertFalse(w.cases.canSee(SoarWorld.LEAD, own), "nor a lead about herself");
        assertTrue(w.cases.aboutAnalyst(Entity.subject("ana")));
        assertFalse(w.cases.aboutAnalyst(Entity.subject("alice")));
        assertFalse(w.cases.aboutAnalyst(Entity.device("ana")));
    }

    @Test
    void anAnalystOnlyTakesUnassignedCasesForThemselves() {
        String c = w.caseOf(w.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice")));
        assertEquals(CaseManager.Outcome.FORBIDDEN, w.cases.assign(c, SoarWorld.ANA, "ben"), "not for others");
        assertEquals(CaseManager.Outcome.OK, w.cases.assign(c, SoarWorld.ANA, "ana"));
        assertEquals(CaseManager.Outcome.OK, w.cases.assign(c, SoarWorld.ANA, "ana"), "idempotent");
        assertFalse(w.cases.canSee(SoarWorld.BEN, c), "ben no longer sees ana's case");
        assertEquals(CaseManager.Outcome.NOT_FOUND, w.cases.assign(c, SoarWorld.BEN, "ben"), "cannot take it");
        assertEquals(CaseManager.Outcome.OK, w.cases.assign(c, SoarWorld.LEAD, "ben"), "a lead can move it");
        assertEquals("ben", w.cases.view(c).orElseThrow().assignee().orElseThrow());
        assertEquals(CaseManager.Outcome.INVALID, w.cases.assign(c, SoarWorld.LEAD, "mallory"));
        assertEquals(CaseManager.Outcome.NOT_FOUND, w.cases.assign("case-999", SoarWorld.LEAD, "ana"));
        assertEquals(CaseManager.Outcome.NOT_FOUND, w.cases.assign(null, SoarWorld.LEAD, "ana"));
        // an impostor object with a known id but another role is not that analyst
        Analyst fakeLead = new Analyst("ana", Analyst.Role.LEAD);
        assertFalse(w.cases.canSee(fakeLead, c));
        assertEquals(2, w.audited("CASE_ASSIGNED"), "only real changes are audited (ana's, then cleo's)");
    }

    @Test
    void casesWaitingForASecondAnalystAreVisibleToEveryAnalyst() {
        String al = w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("ceo"));
        String c = w.caseOf(al);
        assertEquals(CaseManager.Outcome.OK, w.cases.assign(c, SoarWorld.ANA, "ana"));
        assertFalse(w.cases.canSee(SoarWorld.BEN, c));
        w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE);
        assertTrue(w.cases.canSee(SoarWorld.BEN, c), "ben is needed as the second analyst");
    }

    @Test
    void notesAreBoundedSanitisedAndAuditedByHash() {
        SoarWorld small = new SoarWorld(ResponseSettings.defaults(), CaseSettings.defaults().withLimits(2, 50, 10, 1));
        String c = small.caseOf(small.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice")));
        assertEquals(CaseManager.Outcome.INVALID, small.cases.note(c, SoarWorld.ANA, "   "));
        assertEquals(CaseManager.Outcome.INVALID, small.cases.note(c, SoarWorld.ANA, "x".repeat(51)), "refused, not cut");
        assertEquals(CaseManager.Outcome.OK, small.cases.note(c, SoarWorld.ANA, "line one\nFAKE: line two\u202e"));
        assertEquals(CaseManager.Outcome.OK, small.cases.note(c, SoarWorld.ANA, "second"));
        assertEquals(CaseManager.Outcome.CONFLICT, small.cases.note(c, SoarWorld.ANA, "third"));
        CaseView.Note n = small.cases.view(c).orElseThrow().notes().getFirst();
        assertFalse(n.text().contains("\n"));
        assertFalse(n.text().contains("\u202e"));
        String payload = small.records("CASE_NOTE").getFirst().payloadJson();
        assertTrue(payload.contains("sha256"));
        assertFalse(payload.contains("line one"), "the note text stays out of the trail");
    }

    @Test
    void noAuditNoChange() {
        String c = w.caseOf(w.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice")));
        w.auditDown.set(true);
        assertEquals(CaseManager.Outcome.UNAVAILABLE, w.cases.assign(c, SoarWorld.ANA, "ana"));
        assertEquals(CaseManager.Outcome.UNAVAILABLE, w.cases.note(c, SoarWorld.ANA, "hello"));
        w.auditDown.set(false);
        CaseView v = w.cases.view(c).orElseThrow();
        assertTrue(v.assignee().isEmpty());
        assertTrue(v.notes().isEmpty());
        assertTrue(w.cases.metrics().auditFailures() >= 2);
    }

    @Test
    void aClosedCaseCannotBeAssigned() {
        String al = w.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice"));
        w.decide("ana", al, Verdict.Outcome.BENIGN);
        assertEquals(Case.State.CLOSED, w.cases.view(w.caseOf(al)).orElseThrow().state());
        assertEquals(CaseManager.Outcome.CONFLICT, w.cases.assign(w.caseOf(al), SoarWorld.LEAD, "ana"));
    }

    // ---- ranking and service levels -------------------------------------------------------------------------

    @Test
    void casesTakeTheirAlertsPriorityAndADeadline() {
        String al = w.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice"));
        String c = w.caseOf(al);
        CaseView v = w.cases.view(c).orElseThrow();
        assertEquals(Priority.P3, v.priority());
        assertEquals(w.now().plus(Duration.ofHours(8)), v.deadline());
        w.later(Duration.ofMinutes(30));
        w.raise("mfa-fatigue", Severity.CRITICAL, Entity.subject("alice"));
        v = w.cases.view(c).orElseThrow();
        assertEquals(Priority.P1, v.priority(), "a more urgent alert raises the case");
        assertEquals(w.now().plus(Duration.ofMinutes(15)), v.deadline(), "and brings the deadline forward");
        w.raise("pam-refused", Severity.LOW, Entity.subject("alice"));
        assertEquals(Priority.P1, w.cases.view(c).orElseThrow().priority(), "never lowered");
        assertEquals(3, w.cases.view(c).orElseThrow().alerts().size());
        assertTrue(w.cases.view(c).orElseThrow().timeline().stream()
                .anyMatch(t -> t.kind() == CaseView.TimelineEntry.Kind.PRIORITY));
    }

    @Test
    void aMissedDeadlineIsShownAsBreachedEvenAfterALateResponse() {
        String c = w.caseOf(w.raise("mfa-fatigue", Severity.CRITICAL, Entity.subject("alice")));
        w.later(Duration.ofMinutes(16));
        assertTrue(w.cases.view(c).orElseThrow().breached());
        assertEquals(1, w.cases.metrics().breached());
        w.cases.assign(c, SoarWorld.ANA, "ana");
        assertTrue(w.cases.view(c).orElseThrow().breached(), "late is late");
        String ontime = w.caseOf(w.raise("mfa-fatigue", Severity.CRITICAL, Entity.subject("carol")));
        w.cases.note(ontime, SoarWorld.ANA, "looking");
        w.later(Duration.ofHours(1));
        assertFalse(w.cases.view(ontime).orElseThrow().breached());
    }

    @Test
    void whenTheRankerFailsTheAlertIsP2AndNotActionable() {
        w.ranker.down.set(true);
        String al = w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("alice"), Entity.device("laptop-alice"));
        assertEquals(Priority.P2, w.cases.view(w.caseOf(al)).orElseThrow().priority());
        assertFalse(w.cases.ranked(al).orElseThrow().actionable());
        w.ranker.down.set(false);
        w.ranker.lie = true;
        String other = w.raise("pam-refused", Severity.LOW, Entity.subject("carol"));
        assertFalse(w.cases.ranked(other).orElseThrow().actionable(), "an answer about another alert is not used");
        assertEquals(2, w.cases.metrics().rankerFailures());
        assertEquals(Soar.Mode.WATCH_ONLY, w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE).mode().orElseThrow());
    }

    @Test
    void casesAboutTheSameEntitiesAreLinked() {
        String a = w.caseOf(w.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice"), Entity.ip("203.0.113.5")));
        String b = w.caseOf(w.raise("deny-storm-ip", Severity.HIGH, Entity.subject("carol"), Entity.ip("203.0.113.5")));
        String c = w.caseOf(w.raise("pam-refused", Severity.MEDIUM, Entity.subject("dave")));
        assertEquals(List.of(a), w.cases.view(b).orElseThrow().links());
        assertEquals(List.of(b), w.cases.view(a).orElseThrow().links());
        assertTrue(w.cases.view(c).orElseThrow().links().isEmpty());
        assertEquals(1, w.audited("CASE_LINKED"));
    }

    @Test
    void theTimelineIsBoundedAndKeepsHowTheCaseOpened() {
        SoarWorld small = new SoarWorld(ResponseSettings.defaults(), CaseSettings.defaults().withLimits(100, 100, 10, 1));
        String c = small.caseOf(small.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice")));
        for (int i = 0; i < 20; i++) {
            small.cases.note(c, SoarWorld.ANA, "note " + i);
        }
        CaseView v = small.cases.view(c).orElseThrow();
        assertEquals(10, v.timeline().size());
        assertEquals(CaseView.TimelineEntry.Kind.OPENED, v.timeline().getFirst().kind());
        assertEquals(12, v.timelineDropped());
    }

    @Test
    void entriesFollowTheCaseBooksBound() {
        SoarWorld small = new SoarWorld(ResponseSettings.defaults().withLimits(20, 10, 2, 10), CaseSettings.defaults());
        String first = small.raise("pam-refused", Severity.LOW, Entity.subject("alice"));
        String c1 = small.caseOf(first);
        small.decide("ana", first, Verdict.Outcome.BENIGN);
        small.raise("pam-refused", Severity.LOW, Entity.subject("carol"));
        small.raise("pam-refused", Severity.LOW, Entity.subject("dave"));
        assertTrue(small.cases.view(c1).isEmpty(), "forgotten with the book's closed case");
        assertTrue(small.cases.ranked(first).isEmpty());
        assertEquals(2, small.cases.all().size());
        // a full book of live cases refuses: case management refuses too
        assertFalse(small.cases.raise(small.alert("pam-refused", Severity.LOW, Entity.subject("root"))));
        assertEquals(1, small.cases.metrics().refusedByBook());
    }

    @Test
    void metricsCountOpenCasesByPriority() {
        w.raise("mfa-fatigue", Severity.CRITICAL, Entity.subject("alice"));
        w.raise("pam-refused", Severity.MEDIUM, Entity.subject("carol"));
        String c = w.caseOf(w.raise("pam-refused", Severity.MEDIUM, Entity.subject("dave")));
        w.cases.assign(c, SoarWorld.ANA, "ana");
        CaseManager.Metrics m = w.cases.metrics();
        assertEquals(3, m.tracked());
        assertEquals(1, m.openByPriority().get(Priority.P1));
        assertEquals(2, m.openByPriority().get(Priority.P3));
        assertEquals(2, m.unassigned());
        assertEquals(Priority.P1, w.cases.all().getFirst().priority(), "most urgent first");
    }

    @Test
    void settingsAreChecked() {
        Map<Priority, Duration> sla = new EnumMap<>(Priority.class);
        for (Priority p : Priority.values()) {
            sla.put(p, Duration.ofHours(1));
        }
        assertEquals(Duration.ofHours(1), new CaseSettings(sla, 1, 1, 10, 0).sla(Priority.P4));
        sla.put(Priority.P4, Duration.ofMinutes(5));
        assertThrows(IllegalArgumentException.class, () -> new CaseSettings(sla, 1, 1, 10, 0), "P4 faster than P3");
        sla.put(Priority.P4, Duration.ofDays(31));
        assertThrows(IllegalArgumentException.class, () -> new CaseSettings(sla, 1, 1, 10, 0));
        sla.remove(Priority.P4);
        assertThrows(NullPointerException.class, () -> new CaseSettings(sla, 1, 1, 10, 0));
        assertThrows(IllegalArgumentException.class, () -> CaseSettings.defaults().withLimits(0, 1, 10, 0));
        assertThrows(IllegalArgumentException.class, () -> CaseSettings.defaults().withLimits(1, 1, 9, 0));
        assertThrows(IllegalArgumentException.class, () -> new CaseManager(w.book, w.ranker, w.audit, w.clock,
                CaseSettings.defaults(), List.of(SoarWorld.ANA, SoarWorld.ANA)));
        assertTrue(new CaseManager(new CaseBook(ResponseSettings.defaults(), w.audit, w.clock), w.ranker, w.audit,
                w.clock, CaseSettings.defaults(), Set.of()).all().isEmpty());
    }
}

package dev.dwarpal.soar;

import dev.dwarpal.decision.Outcome;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.response.Playbooks;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Verdict;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Red team of part F: attempts to turn the SOC against innocent people. Each weakness was first reproduced by the
 * probe below (it failed against the first version of the code), then fixed; the probe stays as a regression
 * test. Probes marked "held" passed from the start and are kept so the property cannot be lost.
 */
class SoarRedTeamTest {

    private final SoarWorld w = new SoarWorld();

    /** A forged firewall line naming the CEO and her laptop. */
    private Alert forgedSyslog() {
        Alert a = w.alert(SoarWorld.MIXED_RULE, Severity.CRITICAL, Entity.subject("ceo"), Entity.device("laptop-ceo"),
                Entity.ip("203.0.113.66"));
        w.ranker.collectedAlerts.add(a.id());
        assertTrue(w.cases.raise(a));
        return a;
    }

    /**
     * F-R1 (breach in the first version): watch-only mode kept the play's watches as written, so a forged syslog
     * line, confirmed by one analyst who believed it, put a x1000 watch on the CEO and the engine stopped letting
     * her in; a few forged lines a day would keep her out. Fix: on collected evidence a watch is at most x10 with a
     * half-life of at most one day, and each entity gets at most one such watch a day.
     */
    @Test
    void forgedSyslogLinesCannotLockTheCeoOutThroughWatches() {
        Alert first = forgedSyslog();
        Soar.Result r = w.decide("ana", first.id(), Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(Soar.Mode.WATCH_ONLY, r.mode().orElseThrow());
        assertTrue(w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "ceo", w.now()) <= Math.log(10) + 1e-9);
        assertNotEquals(Outcome.DENY, w.asks("ceo").outcome(), "one forged line must not lock the CEO out");
        w.later(Duration.ofMinutes(5));
        Alert second = forgedSyslog();
        Soar.Result again = w.decide("ben", second.id(), Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(Playbooks.Status.REFUSED, again.status(), "one collected-evidence watch per entity per day");
        assertTrue(w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "ceo", w.now()) <= Math.log(10) + 1e-9);
        assertFalse(w.feed.denied(SignalFeed.Kind.DEVICE, "laptop-ceo", w.now()));
        assertFalse(w.sensor.isolated("laptop-ceo"));
        // a day later one more is allowed
        w.later(Duration.ofDays(1));
        Alert third = forgedSyslog();
        assertEquals(Playbooks.Status.APPLIED, w.decide("ana", third.id(), Verdict.Outcome.TRUE_POSITIVE).status());
        // log weights fade by half a day: ln 10 + ln 10 / 2; one a day never sums past 2 ln 10 (x100)
        double now = w.feed.watchLogLr(SignalFeed.Kind.SUBJECT, "ceo", w.now());
        assertEquals(1.5 * Math.log(10), now, 0.01);
        assertTrue(now < 2 * Math.log(10));
    }

    /**
     * F-R2 (breach in the first version): part B asks for two analysts when an alert names a protected person, but
     * an alert can name only a device. One analyst confirmed a verified alert naming only the CEO's laptop and the
     * laptop was denied, its sessions ended and it was isolated. Fix: devices whose owner (asset catalogue) is a
     * protected person, or whose criticality is 5, need two analysts before the play runs at all.
     */
    @Test
    void oneAnalystCannotIsolateTheCeosLaptopThroughAnAlertNamingOnlyTheDevice() {
        String al = w.raise(SoarWorld.MIXED_RULE, Severity.CRITICAL, Entity.device("laptop-ceo"));
        Soar.Result first = w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(Playbooks.Status.AWAITING_SECOND_ANALYST, first.status());
        assertFalse(w.feed.denied(SignalFeed.Kind.DEVICE, "laptop-ceo", w.now()));
        assertFalse(w.sensor.isolated("laptop-ceo"));
        assertTrue(w.cases.view(w.caseOf(al)).orElseThrow().awaitingSecond());
        // the same analyst again does not count
        w.later(Duration.ofSeconds(1));
        assertEquals(Playbooks.Status.REFUSED, w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE).status());
        assertFalse(w.sensor.isolated("laptop-ceo"));
        // a second analyst who agrees lets it run
        Soar.Result second = w.decide("ben", al, Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(Playbooks.Status.APPLIED, second.status());
        assertTrue(w.sensor.isolated("laptop-ceo"));
    }

    @Test
    void aSecondAnalystWhoDisagreesCancelsTheProtectedDeviceWait() {
        String al = w.raise(SoarWorld.MIXED_RULE, Severity.CRITICAL, Entity.device("laptop-ceo"));
        w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE);
        Soar.Result no = w.decide("ben", al, Verdict.Outcome.FALSE_POSITIVE);
        assertNotEquals(Playbooks.Status.APPLIED, no.status());
        assertFalse(w.sensor.isolated("laptop-ceo"));
        assertFalse(w.cases.view(w.caseOf(al)).orElseThrow().awaitingSecond());
        // the wait also lapses on its own
        String other = w.raise(SoarWorld.MIXED_RULE, Severity.CRITICAL, Entity.device("laptop-ceo"));
        w.decide("ana", other, Verdict.Outcome.TRUE_POSITIVE);
        w.later(Duration.ofHours(2));
        assertEquals(Playbooks.Status.AWAITING_SECOND_ANALYST, w.decide("ben", other, Verdict.Outcome.TRUE_POSITIVE)
                .status(), "ben's verdict is now a first verdict");
        assertFalse(w.sensor.isolated("laptop-ceo"));
    }

    /** Held: a forged syslog line naming the CEO's laptop never isolates it (provenance rule). */
    @Test
    void aForgedSyslogLineNeverIsolatesTheCeosLaptop() {
        Alert forged = forgedSyslog();
        w.decide("ana", forged.id(), Verdict.Outcome.TRUE_POSITIVE);
        assertFalse(w.feed.denied(SignalFeed.Kind.DEVICE, "laptop-ceo", w.now()));
        assertFalse(w.feed.denied(SignalFeed.Kind.SUBJECT, "ceo", w.now()));
        assertFalse(w.sensor.isolated("laptop-ceo"));
        assertTrue(w.isolation.all().isEmpty());
    }

    /** Held: an analyst named in a case cannot decide it, assign it or write in it. */
    @Test
    void anAnalystCannotActOnTheirOwnCase() {
        String al = w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("ana"), Entity.device("laptop-alice"));
        assertEquals(Playbooks.Status.REFUSED, w.decide("ana", al, Verdict.Outcome.BENIGN).status());
        assertEquals(CaseManager.Outcome.NOT_FOUND, w.cases.assign(w.caseOf(al), SoarWorld.ANA, "ana"));
        assertEquals(CaseManager.Outcome.NOT_FOUND, w.cases.note(w.caseOf(al), SoarWorld.ANA, "false alarm"));
        assertFalse(w.cases.canSee(SoarWorld.ANA, w.caseOf(al)));
    }

    /** Held: a playbook file that removes the guard rails does not load, whoever signed it. */
    @Test
    void aPlaybookFileWithoutGuardRailsDoesNotLoad() {
        String noRails = SoarWorld.TEST_PLAYBOOKS
                .replace("  - rule: fw-port-scan\n    steps:\n      - watch: {target: ip, ratio: 10, halfLife: P1D}",
                        "  - rule: fw-port-scan\n    steps:\n      - isolate: device\n      - revoke: subject")
                .replace("  - rule: deny-storm-subject\n    steps:\n      - deny: {target: ip, for: PT4H}",
                        "  - rule: deny-storm-subject\n    steps:\n      - deny: {target: subject, for: P7D}")
                .replace("default:\n  - watch: {target: subject, ratio: 10, halfLife: P1D}", "default:\n  - revoke: subject");
        assertNotEquals(SoarWorld.TEST_PLAYBOOKS, noRails);
        PlaybookCompiler.Compilation c = w.compiler(true).compile(noRails);
        assertFalse(c.accepted());
        assertEquals(3, c.findings().stream().filter(f -> f.severity() == PlaybookCompiler.Finding.Severity.ERROR).count(),
                c.findings().toString());
    }
}

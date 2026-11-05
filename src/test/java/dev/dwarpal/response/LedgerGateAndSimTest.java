package dev.dwarpal.response;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.pam.PamSettings;
import dev.dwarpal.pam.PrivilegedAccessManager;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Verdict;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The signal ledger's failure paths, the verdict gate's bounds, and the loop on the shared simulated organisation. */
class LedgerGateAndSimTest {

    private final SimOrganisation.SimClock clock = new SimOrganisation.SimClock();
    /** Writes left before the audit store fails; negative means never. */
    private final AtomicInteger writesLeft = new AtomicInteger(-1);
    private final InMemoryAuditSink sink = new InMemoryAuditSink();
    private final AuditLog audit = new AuditLog(ResponseWorld.newKey(), r -> {
        if (writesLeft.get() == 0) {
            throw new IllegalStateException("disk full");
        }
        writesLeft.decrementAndGet();
        sink.write(r);
    });
    private final SignalFeed feed = new SignalFeed(Set.of(), audit, clock);
    private final SignalLedger ledger = new SignalLedger(feed, clock);

    @Test
    void anInterruptedLiftIsRememberedAndReconciled() {
        assertTrue(ledger.deny("case-1", SignalFeed.Kind.SUBJECT, "carol", Duration.ofHours(10), "ana", "c1"));
        assertTrue(ledger.watch("case-2", SignalFeed.Kind.SUBJECT, "carol", Math.log(10), Duration.ofHours(1), "ben", "c2"));
        assertEquals(List.of("case-1", "case-2"), ledger.holders(SignalFeed.Kind.SUBJECT, "carol"));
        writesLeft.set(1);       // the clear is written, putting back case 1's deny is not
        assertFalse(ledger.lift("case-2", SignalFeed.Kind.SUBJECT, "carol", "cleo", "false positive"));
        assertEquals(1, ledger.unsettled());
        assertFalse(feed.denied(SignalFeed.Kind.SUBJECT, "carol", clock.instant()), "reported: less than it should be");
        writesLeft.set(-1);
        assertEquals(0, ledger.reconcile("soc-playbooks"));
        assertTrue(feed.denied(SignalFeed.Kind.SUBJECT, "carol", clock.instant()));
        assertEquals(0, feed.watchLogLr(SignalFeed.Kind.SUBJECT, "carol", clock.instant()));
        assertTrue(ledger.lift("case-9", SignalFeed.Kind.SUBJECT, "carol", "cleo", "nothing of case 9 here"));
        writesLeft.set(0);
        assertFalse(ledger.lift("case-1", SignalFeed.Kind.SUBJECT, "carol", "cleo", "audit down: nothing changes"));
        assertTrue(feed.denied(SignalFeed.Kind.SUBJECT, "carol", clock.instant()));
        assertFalse(ledger.deny("case-3", SignalFeed.Kind.IP, "192.0.2.1", Duration.ofHours(1), "ana", "x"));
        assertFalse(ledger.watch("case-3", SignalFeed.Kind.IP, "192.0.2.1", 1, Duration.ofHours(1), "ana", "x"));
    }

    @Test
    void aLongerDenyIsKeptAndTheLedgerForgetsWhatHasEnded() {
        ledger.deny("case-1", SignalFeed.Kind.DEVICE, "pc-1", Duration.ofHours(5), "ana", "x");
        ledger.deny("case-1", SignalFeed.Kind.DEVICE, "pc-1", Duration.ofHours(1), "ana", "x");
        ledger.watch("case-1", SignalFeed.Kind.DEVICE, "pc-1", 1, Duration.ofMinutes(10), "ana", "x");
        ledger.deny("case-1", SignalFeed.Kind.DEVICE, "pc-1", Duration.ofHours(2), "ana", "x");
        ledger.watch(SignalLedger.DLP, SignalFeed.Kind.SUBJECT, "dave", 1, Duration.ofMinutes(10), "dlp", "x");
        assertEquals(2, ledger.size());
        clock.set(clock.instant().plus(Duration.ofHours(4)));
        assertEquals(1, ledger.purge(), "dave's watch faded");
        assertEquals(List.of("case-1"), ledger.holders(SignalFeed.Kind.DEVICE, "pc-1"), "the 5 h deny is still on");
        clock.set(clock.instant().plus(Duration.ofHours(2)));
        assertEquals(1, ledger.purge());
        assertEquals(0, ledger.size());
        assertTrue(ledger.holders(SignalFeed.Kind.DEVICE, "pc-1").isEmpty());
    }

    @Test
    void aFullReplayStoreRefusesRatherThanForgets() {
        ResponseWorld w = new ResponseWorld();
        VerdictGate tiny = new VerdictGate(w.keys, w.clock, 2);
        assertTrue(tiny.admit(w.verdict("ana", "al-1", Verdict.Outcome.BENIGN)).isEmpty());
        assertTrue(tiny.admit(w.verdict("ana", "al-2", Verdict.Outcome.BENIGN)).isEmpty());
        assertTrue(tiny.admit(w.verdict("ana", "al-3", Verdict.Outcome.BENIGN)).isPresent());
        w.later(Verdict.MAX_AGE.plus(Duration.ofMinutes(5)));
        assertTrue(tiny.admit(w.verdict("ana", "al-3", Verdict.Outcome.BENIGN)).isEmpty(), "space again once spent ones age out");
    }

    @Test
    void enforcementSeesDirectoryRolesAndEndsElevationWithTheSessions() {
        ResponseWorld w = new ResponseWorld();
        assertEquals(Set.of("admin", "engineer"), w.enforcement.rolesOf("root", w.now()));
        assertEquals(Set.of(), w.enforcement.rolesOf("nobody", w.now()));
        PrivilegedAccessManager pam = new PrivilegedAccessManager(w.keys, Map.of(), Map.of(), PamSettings.defaults(),
                w.audit, w.clock, s -> { });
        Enforcement e = Enforcement.of(w.pa, pam, w.directory);
        ResponseWorld.grant(w.aliceLogsIn());
        assertEquals(1, e.revokeSubject("alice", "ana", "case-1"));
        assertEquals(0, e.revokeDevice("laptop-alice", "ana", "case-1"));
        assertEquals(0, e.revokeSession("s-none", "ana", "case-1"));
    }

    /**
     * The loop on the shared simulated organisation (seed 7, 60 users; consistency with the threat model,
     * not real-world accuracy): a confirmed honeytoken alert denies the person on the engine's next
     * decision, and the false-positive verdict gives the engine's own answer back.
     */
    @Test
    void onTheSimulatedOrganisationAVerdictChangesTheEnginesNextDecisionAndIsUndone() {
        SimOrganisation org = SimOrganisation.create(7, 60);
        PolicyEngine engine = org.engine();
        List<SimOrganisation.Step> traffic = org.traffic();
        SimOrganisation.Labelled legit = traffic.stream()
                .filter(s -> s instanceof SimOrganisation.RequestStep).map(s -> ((SimOrganisation.RequestStep) s).labelled())
                .filter(l -> !l.scenario().attack()).findFirst().orElseThrow();
        Instant at = legit.request().timestamp();
        org.clock.set(at);
        Outcome before = engine.decide(legit.request(), org.signals.snapshot(at)).outcome();
        assertNotEquals(Outcome.DENY, before);

        ResponseSettings settings = ResponseSettings.defaults();
        CaseBook book = new CaseBook(settings, org.audit, org.clock);
        AtomicInteger revoked = new AtomicInteger();
        Playbooks pb = Playbooks.builder(org.audit, new SignalLedger(org.signals, org.clock)).settings(settings)
                .cases(book).verdicts(new VerdictGate(org.keys, org.clock))
                .clock(org.clock).enforcement(new Enforcement() {
                    @Override
                    public int revokeSession(String s, String a, String r) {
                        return revoked.incrementAndGet();
                    }

                    @Override
                    public int revokeSubject(String s, String a, String r) {
                        return revoked.incrementAndGet();
                    }

                    @Override
                    public int revokeDevice(String s, String a, String r) {
                        return revoked.incrementAndGet();
                    }

                    @Override
                    public Set<String> rolesOf(String s, Instant n) {
                        return org.directory.subject(s).map(x -> x.roles()).orElse(Set.of());
                    }
                }).build();
        String user = legit.userId();
        Alert alert = new Alert("al-honeytoken-touched-1", "honeytoken-touched", Severity.CRITICAL, at,
                List.of(Entity.subject(user)), List.of(org.audit.head().sequence() + 1), 1, "honeytoken used by " + user);
        assertTrue(book.raise(alert));
        assertEquals(Playbooks.Status.APPLIED,
                pb.handle(org.verdict("ana", alert.id(), Verdict.Outcome.TRUE_POSITIVE, at)).status());
        assertEquals(1, revoked.get());
        assertEquals(Outcome.DENY, engine.decide(legit.request(), org.signals.snapshot(at)).outcome());
        org.clock.set(at.plus(Duration.ofMinutes(10)));
        assertEquals(Playbooks.Status.UNDONE, pb.handle(org.verdict("ben", alert.id(), Verdict.Outcome.FALSE_POSITIVE,
                org.clock.instant())).status());
        assertEquals(before, engine.decide(legit.request(), org.signals.snapshot(org.clock.instant())).outcome());
    }
}

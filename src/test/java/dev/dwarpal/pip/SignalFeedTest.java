package dev.dwarpal.pip;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.sim.SimOrganisation;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static dev.dwarpal.pip.SignalFeed.Kind.DEVICE;
import static dev.dwarpal.pip.SignalFeed.Kind.IP;
import static dev.dwarpal.pip.SignalFeed.Kind.SUBJECT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 5 part 0: the signals the SOC controls are temporary, decaying, bounded and audited. */
class SignalFeedTest {

    private static final Instant T = SimOrganisation.DAY_ZERO;
    private final SimOrganisation.SimClock clock = new SimOrganisation.SimClock();
    private final InMemoryAuditSink sink = new InMemoryAuditSink();
    private final SignalFeed feed = new SignalFeed(Set.of("svc-backup-old"), log(sink), clock);

    private static AuditLog log(dev.dwarpal.audit.AuditSink sink) {
        try {
            return new AuditLog(KeyGenerator.getInstance("HmacSHA256").generateKey(), sink);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private long audited(String type) {
        return sink.snapshot().stream().map(AuditRecord::type).filter(type::equals).count();
    }

    private void at(Duration later) {
        clock.set(T.plus(later));
    }

    @Test
    void aDenyHoldsForItsDurationAndThenEndsOnItsOwn() {
        assertTrue(feed.deny(SUBJECT, "mallory", Duration.ofHours(2), "soc-ana", "case 12"));
        assertTrue(feed.deny(IP, "45.155.205.9", Duration.ofHours(1), "soc-ana", "case 12"));
        assertTrue(feed.deny(DEVICE, "pc-77", Duration.ofMinutes(30), "soc-ana", "case 12"));
        SignalSnapshot now = feed.snapshot(T);
        assertEquals(Set.of("mallory"), now.deniedSubjects());
        assertEquals(Set.of("45.155.205.9"), now.deniedIps());
        assertEquals(Set.of("pc-77"), now.deniedDevices());
        assertEquals(Set.of("svc-backup-old"), now.honeytokenIds());
        assertEquals(Set.of(), feed.snapshot(T.plus(Duration.ofMinutes(45))).deniedDevices(), "device deny over");
        assertEquals(Set.of(), feed.snapshot(T.plus(Duration.ofHours(3))).deniedSubjects());
        assertFalse(feed.denied(SUBJECT, "mallory", T.plus(Duration.ofHours(3))));
        assertEquals(3, audited("SIGNAL_DENY"));
    }

    @Test
    void aDenyIsNeverForeverAndOnlyEverExtendedHere() {
        for (Duration bad : List.of(Duration.ZERO, Duration.ofSeconds(-1), SignalFeed.MAX_DENY.plusSeconds(1))) {
            assertThrows(IllegalArgumentException.class, () -> feed.deny(SUBJECT, "a", bad, "soc", "r"), bad.toString());
        }
        assertTrue(feed.deny(SUBJECT, "a", Duration.ofHours(5), "soc", "r"));
        assertTrue(feed.deny(SUBJECT, "a", Duration.ofHours(1), "soc", "shorter"));
        assertTrue(feed.denied(SUBJECT, "a", T.plus(Duration.ofHours(4))), "a later, shorter deny does not shorten it");
        assertTrue(feed.clear(SUBJECT, "a", "soc", "false positive"));
        assertFalse(feed.denied(SUBJECT, "a", T));
        assertFalse(feed.clear(SUBJECT, "a", "soc", "again"), "nothing left to clear");
    }

    @Test
    void r1_aCallerCannotChooseTheTimeADenyIsMeasuredFrom() {
        // Before the fix deny() took the caller's "now": claiming to be five years ahead set a five-year
        // deny. The feed now measures every duration from its own clock.
        assertTrue(feed.deny(SUBJECT, "ceo", SignalFeed.MAX_DENY, "playbook", "worst case"));
        assertFalse(feed.denied(SUBJECT, "ceo", T.plus(SignalFeed.MAX_DENY).plusSeconds(1)),
                "no deny outlives MAX_DENY on the feed's clock");
    }

    @Test
    void r2_readingTheFutureNeitherDeletesNorHidesDenies() {
        // Before the fix a snapshot for a far-future time deleted every deny that would have ended by
        // then, and its cached result was then served for the present.
        assertTrue(feed.deny(SUBJECT, "mallory", Duration.ofHours(2), "soc", "case"));
        assertEquals(Set.of(), feed.snapshot(T.plus(Duration.ofDays(40))).deniedSubjects());
        assertEquals(Set.of("mallory"), feed.snapshot(T).deniedSubjects(), "still denied now");
        assertTrue(feed.denied(SUBJECT, "mallory", T.plusSeconds(1)));
        assertEquals(1, feed.size(), "a read deleted nothing");
    }

    @Test
    void aWatchHalvesEveryHalfLifeAndAddsUpToACap() {
        Duration h = Duration.ofDays(7);
        assertTrue(feed.watch(SUBJECT, "carol", Math.log(8), h, "response", "DLP block"));
        assertEquals(Math.log(8), feed.watchLogLr(SUBJECT, "carol", T), 1e-12);
        assertEquals(Math.log(8) / 2, feed.watchLogLr(SUBJECT, "carol", T.plus(h)), 1e-9);
        assertEquals(Math.log(8) / 4, feed.watchLogLr(SUBJECT, "carol", T.plus(h.multipliedBy(2))), 1e-9);
        assertEquals(Math.log(8), feed.watchLogLr(SUBJECT, "carol", T.minus(h)), 1e-12, "no growth backwards in time");

        at(h);  // a second watch a half-life later: half of the first, plus the new one
        assertTrue(feed.watch(SUBJECT, "carol", Math.log(8), h, "response", "DLP block again"));
        assertEquals(1.5 * Math.log(8), feed.watchLogLr(SUBJECT, "carol", T.plus(h)), 1e-9);
        for (int i = 0; i < 20; i++) {
            feed.watch(SUBJECT, "carol", Math.log(8), h, "response", "flood");
        }
        assertEquals(SignalFeed.MAX_WATCH_LOG_LR, feed.watchLogLr(SUBJECT, "carol", T.plus(h)), 1e-12, "capped");
        assertEquals(0, feed.watchLogLr(SUBJECT, "carol", T.plus(Duration.ofDays(365))), "faded away");
        assertEquals(0, feed.watchLogLr(IP, "carol", T), "kinds are separate");
        assertEquals(22, audited("SIGNAL_WATCH"));
    }

    @Test
    void watchesOnlyAddRiskWithinBounds() {
        Duration h = Duration.ofHours(1);
        for (double bad : new double[]{0, -1, Double.NaN, Double.POSITIVE_INFINITY, Math.log(1000) + 0.01}) {
            assertThrows(IllegalArgumentException.class, () -> feed.watch(SUBJECT, "a", bad, h, "soc", "r"),
                    "logLr " + bad);
        }
        assertThrows(IllegalArgumentException.class, () -> feed.watch(SUBJECT, "a", 1, Duration.ofSeconds(30), "soc", "r"));
        assertThrows(IllegalArgumentException.class, () -> feed.watch(SUBJECT, "a", 1, Duration.ofDays(91), "soc", "r"));
        assertThrows(IllegalArgumentException.class, () -> feed.deny(SUBJECT, "bob\nadmin", h, "soc", "r"),
                "ids are identifiers");
        assertThrows(IllegalArgumentException.class, () -> feed.deny(SUBJECT, "bob", h, "soc ana", "r"),
                "so are actors");
        assertThrows(IllegalArgumentException.class, () -> new SignalFeed(Set.of("bad id"), log(sink), clock));
        assertTrue(feed.watch(SUBJECT, "a", 1, h, "soc", "line one\nline two" + (char) 0x2028));
        String payload = sink.snapshot().getLast().payloadJson();
        assertFalse(payload.contains("\\n"), "the reason is sanitised before it is audited: " + payload);
    }

    @Test
    void noAuditNoChange() {
        SignalFeed blind = new SignalFeed(Set.of(), log(r -> {
            throw new IllegalStateException("disk full");
        }), clock);
        assertFalse(blind.deny(SUBJECT, "a", Duration.ofMinutes(1), "soc", "r"));
        assertFalse(blind.watch(SUBJECT, "a", 1, Duration.ofHours(1), "soc", "r"));
        assertEquals(0, blind.size());
        assertEquals(Set.of(), blind.snapshot(T).deniedSubjects());
    }

    @Test
    void theStoreIsBoundedAndRefusesRatherThanForgets() {
        for (int i = 0; i < SignalFeed.MAX_ENTRIES; i++) {
            assertTrue(feed.deny(IP, "10.0." + (i / 256) + "." + (i % 256), Duration.ofMinutes(10), "soc", "flood"));
        }
        assertFalse(feed.deny(SUBJECT, "one-more", Duration.ofMinutes(10), "soc", "r"));
        assertFalse(feed.watch(SUBJECT, "one-more", 1, Duration.ofHours(1), "soc", "r"));
        assertEquals(2, feed.refused());
        assertTrue(feed.deny(IP, "10.0.0.1", Duration.ofMinutes(20), "soc", "extend"),
                "an existing entry can still be extended");
        at(Duration.ofMinutes(11));
        assertTrue(feed.deny(SUBJECT, "later", Duration.ofHours(1), "soc", "r"),
                "once old entries end there is room again");
        assertTrue(feed.size() < SignalFeed.MAX_ENTRIES);
    }

    @Test
    void theSnapshotIsCachedUntilAChangeOrAnExpiry() {
        feed.deny(SUBJECT, "a", Duration.ofMinutes(10), "soc", "r");
        SignalSnapshot s1 = feed.snapshot(T);
        assertSame(s1, feed.snapshot(T.plusSeconds(5)), "no copying per decision");
        feed.deny(SUBJECT, "b", Duration.ofMinutes(20), "soc", "r");
        assertEquals(Set.of("a", "b"), feed.snapshot(T.plusSeconds(5)).deniedSubjects(), "a change is visible at once");
        assertEquals(Set.of("b"), feed.snapshot(T.plus(Duration.ofMinutes(10))).deniedSubjects(),
                "and so is an expiry");
        at(Duration.ofMinutes(30));
        assertEquals(2, feed.purge());
        assertEquals(0, feed.size());
    }

    @Test
    void theEngineObeysTheFeed() {
        SimOrganisation org = SimOrganisation.create(3, 6);
        PolicyEngine engine = org.engine();
        SimOrganisation.User u = org.users.getFirst();
        var normal = org.traffic().stream().filter(s -> s instanceof SimOrganisation.RequestStep r
                        && r.labelled().scenario() == SimOrganisation.Scenario.L1_NORMAL
                        && r.labelled().userId().equals(u.id()))
                .map(s -> ((SimOrganisation.RequestStep) s).labelled().request()).findFirst().orElseThrow();
        Instant at = normal.timestamp();
        org.clock.set(at);
        assertEquals(Outcome.ALLOW, engine.decide(normal, org.signals.snapshot(at)).outcome());
        assertTrue(org.signals.deny(SUBJECT, u.id(), Duration.ofHours(1), "soc-ana", "case 3"));
        assertEquals(Outcome.DENY, engine.decide(normal, org.signals.snapshot(at)).outcome(), "denied by the SOC");
        assertEquals(Outcome.ALLOW, engine.decide(normal, org.signals.snapshot(at.plus(Duration.ofHours(2)))).outcome(),
                "and back once the deny ends");
    }

    @Test
    void changesAndSnapshotsMayRunInParallel() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> fs = new java.util.ArrayList<>();
            for (int t = 0; t < 8; t++) {
                int n = t;
                fs.add(pool.submit(() -> {
                    for (int i = 0; i < 500; i++) {
                        feed.deny(SUBJECT, "s" + n + "-" + i, Duration.ofMinutes(1 + i % 30), "soc", "r");
                        feed.watch(IP, "10.1." + n + "." + (i % 250), 0.5, Duration.ofHours(1), "soc", "r");
                        feed.snapshot(T);
                    }
                }));
            }
            for (Future<?> f : fs) {
                f.get(60, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(4000, feed.snapshot(T).deniedSubjects().size());
        assertEquals(4000, audited("SIGNAL_DENY"));
    }
}

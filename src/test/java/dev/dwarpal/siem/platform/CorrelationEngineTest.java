package dev.dwarpal.siem.platform;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.ChainedEvent;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.Severity;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Part D: the correlation engine fires what the rules say, in event time, within its bounds. */
class CorrelationEngineTest {

    private static final Instant T = Fx.T0;

    private static String rule(String id, String severity, String body) {
        return "  - id: " + id + "\n    title: " + id + " title\n    severity: " + severity
                + "\n    techniques: [T1071]\n" + body;
    }

    private static RuleBook book(String... rules) {
        return RuleBook.load("version: 1\nrules:\n" + String.join("", rules), RuleBookTest.DATASETS);
    }

    /** Writes and reads: one trail, one engine reading it through a keyed cursor. */
    private static final class Rig {
        final Fx.Trail trail = new Fx.Trail();
        final Fx.Alerts alerts = new Fx.Alerts();
        final CorrelationEngine engine;
        final AuditCursor cursor;
        int n;

        Rig(RuleBook book) {
            this(book, CorrelationEngine.Settings.defaults());
        }

        Rig(RuleBook book, CorrelationEngine.Settings s) {
            engine = new CorrelationEngine(book, alerts, s);
            cursor = trail.cursor();
        }

        long add(String dataset, String action, SecurityEvent.Provenance p, Instant at, Instant recorded,
                 List<Entity> entities, Map<String, String> fields) {
            return trail.collected(new SecurityEvent(dataset + "-" + (++n), at, dataset, SecurityEvent.Category.SYSTEM,
                    action, SecurityEvent.EventOutcome.UNKNOWN, p, entities, fields), recorded);
        }

        long fw(Instant at, String device, String dst) {
            return add("firewall", "network.flow", SecurityEvent.Provenance.COLLECTED, at, at,
                    List.of(Entity.device(device), Entity.ip(dst)), Map.of("dst", dst));
        }

        long ep(Instant at, String device, String action, Map<String, String> f) {
            return add("endpoint", action, SecurityEvent.Provenance.SIGNED_SENSOR, at, at,
                    List.of(Entity.device(device), Entity.subject("u-" + device)), f);
        }

        CorrelationEngine.Report run() {
            return engine.run(cursor, 10_000);
        }
    }

    private static final String THRESHOLD = rule("th", "HIGH",
            "    threshold: {where: 'dataset = firewall', by: [device, dst], within: 10m, count: 5}\n");

    // ---- abuse first ----------------------------------------------------------------------------------------

    @Test
    void aFutureDatedEventCannotMoveTheClockAndCloseEveryonesWindows() {
        Rig r = new Rig(book(THRESHOLD));
        for (int i = 0; i < 4; i++) {
            r.fw(T.plusSeconds(60L * i), "d1", "1.1.1.1");
        }
        r.add("firewall", "network.flow", SecurityEvent.Provenance.COLLECTED, T.plus(Duration.ofDays(2)), T,
                List.of(Entity.device("d9"), Entity.ip("9.9.9.9")), Map.of("dst", "9.9.9.9"));
        r.fw(T.plusSeconds(300), "d1", "1.1.1.1");
        r.run();
        assertEquals(1, r.engine.ignoredAhead());
        assertEquals(1, r.alerts.of("th").size(), "the window survived");
    }

    @Test
    void backdatedEventsAreTooLateToCount() {
        Rig r = new Rig(book(THRESHOLD));
        r.fw(T.plus(Duration.ofHours(5)), "d0", "1.1.1.1");
        for (int i = 0; i < 6; i++) {
            Instant old = T.plusSeconds(10L * i);
            r.add("firewall", "network.flow", SecurityEvent.Provenance.COLLECTED, old, T.plus(Duration.ofHours(5)),
                    List.of(Entity.device("ceo-laptop"), Entity.ip("6.6.6.6")), Map.of("dst", "6.6.6.6"));
        }
        r.run();
        assertTrue(r.alerts.list.isEmpty());
        assertEquals(6, r.engine.late());
    }

    @Test
    void floodingAStateWithInventedKeysIsRefusedAndReportedNotForgottenSilently() {
        Rig r = new Rig(book(THRESHOLD), new CorrelationEngine.Settings(Duration.ofHours(2), Duration.ofMinutes(5),
                100, 50, 50));
        for (int i = 0; i < 150; i++) {
            r.fw(T.plusMillis(i), "d" + i, "1.1.1.1");
        }
        for (int i = 0; i < 5; i++) {
            r.fw(T.plusSeconds(1 + i), "d7", "1.1.1.1");
        }
        r.run();
        assertEquals(1, r.alerts.of(CorrelationEngine.STATE_FULL_RULE).size(), "one per rule per hour");
        assertEquals(1, r.alerts.of("th").size(), "a key that was live before the flood is still tracked");
        assertEquals(50, r.engine.statistics().get("th")[3]);
        assertEquals(100, r.engine.keys());
    }

    @Test
    void anAlertFloodIsCappedPerRuleAndReportedOnce() {
        Rig r = new Rig(book(rule("m", "LOW", "    match: 'dataset = firewall'\n")),
                new CorrelationEngine.Settings(Duration.ofHours(2), Duration.ofMinutes(5), 100, 50, 10));
        for (int i = 0; i < 40; i++) {
            r.fw(T.plusSeconds(i), "d1", "1.1.1.1");
        }
        r.run();
        assertEquals(10, r.alerts.of("m").size());
        List<Alert> flood = r.alerts.of(CorrelationEngine.FLOOD_RULE);
        assertEquals(1, flood.size());
        assertEquals(Severity.HIGH, flood.getFirst().severity());
        assertEquals(30, r.engine.statistics().get("m")[2], "the rest are counted as suppressed");
    }

    @Test
    void alertsTheSinkRefusesAreKeptAndOfferedAgainInOrder() {
        Rig r = new Rig(book(rule("m", "LOW", "    match: 'dataset = firewall'\n")));
        r.alerts.refusing = true;
        r.fw(T, "d1", "1.1.1.1");
        r.fw(T.plusSeconds(1), "d1", "1.1.1.1");
        r.run();
        assertTrue(r.alerts.list.isEmpty());
        r.alerts.refusing = false;
        r.fw(T.plusSeconds(2), "d1", "1.1.1.1");
        r.run();
        assertEquals(3, r.alerts.list.size());
        assertTrue(r.alerts.list.get(0).id().compareTo(r.alerts.list.get(1).id()) < 0);
        Rig t = new Rig(book(rule("m", "LOW", "    match: 'dataset = firewall'\n")));
        CorrelationEngine thrower = new CorrelationEngine(t.engine.book(), a -> {
            throw new IllegalStateException("down");
        }, new CorrelationEngine.Settings(Duration.ofHours(2), Duration.ofMinutes(5), 100, 50, 10_000));
        for (int i = 0; i < CorrelationEngine.MAX_PENDING_ALERTS + 5; i++) {
            t.fw(T.plusMillis(i), "d1", "1.1.1.1");
        }
        thrower.run(t.cursor, 10_000);
        assertEquals(CorrelationEngine.MAX_PENDING_ALERTS + 5, thrower.raised());
        assertEquals(5, thrower.lost(), "a sink that throws is a sink that refuses; past the pending limit, counted");
    }

    @Test
    void theEngineStopsForGoodAtABreakInTheChain() {
        Fx.Trail t = new Fx.Trail();
        Rig r = new Rig(book(rule("m", "LOW", "    match: 'dataset = firewall'\n")));
        r.fw(T, "d1", "1.1.1.1");
        AuditRecord good = r.trail.sink.snapshot().getFirst();
        InMemoryAuditSink forged = new InMemoryAuditSink();
        forged.write(good);
        AuditLog other = new AuditLog(t.key, new InMemoryAuditSink(), new AuditLog.Head(1, good.mac()));
        forged.write(other.append("ACCESS_DECISION", "pdp", T, Map.of("outcome", "DENY")));
        CorrelationEngine e = new CorrelationEngine(r.engine.book(), r.alerts, CorrelationEngine.Settings.defaults());
        CorrelationEngine.Report rep = e.run(AuditCursor.fromStart(forged, r.trail.key), 100);
        assertEquals(1, rep.read());
        assertTrue(rep.problem().orElseThrow().contains("break"));
        assertTrue(e.broken().isPresent());
        assertEquals(0, e.run(AuditCursor.fromStart(r.trail.sink, r.trail.key), 100).read(), "stopped for good");
    }

    @Test
    void collectedOnlyAlertsSaySoAndAreNotActionable() {
        Rig r = new Rig(book(THRESHOLD));
        for (int i = 0; i < 5; i++) {
            r.fw(T.plusSeconds(i), "ceo-laptop", "1.1.1.1");
        }
        r.run();
        Alert a = r.alerts.of("th").getFirst();
        assertTrue(a.summary().startsWith(CorrelationEngine.COLLECTED_ONLY), a.summary());
        assertFalse(r.engine.recent().getFirst().actionable());
        assertTrue(a.summary().contains("[MITRE T1071]"));
    }

    // ---- meaning --------------------------------------------------------------------------------------------

    @Test
    void thresholdsCountInEventTimeEvenWhenEventsArriveOutOfOrder() {
        Rig r = new Rig(book(THRESHOLD));
        Instant[] times = {T.plusSeconds(400), T.plusSeconds(100), T.plusSeconds(500), T.plusSeconds(200),
            T.plus(Duration.ofHours(1)), T.plusSeconds(300)};
        for (Instant at : times) {
            r.fw(at, "d1", "1.1.1.1");
        }
        r.fw(T, "d1", "2.2.2.2");
        r.run();
        List<Alert> a = r.alerts.of("th");
        assertEquals(1, a.size());
        assertEquals(5, a.getFirst().count());
        assertEquals(5, a.getFirst().evidence().size());
        assertEquals(List.of(Entity.device("d1"), Entity.ip("1.1.1.1")), a.getFirst().entities());
        assertTrue(a.getFirst().id().startsWith("al-th-"));
        for (int i = 0; i < 6; i++) {
            r.fw(T.plusSeconds(510 + i), "d1", "1.1.1.1");
        }
        r.run();
        assertEquals(1, r.alerts.of("th").size(), "quiet for one window after firing");
        assertTrue(r.engine.statistics().get("th")[2] > 0);
    }

    @Test
    void distinctAndSumThresholds() {
        Rig r = new Rig(book(
                rule("spray", "HIGH", "    threshold: {where: 'dataset = firewall', by: device, within: 1h, distinct: dst, count: 3}\n"),
                rule("vol", "MEDIUM", "    threshold: {where: 'dataset = cloud', by: subject, within: 1h, sum: bytes, atLeast: 1000}\n")));
        r.fw(T, "d1", "1.1.1.1");
        r.fw(T.plusSeconds(1), "d1", "1.1.1.1");
        r.fw(T.plusSeconds(2), "d1", "2.2.2.2");
        r.run();
        assertTrue(r.alerts.of("spray").isEmpty());
        r.fw(T.plusSeconds(3), "d1", "3.3.3.3");
        for (int i = 0; i < 3; i++) {
            r.add("cloud", "file.download", SecurityEvent.Provenance.COLLECTED, T.plusSeconds(i), T.plusSeconds(i),
                    List.of(Entity.subject("u9")), Map.of("bytes", i == 1 ? "lots" : "600"));
        }
        r.add("cloud", "file.download", SecurityEvent.Provenance.COLLECTED, T, T, List.of(Entity.device("x")),
                Map.of("bytes", "5000"));
        r.run();
        assertEquals(1, r.alerts.of("spray").size());
        assertTrue(r.alerts.of("spray").getFirst().summary().contains("3 distinct dst"));
        assertEquals(1, r.alerts.of("vol").size(), "600 + 600; 'lots' is not a number; no subject, no key");
        assertTrue(r.alerts.of("vol").getFirst().summary().contains("1200 bytes"));
    }

    private static final String SEQ = rule("seq", "HIGH", "    sequence:\n      by: device\n      within: 15m\n"
            + "      steps:\n        - where: 'action = process.start'\n        - where: 'action = network.connect'\n"
            + "          min: 2\n        - where: 'dataset = firewall'\n");

    @Test
    void sequencesNeedEveryStepInOrderWithinTheWindowAcrossSources() {
        Rig r = new Rig(book(SEQ));
        r.fw(T.minusSeconds(60), "d1", "6.6.6.6");                                // before the start: does not count
        r.ep(T, "d1", "process.start", Map.of());
        r.ep(T.plusSeconds(60), "d1", "network.connect", Map.of());
        r.fw(T.plusSeconds(90), "d1", "6.6.6.6");                                 // too early: one connect so far
        r.run();
        assertTrue(r.alerts.list.isEmpty());
        r.ep(T.plusSeconds(120), "d1", "network.connect", Map.of());
        r.ep(T.plusSeconds(60), "d2", "process.start", Map.of());                 // another device
        r.run();
        assertTrue(r.alerts.list.isEmpty());
        r.fw(T.plus(Duration.ofMinutes(16)), "d1", "6.6.6.6");                    // outside the window
        r.run();
        assertTrue(r.alerts.list.isEmpty());
        r.fw(T.plusSeconds(180), "d1", "6.6.6.6");                                // arrives late, fits
        r.run();
        Alert a = r.alerts.of("seq").getFirst();
        assertEquals(4, a.count());
        assertTrue(a.entities().contains(Entity.device("d1")));
        assertTrue(r.engine.recent().getFirst().actionable(), "signed endpoint evidence");
        assertFalse(a.summary().startsWith(CorrelationEngine.COLLECTED_ONLY));
    }

    @Test
    void absenceFiresOnceWhenAKeyGoesQuietAndAgainOnlyAfterItCameBack() {
        Rig r = new Rig(book(rule("hb", "MEDIUM", "    absence: {where: 'action = sensor.heartbeat', by: device, within: 30m}\n")),
                new CorrelationEngine.Settings(Duration.ZERO, Duration.ofMinutes(5), 100, 50, 50));
        r.ep(T, "d1", "sensor.heartbeat", Map.of());
        r.ep(T.plusSeconds(1), "d2", "sensor.heartbeat", Map.of());
        for (int m = 10; m <= 60; m += 10) {
            r.ep(T.plus(Duration.ofMinutes(m)), "d2", "sensor.heartbeat", Map.of());
        }
        r.run();
        assertEquals(1, r.alerts.of("hb").size());
        assertTrue(r.alerts.of("hb").getFirst().entities().contains(Entity.device("d1")));
        r.ep(T.plus(Duration.ofMinutes(70)), "d1", "sensor.heartbeat", Map.of());
        r.ep(T.plus(Duration.ofMinutes(75)), "d2", "sensor.heartbeat", Map.of());
        r.ep(T.plus(Duration.ofMinutes(105)), "d2", "sensor.heartbeat", Map.of());
        r.run();
        assertEquals(2, r.alerts.of("hb").size(), "d1 came back and went quiet again");
        assertTrue(r.engine.silentRules().isEmpty());
    }

    @Test
    void settingsAreBoundedAndCountersStartAtZero() {
        assertThrows(IllegalArgumentException.class, () -> new CorrelationEngine.Settings(Duration.ofDays(2),
                Duration.ZERO, 1, 2, 1));
        assertThrows(IllegalArgumentException.class, () -> new CorrelationEngine.Settings(Duration.ZERO,
                Duration.ofHours(2), 1, 2, 1));
        assertThrows(IllegalArgumentException.class, () -> new CorrelationEngine.Settings(Duration.ZERO,
                Duration.ZERO, 0, 2, 1));
        Rig r = new Rig(book(THRESHOLD));
        assertEquals(List.of("th"), r.engine.silentRules());
        assertEquals(0, r.engine.processed() + r.engine.late() + r.engine.malformed() + r.engine.lost()
                + r.engine.raised() + r.engine.ignoredAhead());
        r.trail.log.append("SECURITY_EVENT", "collector:firewall", T, Map.of("dataset", "firewall"));
        r.run();
        assertEquals(1, r.engine.malformed());
        r.engine.process(new ChainedEvent(99, T, Fx.event("x", T, "firewall", "a", SecurityEvent.Provenance.COLLECTED,
                List.of(), Map.of())));
        assertEquals(1, r.engine.processed());
    }
}

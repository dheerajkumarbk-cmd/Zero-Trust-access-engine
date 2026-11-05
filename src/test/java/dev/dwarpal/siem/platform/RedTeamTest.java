package dev.dwarpal.siem.platform;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.crypto.TrustedKey;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Part D red-team pass. Each test was first written as a working probe of an attack (and failed against the code
 * as it was), then the code was fixed; the probe stays as a regression test. Ids match docs/layer-5-2/part-d.md.
 */
class RedTeamTest {

    private static final Instant T = Fx.T0;

    private static RuleBook book(String body) {
        return RuleBook.load("version: 1\nrules:\n  - id: r\n    title: r\n    severity: HIGH\n    techniques: [T1071]\n"
                + body, RuleBookTest.DATASETS);
    }

    private static SecurityEvent only(CollectorBase c) {
        List<SecurityEvent> es = c.poll(10);
        assertEquals(1, es.size());
        return es.getFirst();
    }

    /** rD1: a syslog message overwrote the collector's own fields (host, verdict) with its own key=value pairs. */
    @Test
    void rD1_aSyslogMessageCannotOverwriteTheCollectorsOwnFields() {
        FirewallCollector c = new FirewallCollector("r", Map.of());
        assertFalse(c.offer("<134>1 2026-11-04T10:00:00Z fw01 dwfw 1 - - action=allow src=1.2.3.4 dst=5.6.7.8 "
                + "verdict=deny host=fw-trusted", T), "a line naming reserved fields is refused, not merged");
        SecurityEvent e = only(c);
        assertEquals("parse.failure", e.action());
        assertTrue(e.field("reason").orElseThrow().contains("reserved"));
    }

    /** rD2: a device line overwrote the batch number, and could pre-set the ingestion's own late flag. */
    @Test
    void rD2_anEndpointLineCannotForgeTheBatchNumberOrTheIngestionFlags() {
        KeyPair k = Ed25519.generateKeyPair();
        KeyRing ring = new KeyRing(List.of(new TrustedKey("agent-d", KeyPurpose.DEVICE_AGENT, "d", k.getPublic(),
                T.minus(Duration.ofDays(1)), T.plus(Duration.ofDays(1)))));
        EndpointCollector c = new EndpointCollector("r", ring);
        String body = "{\"ts\":\"" + T + "\",\"device\":\"d\",\"type\":\"file.read\",\"batch\":\"999\"}\n"
                + "{\"ts\":\"" + T + "\",\"device\":\"d\",\"type\":\"file.read\",\"ingest.late\":\"true\"}\n";
        Instant sealed = T.plusSeconds(60);
        String sig = Ed25519.sign(k.getPrivate(), SignedMessages.endpointTelemetry("d", 1, sealed, Digests.sha256Hex(body)));
        c.offer(new EndpointCollector.Batch("d", "agent-d", 1, sealed, body, sig), sealed);
        List<SecurityEvent> es = c.poll(10);
        assertEquals(2, es.size());
        for (SecurityEvent e : es) {
            assertEquals("parse.failure", e.action());
            assertTrue(e.field("reason").orElseThrow().contains("reserved"));
        }
        FirewallCollector fw = new FirewallCollector("r", Map.of());
        assertFalse(fw.offer("<134>1 2026-11-04T10:00:00Z fw01 dwfw 1 - - action=allow src=1.2.3.4 dst=5.6.7.8 "
                + "ingest.lagSeconds=0", T));
    }

    /** rD3: a sensor silenced for hours and then restarted was never reported when nothing else moved the clock. */
    @Test
    void rD3_aSensorThatWentQuietAndCameBackIsStillReported() {
        Fx.Trail t = new Fx.Trail();
        Fx.Alerts alerts = new Fx.Alerts();
        CorrelationEngine e = new CorrelationEngine(book(
                "    absence: {where: 'action = sensor.heartbeat', by: device, within: 30m}\n"), alerts,
                CorrelationEngine.Settings.defaults());
        for (int m = 0; m <= 20; m += 10) {
            t.collected(Fx.event("hb" + m, T.plus(Duration.ofMinutes(m)), "endpoint", "sensor.heartbeat",
                    SecurityEvent.Provenance.SIGNED_SENSOR, List.of(Entity.device("ceo-laptop")), Map.of()),
                    T.plus(Duration.ofMinutes(m)));
        }
        Instant back = T.plus(Duration.ofHours(5));
        t.collected(Fx.event("hb-back", back, "endpoint", "sensor.heartbeat", SecurityEvent.Provenance.SIGNED_SENSOR,
                List.of(Entity.device("ceo-laptop")), Map.of()), back);
        e.run(t.cursor(), 100);
        assertEquals(1, alerts.of("r").size(), "4h40m without a heartbeat, reported when it came back");
        assertTrue(alerts.of("r").getFirst().summary().contains("came back"));
    }

    /**
     * rD4: a threshold above the per-key state limit (count 5,000, a key holds 2,000) was accepted but could never
     * fire. Now counts fire (full state merges, rD5) and what still cannot fire is refused when the engine is built.
     */
    @Test
    void rD4_aRuleTheEngineCouldNeverFireIsRefusedWhenTheEngineIsBuilt() {
        Fx.Trail t = new Fx.Trail();
        Fx.Alerts alerts = new Fx.Alerts();
        CorrelationEngine counts = new CorrelationEngine(book(
                "    threshold: {where: 'dataset = firewall', by: device, within: 1h, count: 5000}\n"), alerts,
                CorrelationEngine.Settings.defaults());
        for (int i = 0; i < 5_000; i++) {
            Instant at = T.plusMillis(500L * i);
            t.collected(Fx.event("f" + i, at, "firewall", "network.flow", SecurityEvent.Provenance.COLLECTED,
                    List.of(Entity.device("d1")), Map.of()), at);
        }
        dev.dwarpal.audit.AuditCursor cursor = t.cursor();
        counts.run(cursor, 10_000);
        assertEquals(1, alerts.of("r").size(), "the count of 5,000 is reached");
        assertEquals(5_000, alerts.of("r").getFirst().count());

        RuleBook b = book("    threshold: {where: 'dataset = firewall', by: device, within: 1h, distinct: dst, count: 5000}\n");
        IllegalArgumentException x = assertThrows(IllegalArgumentException.class,
                () -> new CorrelationEngine(b, new Fx.Alerts(), CorrelationEngine.Settings.defaults()));
        assertTrue(x.getMessage().contains("can never fire"));
        RuleBook seq = book("    sequence: {by: device, within: 1h, steps: [{where: 'action = a', min: 60}, "
                + "{where: 'action = b'}]}\n");
        assertThrows(IllegalArgumentException.class, () -> new CorrelationEngine(seq, new Fx.Alerts(),
                new CorrelationEngine.Settings(Duration.ofHours(2), Duration.ofMinutes(5), 100, 50, 50)));
    }

    /** rD5: exfiltration spread over many small downloads stayed under a volume rule once the state was full. */
    @Test
    void rD5_manySmallEventsCannotHideAVolumeOverTheStateLimit() {
        Fx.Trail t = new Fx.Trail();
        Fx.Alerts alerts = new Fx.Alerts();
        CorrelationEngine e = new CorrelationEngine(book(
                "    threshold: {where: 'dataset = cloud', by: subject, within: 1h, sum: bytes, atLeast: 1000000000}\n"),
                alerts, CorrelationEngine.Settings.defaults());
        for (int i = 0; i < 3_000; i++) {
            Instant at = T.plusMillis(1_000L * i);
            t.collected(Fx.event("c" + i, at, "cloud", "file.download", SecurityEvent.Provenance.COLLECTED,
                    List.of(Entity.subject("u9")), Map.of("bytes", "400000")), at);
        }
        e.run(t.cursor(), 10_000);
        assertEquals(1, alerts.of("r").size(), "3,000 x 400 kB = 1.2 GB within the hour");
        Alert a = alerts.of("r").getFirst();
        assertTrue(a.count() >= 2_500, "the count covers every event, merged or not: " + a.count());
    }

    /** rD6: one busy key made every new event rescan every window: quadratic time, the engine fell behind. */
    @Test
    void rD6_oneBusyKeyCannotMakeTheEngineQuadratic() {
        Fx.Trail t = new Fx.Trail();
        Fx.Alerts alerts = new Fx.Alerts();
        CorrelationEngine e = new CorrelationEngine(book(
                "    threshold: {where: 'dataset = firewall', by: device, within: 1h, distinct: dst, count: 50}\n"),
                alerts, CorrelationEngine.Settings.defaults());
        for (int i = 0; i < 20_000; i++) {
            Instant at = T.plusMillis(100L * i);
            t.collected(Fx.event("f" + i, at, "firewall", "network.flow", SecurityEvent.Provenance.COLLECTED,
                    List.of(Entity.device("d1")), Map.of("dst", "1.1.1.1")), at);
        }
        dev.dwarpal.audit.AuditCursor cursor = t.cursor();
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
            e.run(cursor, 10_000);
            e.run(cursor, 10_000);
        });
        assertEquals(20_000, e.processed());
        assertTrue(alerts.list.isEmpty());
    }

    /** rD7: after a restart the collector forgot used batch numbers, so a captured batch was accepted again. */
    @Test
    void rD7_aBatchCapturedBeforeARestartIsRefusedAfterIt() {
        KeyPair k = Ed25519.generateKeyPair();
        KeyRing ring = new KeyRing(List.of(new TrustedKey("agent-d", KeyPurpose.DEVICE_AGENT, "d", k.getPublic(),
                T.minus(Duration.ofDays(1)), T.plus(Duration.ofDays(1)))));
        String body = "{\"ts\":\"" + T + "\",\"device\":\"d\",\"type\":\"file.read\"}\n";
        Instant sealed = T.plusSeconds(60);
        EndpointCollector.Batch b = new EndpointCollector.Batch("d", "agent-d", 7, sealed, body,
                Ed25519.sign(k.getPrivate(), SignedMessages.endpointTelemetry("d", 7, sealed, Digests.sha256Hex(body))));
        Fx.Trail t = new Fx.Trail();
        EndpointCollector before = new EndpointCollector("r1", ring);
        before.offer(b, sealed);
        Ingestor in = new Ingestor(t.log, List.of(new Ingestor.Registration(before,
                SecurityEvent.Provenance.SIGNED_SENSOR, 600, 100)), Ingestor.Settings.defaults());
        in.pump(sealed, 100);

        EndpointCollector after = new EndpointCollector("r2", ring);
        after.resume(EndpointCollector.lastBatches(t.cursor(), 100_000));
        assertEquals(0, after.offer(b, sealed.plusSeconds(5)), "the trail remembers which batches were used");
        assertEquals(Map.of("d", 7L), after.checkpoint());
    }

    /** Not a breach (kept as a guard): framing someone with forged syslog yields a watch-only alert. */
    @Test
    void forgedSyslogNamingTheCeoLaptopNeverYieldsAnActionableAlert() {
        Fx.Trail t = new Fx.Trail();
        Fx.Alerts alerts = new Fx.Alerts();
        CorrelationEngine e = new CorrelationEngine(RuleBook.defaults(RuleBookTest.DATASETS), alerts,
                CorrelationEngine.Settings.defaults());
        FirewallCollector fw = new FirewallCollector("r", Map.of("10.20.0.1", "ceo-laptop"));
        for (int i = 0; i < 40; i++) {
            fw.offer("<134>1 " + T.plusSeconds(60L * i) + " fw01 dwfw 1 - - action=allow src=10.20.0.1 dst=6.6.6.6", T);
        }
        Ingestor in = new Ingestor(t.log, List.of(new Ingestor.Registration(fw, SecurityEvent.Provenance.COLLECTED,
                600, 100)), Ingestor.Settings.defaults());
        in.pump(T.plus(Duration.ofHours(1)), 100);
        e.run(t.cursor(), 1_000);
        List<CorrelationEngine.Raised> raised = e.recent();
        assertFalse(raised.isEmpty());
        assertTrue(raised.stream().noneMatch(CorrelationEngine.Raised::actionable));
        assertTrue(alerts.list.stream().allMatch(a -> a.summary().startsWith(CorrelationEngine.COLLECTED_ONLY)));
    }
}

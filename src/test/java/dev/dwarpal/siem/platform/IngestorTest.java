package dev.dwarpal.siem.platform;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.AuditSink;
import dev.dwarpal.soc.ChainedEvent;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EventSource;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.SecurityEvents;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Part D: ingestion into the audit chain, with quotas, trust levels and event-time checks. */
class IngestorTest {

    private static final Instant NOW = Fx.T0;

    /** A source that hands out whatever the test queues, of any dataset or provenance. */
    static final class Scripted implements EventSource {
        final String name;
        final ArrayDeque<SecurityEvent> queue = new ArrayDeque<>();
        int n;

        Scripted(String name) {
            this.name = name;
        }

        Scripted add(int count, Instant at, SecurityEvent.Provenance p, String dataset) {
            for (int i = 0; i < count; i++) {
                queue.add(Fx.event(name + "-" + (++n), at, dataset, "network.flow", p,
                        List.of(Entity.ip("10.0.0." + (n % 250 + 1))), Map.of("k", "v")));
            }
            return this;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public List<SecurityEvent> poll(int max) {
            List<SecurityEvent> out = new ArrayList<>();
            while (out.size() < max && !queue.isEmpty()) {
                out.add(queue.poll());
            }
            return out;
        }

        @Override
        public long refused() {
            return 0;
        }
    }

    private static List<ChainedEvent> read(Fx.Trail t) {
        AuditCursor c = t.cursor();
        List<ChainedEvent> out = new ArrayList<>();
        for (AuditEvent a : c.next(10_000).events()) {
            out.add(SecurityEvents.fromAudit(a));
        }
        assertTrue(c.broken().isEmpty());
        return out;
    }

    private static Ingestor ingestor(Fx.Trail t, Ingestor.Registration... r) {
        return new Ingestor(t.log, List.of(r), Ingestor.Settings.defaults());
    }

    // ---- abuse first ----------------------------------------------------------------------------------------

    @Test
    void aSourceCannotWriteAnotherDatasetOrClaimMoreTrustThanItHas() {
        Fx.Trail t = new Fx.Trail();
        Scripted fw = new Scripted("firewall")
                .add(1, NOW, SecurityEvent.Provenance.SIGNED_SENSOR, "firewall")     // syslog posing as a sensor
                .add(1, NOW, SecurityEvent.Provenance.COLLECTED, "endpoint")         // another dataset
                .add(1, NOW, SecurityEvent.Provenance.COLLECTED, "firewall");
        Ingestor.Report r = ingestor(t, new Ingestor.Registration(fw, SecurityEvent.Provenance.COLLECTED, 600, 100))
                .pump(NOW, 100);
        assertEquals(1, r.written());
        assertEquals(Map.of("firewall:provenance-above-source", 1L, "firewall:wrong-dataset", 1L), r.refused());
        List<ChainedEvent> chain = read(t);
        assertEquals(2, chain.size(), "the event and one refusal summary");
        SecurityEvent summary = chain.get(1).event();
        assertEquals(Ingestor.REFUSED_ACTION, summary.action());
        assertEquals("1", summary.field("refused.provenance_above_source").orElseThrow());
        assertTrue(summary.entities().isEmpty(), "a summary names nobody");
        assertThrows(IllegalArgumentException.class, () -> new Ingestor.Registration(fw,
                SecurityEvent.Provenance.VERIFIED_AUDIT, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> ingestor(t,
                new Ingestor.Registration(new Scripted(SecurityEvents.NATIVE_DATASET), SecurityEvent.Provenance.COLLECTED, 1, 1)));
        assertThrows(IllegalArgumentException.class, () -> ingestor(t,
                new Ingestor.Registration(fw, SecurityEvent.Provenance.COLLECTED, 1, 1),
                new Ingestor.Registration(new Scripted("firewall"), SecurityEvent.Provenance.COLLECTED, 1, 1)));
    }

    @Test
    void futureAndAncientEventsAreRefusedAndLateOnesFlagged() {
        Fx.Trail t = new Fx.Trail();
        Scripted s = new Scripted("cloud")
                .add(1, NOW.plus(Duration.ofMinutes(6)), SecurityEvent.Provenance.COLLECTED, "cloud")
                .add(1, NOW.minus(Duration.ofDays(8)), SecurityEvent.Provenance.COLLECTED, "cloud")
                .add(1, NOW.minus(Duration.ofHours(3)), SecurityEvent.Provenance.COLLECTED, "cloud")
                .add(1, NOW.plus(Duration.ofMinutes(4)), SecurityEvent.Provenance.COLLECTED, "cloud");
        Ingestor.Report r = ingestor(t, new Ingestor.Registration(s, SecurityEvent.Provenance.COLLECTED, 600, 100))
                .pump(NOW, 100);
        assertEquals(2, r.written());
        assertEquals(1, r.late());
        assertEquals(Map.of("cloud:future-time", 1L, "cloud:too-old", 1L), r.refused());
        SecurityEvent late = read(t).getFirst().event();
        assertEquals("true", late.field("ingest.late").orElseThrow());
        assertEquals("10800", late.field("ingest.lagSeconds").orElseThrow());
        assertThrows(IllegalArgumentException.class, () -> new Ingestor.Settings(Duration.ofHours(2),
                Duration.ofDays(1), Duration.ofHours(1)));
        assertThrows(IllegalArgumentException.class, () -> new Ingestor.Settings(Duration.ofMinutes(1),
                Duration.ofHours(1), Duration.ofHours(1)));
    }

    @Test
    void aFloodingSourceCannotStarveTheOthers() {
        Fx.Trail t = new Fx.Trail();
        Scripted loud = new Scripted("firewall").add(50_000, NOW, SecurityEvent.Provenance.COLLECTED, "firewall");
        Scripted quiet = new Scripted("cloud").add(40, NOW, SecurityEvent.Provenance.COLLECTED, "cloud");
        Ingestor in = ingestor(t,
                new Ingestor.Registration(loud, SecurityEvent.Provenance.COLLECTED, 600, 1_000),
                new Ingestor.Registration(quiet, SecurityEvent.Provenance.COLLECTED, 60, 100));
        Ingestor.Report r = in.pump(NOW, 10_000);
        assertEquals(1_040, r.written(), "the loud source gets its burst, the quiet one everything");
        assertTrue(quiet.queue.isEmpty());
        assertEquals(0, in.pump(NOW, 10_000).written(), "no time passed, no new tokens");
        assertEquals(600, in.pump(NOW.plus(Duration.ofMinutes(1)), 10_000).written(), "one minute of quota");
        assertEquals(0, in.pump(NOW, 10_000).written(), "a clock going back earns nothing");
        assertEquals(1_640, in.written());
        assertEquals(List.of("firewall", "cloud"), in.datasets());
        assertThrows(IllegalArgumentException.class, () -> in.pump(NOW, 0));
    }

    @Test
    void whenTheAuditWriteFailsNothingIsLostAndNothingMoreIsRead() {
        Fx.Trail t = new Fx.Trail();
        boolean[] failing = {true};
        AuditSink flaky = record -> {
            if (failing[0]) {
                throw new IllegalStateException("disk full");
            }
            t.sink.write(record);
        };
        AuditLog log = new AuditLog(t.key, flaky);
        Scripted s = new Scripted("cloud").add(5, NOW, SecurityEvent.Provenance.COLLECTED, "cloud")
                .add(1, NOW.plus(Duration.ofHours(1)), SecurityEvent.Provenance.COLLECTED, "cloud");
        Ingestor in = new Ingestor(log, List.of(new Ingestor.Registration(s, SecurityEvent.Provenance.COLLECTED,
                600, 100)), Ingestor.Settings.defaults());
        Ingestor.Report r = in.pump(NOW, 100);
        assertEquals(0, r.written());
        assertTrue(r.problem().orElseThrow().contains("audit write failed"));
        failing[0] = false;
        Ingestor.Report r2 = in.pump(NOW, 100);
        assertEquals(5, r2.written(), "the held events, in order");
        List<ChainedEvent> chain = read(t);
        assertEquals(List.of("cloud-1", "cloud-2", "cloud-3", "cloud-4", "cloud-5"),
                chain.subList(0, 5).stream().map(c -> c.event().id()).toList());
        assertEquals(1L, in.refusals().get("cloud").get("future-time"));
    }

    @Test
    void aFailedRefusalSummaryIsKeptForTheNextPump() {
        Fx.Trail t = new Fx.Trail();
        int[] calls = {0};
        AuditSink failsSecond = record -> {
            if (++calls[0] == 2) {
                throw new IllegalStateException("blip");
            }
            t.sink.write(record);
        };
        AuditLog log = new AuditLog(t.key, failsSecond);
        Scripted s = new Scripted("cloud").add(1, NOW, SecurityEvent.Provenance.COLLECTED, "cloud")
                .add(1, NOW.plus(Duration.ofHours(1)), SecurityEvent.Provenance.COLLECTED, "cloud");
        Ingestor in = new Ingestor(log, List.of(new Ingestor.Registration(s, SecurityEvent.Provenance.COLLECTED,
                600, 100)), Ingestor.Settings.defaults());
        assertTrue(in.pump(NOW, 100).problem().orElseThrow().contains("summary kept"));
        assertFalse(in.pump(NOW, 100).problem().isPresent());
        assertEquals(Ingestor.REFUSED_ACTION, read(t).getLast().event().action());
    }

    @Test
    void ingestedEventsComeBackFromTheVerifiedChainUnderTheirCollector() {
        Fx.Trail t = new Fx.Trail();
        FirewallCollector fw = new FirewallCollector("r1", Map.of());
        fw.offer("<134>1 2026-11-04T10:00:00Z fw01 dwfw 1 - - action=allow src=1.2.3.4 dst=5.6.7.8", NOW);
        fw.offer("garbage", NOW);
        Ingestor in = ingestor(t, new Ingestor.Registration(fw, SecurityEvent.Provenance.COLLECTED, 600, 100));
        assertEquals(2, in.pump(NOW, 10).written());
        List<AuditRecord> records = t.sink.snapshot();
        assertEquals("collector:firewall", records.getFirst().actor());
        assertEquals(SecurityEvents.RECORD_TYPE, records.getFirst().type());
        List<ChainedEvent> chain = read(t);
        assertEquals("network.flow", chain.get(0).event().action());
        assertEquals("parse.failure", chain.get(1).event().action());
        assertThrows(IllegalArgumentException.class, () -> new Ingestor(t.log, List.of(), Ingestor.Settings.defaults()));
    }
}

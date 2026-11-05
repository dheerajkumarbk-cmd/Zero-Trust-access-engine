package dev.dwarpal.siem.platform;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.crypto.TrustedKey;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Part D: the three collectors parse strictly, refuse what they cannot prove, and never drop input silently. */
class CollectorTest {

    private static final Instant T = Fx.T0;
    private static final Map<String, String> LEASES = Map.of("10.20.0.5", "laptop-u4");
    private static final KeyPair AGENT = Ed25519.generateKeyPair();
    private static final KeyPair OTHER = Ed25519.generateKeyPair();
    private static final KeyRing KEYS = new KeyRing(List.of(
            new TrustedKey("agent-laptop-a", KeyPurpose.DEVICE_AGENT, "laptop-a", AGENT.getPublic(),
                    T.minus(Duration.ofDays(30)), T.plus(Duration.ofDays(30))),
            new TrustedKey("agent-laptop-b", KeyPurpose.DEVICE_AGENT, "laptop-b", OTHER.getPublic(),
                    T.minus(Duration.ofDays(30)), T.plus(Duration.ofDays(30))),
            new TrustedKey("idp-x", KeyPurpose.IDENTITY_PROVIDER, "laptop-a", OTHER.getPublic(),
                    T.minus(Duration.ofDays(30)), T.plus(Duration.ofDays(30)))));

    private static String fw(String msg) {
        return "<134>1 2026-11-04T10:00:02Z fw01 dwfw 7 - - " + msg;
    }

    private static List<SecurityEvent> drain(CollectorBase c) {
        return c.poll(100_000);
    }

    // ---- firewall: abuse first --------------------------------------------------------------------------------

    @Test
    void firewallRefusesWhatItCannotParseAndKeepsATraceWithoutTheText() {
        FirewallCollector c = new FirewallCollector("r1", LEASES);
        String private1 = "<134>1 garbage note=do-not-copy-me";
        List<String> bad = List.of(private1, "", "<134>1 2026-11-04T10:00:02Z fw01 dwfw - - - action=allow src=10.20.0.1 dport=notanumber",
                "<999>1 2026-11-04T10:00:02Z h a - - - action=allow src=1.2.3.4 dst=5.6.7.8",
                "no priority at all", "<134>1 not-a-time h a - - - action=allow src=1.2.3.4 dst=5.6.7.8",
                fw("action=allow src=1.2.3.4 src=9.9.9.9 dst=5.6.7.8"),
                fw("action=allow src=1.2.3.4 dst=5.6.7.8 dport=70000"),
                fw("action=allow src=1.2.3.4 dst=5.6.7.8 bytes=-1"),
                fw("action=allow src=999.2.3.4 dst=5.6.7.8"),
                fw("action=allow dst=5.6.7.8"),
                fw("action=allow src=1.2.3.4 dst=5.6.7.8 junk"),
                fw("action=allow src=1.2.3.4 dst=5.6.7.8 note=\"unterminated"),
                "<134>1 2026-11-04T10:00:02Z fw01 dwfw 7 - [sd unterminated action=allow",
                "<134>1 2026-11-04T10:00:02Z fw01 dwfw 7 - bogus action=allow",
                "<134>Foo  4 10:00:02 fw01 dwfw: action=allow src=1.2.3.4 dst=5.6.7.8",
                "<134>Nov 44 10:00:02 fw01 dwfw: action=allow src=1.2.3.4 dst=5.6.7.8",
                "<134>Nov  4 25:00:02 fw01 dwfw: action=allow src=1.2.3.4 dst=5.6.7.8",
                fw("x".repeat(FirewallCollector.MAX_LINE)));
        for (String line : bad) {
            assertFalse(c.offer(line, T), line.length() > 60 ? line.substring(0, 60) : line);
        }
        assertEquals(bad.size(), c.refused());
        List<SecurityEvent> events = drain(c);
        assertEquals(bad.size(), events.size(), "every refused line is kept as an event");
        for (SecurityEvent e : events) {
            assertEquals("parse.failure", e.action());
            assertEquals(SecurityEvent.Provenance.COLLECTED, e.provenance());
            assertTrue(e.entities().isEmpty(), "nothing in a refused line is trusted enough to be an entity");
            assertTrue(e.fields().values().stream().noneMatch(v -> v.contains("do-not-copy")), "raw text is never kept");
            assertEquals(32, e.field("sha256").orElseThrow().length());
        }
    }

    @Test
    void firewallReadsRfc5424AndBsdLinesWithLeases() {
        FirewallCollector c = new FirewallCollector("r1", LEASES);
        assertTrue(c.offer(fw("action=allow src=10.20.0.5 sport=50001 dst=203.0.113.66 dport=4444 proto=tcp bytes=320 rule=out-any"), T));
        assertTrue(c.offer("<134>1 2026-11-04T10:00:03+01:00 fw01 dwfw 8 - [ex@1 a=\"b]\\\"c\"][x@2] action=deny src=198.51.100.7 dst=10.20.0.5 note=\"two words\"", T));
        assertTrue(c.offer("<134>Nov  4 10:00:04 fw01 dwfw[311]: action=drop src=1.2.3.4 dst=5.6.7.8", T));
        assertTrue(c.offer("<134>Dec 31 23:59:59 fw01 dwfw: action=weird src=::1 dst=fe80::1", T),
                "December line arriving in November is last year's");
        List<SecurityEvent> es = drain(c);
        assertEquals(4, es.size());
        SecurityEvent a = es.get(0);
        assertEquals("network.flow", a.action());
        assertEquals(Instant.parse("2026-11-04T10:00:02Z"), a.at());
        assertEquals(SecurityEvent.EventOutcome.SUCCESS, a.outcome());
        assertEquals(List.of(Entity.ip("10.20.0.5"), Entity.ip("203.0.113.66"), Entity.device("laptop-u4")), a.entities());
        assertEquals("4444", a.field("dport").orElseThrow());
        assertEquals("fw01", a.field("host").orElseThrow());
        assertTrue(a.id().startsWith("fw-r1-"));
        SecurityEvent b = es.get(1);
        assertEquals(Instant.parse("2026-11-04T09:00:03Z"), b.at());
        assertEquals(SecurityEvent.EventOutcome.FAILURE, b.outcome());
        assertEquals("two words", b.field("note").orElseThrow());
        assertTrue(b.entities().contains(Entity.device("laptop-u4")), "lease of the destination");
        assertEquals("dwfw", es.get(2).field("app").orElseThrow());
        assertEquals(Instant.parse("2026-11-04T10:00:04Z"), es.get(2).at());
        assertEquals(Instant.parse("2025-12-31T23:59:59Z"), es.get(3).at());
        assertEquals(SecurityEvent.EventOutcome.UNKNOWN, es.get(3).outcome());
        assertEquals(4, c.accepted());
    }

    @Test
    void aFloodFillsOnlyTheCollectorsOwnQueueAndTheLossIsReported() {
        FirewallCollector c = new FirewallCollector("r1", Map.of());
        int n = CollectorBase.MAX_PENDING + 25;
        for (int i = 0; i < n; i++) {
            c.offer(fw("action=allow src=1.2.3.4 dst=5.6.7.8"), T);
        }
        assertEquals(CollectorBase.MAX_PENDING, c.pending());
        assertEquals(25, c.overflowed());
        // Regression (integration finding I-1): the loss is reported at the FRONT of the queue. Behind 10,000
        // queued events and a source quota the report used to wait for hours, so a flood hid itself.
        List<SecurityEvent> first = c.poll(1);
        assertEquals(1, first.size());
        assertEquals("collector.overflow", first.getFirst().action());
        assertEquals("25", first.getFirst().field("lost").orElseThrow());
        List<SecurityEvent> es = drain(c);
        assertEquals(CollectorBase.MAX_PENDING, es.size());
        assertTrue(es.stream().noneMatch(e -> e.action().equals("collector.overflow")), "reported once");
        assertTrue(drain(c).isEmpty());
        assertThrows(IllegalArgumentException.class, () -> c.poll(0));
    }

    @Test
    void collectorSettingsAreChecked() {
        assertThrows(IllegalArgumentException.class, () -> new FirewallCollector("a".repeat(25), Map.of()));
        assertThrows(IllegalArgumentException.class, () -> new FirewallCollector("ok", Map.of("1.2.3.4", "bad id!")));
        assertThrows(IllegalArgumentException.class, () -> new CloudCollector("bad run", Map.of()));
        Map<String, String> many = new HashMap<>();
        for (int i = 0; i <= FirewallCollector.MAX_LEASES; i++) {
            many.put("ip" + i, "d" + i);
        }
        assertThrows(IllegalArgumentException.class, () -> new FirewallCollector("ok", many));
        assertThrows(IllegalArgumentException.class, () -> new CloudCollector("ok", many));
        assertTrue(CollectorBase.address("10.0.0.1"));
        assertFalse(CollectorBase.address("10.0.0"));
        assertFalse(CollectorBase.address("10..0.1"));
        assertFalse(CollectorBase.address("::g"));
        assertFalse(CollectorBase.address(""));
        assertEquals(-1, CollectorBase.count("1".repeat(19)));
    }

    // ---- endpoint: abuse first --------------------------------------------------------------------------------

    private static String line(String device, Instant ts, String type, String extra) {
        return "{\"ts\":\"" + ts + "\",\"device\":\"" + device + "\",\"user\":\"u1\",\"type\":\"" + type + "\"" + extra + "}\n";
    }

    private static EndpointCollector.Batch batch(KeyPair k, String keyId, String device, long n, Instant sealed,
                                                 String body) {
        byte[] msg = SignedMessages.endpointTelemetry(device, n, sealed, Digests.sha256Hex(body));
        return new EndpointCollector.Batch(device, keyId, n, sealed, body, Ed25519.sign(k.getPrivate(), msg));
    }

    private static final Instant SEALED = T.plus(Duration.ofHours(1));
    private static final String BODY = line("laptop-a", T.plus(Duration.ofMinutes(5)), "process.start",
            ",\"process\":\"powershell.exe\",\"cmd\":\"powershell.exe -enc AAAA\"")
            + line("laptop-a", T.plus(Duration.ofMinutes(6)), "network.connect", ",\"dst\":\"203.0.113.66\",\"dport\":\"4444\"");

    @Test
    void forgedEditedMovedOrMisusedBatchesAreRefused() {
        EndpointCollector c = new EndpointCollector("r1", KEYS);
        EndpointCollector.Batch good = batch(AGENT, "agent-laptop-a", "laptop-a", 1, SEALED, BODY);
        List<EndpointCollector.Batch> bad = List.of(
                new EndpointCollector.Batch("laptop-a", good.keyId(), 1, SEALED, BODY.replace("4444", "4445"),
                        good.signature()),                                                           // edited body
                batch(OTHER, "agent-laptop-b", "laptop-a", 1, SEALED, BODY),                          // another device's key
                batch(AGENT, "agent-laptop-a", "laptop-b", 1, SEALED, BODY),                          // moved to another device
                batch(OTHER, "idp-x", "laptop-a", 1, SEALED, BODY),                                   // key of another purpose
                batch(AGENT, "agent-unknown", "laptop-a", 1, SEALED, BODY),                           // unknown key
                batch(AGENT, "agent-laptop-a", "laptop-a", 1, SEALED.minus(Duration.ofHours(3)), BODY), // too old
                batch(AGENT, "agent-laptop-a", "laptop-a", 1, SEALED.plus(Duration.ofMinutes(10)), BODY), // future
                new EndpointCollector.Batch("bad device!", "agent-laptop-a", 1, SEALED, BODY, good.signature()),
                new EndpointCollector.Batch("laptop-a", "agent-laptop-a", 1, SEALED, BODY, "%%%"),
                new EndpointCollector.Batch("laptop-a", "agent-laptop-a", 1, SEALED,
                        "x".repeat(EndpointCollector.MAX_BODY + 1), good.signature()));
        for (EndpointCollector.Batch b : bad) {
            assertEquals(0, c.offer(b, SEALED));
        }
        assertEquals(bad.size(), c.refused());
        List<SecurityEvent> es = drain(c);
        assertEquals(bad.size(), es.size());
        for (SecurityEvent e : es) {
            assertEquals("telemetry.refused", e.action());
            assertEquals(SecurityEvent.Provenance.COLLECTED, e.provenance(), "nothing in a refused batch is proven");
            assertTrue(e.entities().isEmpty(), "the claimed device is a field, never an entity");
        }
        assertEquals(2, c.offer(good, SEALED), "the genuine batch still works");
    }

    @Test
    void batchNumbersAreSingleUseInOrderAndGapsAreReported() {
        EndpointCollector c = new EndpointCollector("r1", KEYS);
        assertEquals(2, c.offer(batch(AGENT, "agent-laptop-a", "laptop-a", 1, SEALED, BODY), SEALED));
        assertEquals(0, c.offer(batch(AGENT, "agent-laptop-a", "laptop-a", 1, SEALED, BODY), SEALED), "replay");
        assertEquals(0, c.offer(batch(AGENT, "agent-laptop-a", "laptop-a", 0, SEALED, BODY), SEALED), "zero");
        assertEquals(3, c.offer(batch(AGENT, "agent-laptop-a", "laptop-a", 5, SEALED, BODY), SEALED), "gap + 2");
        assertEquals(0, c.offer(batch(AGENT, "agent-laptop-a", "laptop-a", 4, SEALED, BODY), SEALED), "out of order");
        List<SecurityEvent> es = drain(c);
        SecurityEvent gap = es.stream().filter(e -> e.action().equals("telemetry.gap")).findFirst().orElseThrow();
        assertEquals("3", gap.field("missing").orElseThrow());
        assertEquals(SecurityEvent.Provenance.SIGNED_SENSOR, gap.provenance());
        assertEquals(List.of(Entity.device("laptop-a")), gap.entities());
        assertEquals(Map.of("laptop-a", 5L), c.checkpoint());

        EndpointCollector restarted = new EndpointCollector("r2", KEYS);
        restarted.resume(c.checkpoint());
        assertEquals(0, restarted.offer(batch(AGENT, "agent-laptop-a", "laptop-a", 5, SEALED, BODY), SEALED),
                "batches used before a restart stay used");
        assertThrows(IllegalArgumentException.class, () -> restarted.resume(Map.of("bad id!", 1L)));
    }

    @Test
    void endpointEventsAreSignedSensorEventsOfTheirOwnDevice() {
        EndpointCollector c = new EndpointCollector("r1", KEYS);
        c.offer(batch(AGENT, "agent-laptop-a", "laptop-a", 1, SEALED, BODY), SEALED);
        List<SecurityEvent> es = drain(c);
        SecurityEvent ps = es.get(0);
        assertEquals("process.start", ps.action());
        assertEquals(SecurityEvent.Category.PROCESS, ps.category());
        assertEquals(SecurityEvent.Provenance.SIGNED_SENSOR, ps.provenance());
        assertEquals(List.of(Entity.device("laptop-a"), Entity.subject("u1")), ps.entities());
        assertEquals("powershell.exe -enc AAAA", ps.field("cmd").orElseThrow());
        SecurityEvent net = es.get(1);
        assertEquals(SecurityEvent.Category.NETWORK, net.category());
        assertTrue(net.entities().contains(Entity.ip("203.0.113.66")));
        assertEquals(SecurityEvent.Category.FILE, EndpointCollector.category("usb.mount"));
        assertEquals(SecurityEvent.Category.AUTHENTICATION, EndpointCollector.category("logon.success"));
        assertEquals(SecurityEvent.Category.SYSTEM, EndpointCollector.category("sensor.heartbeat"));
        assertEquals(SecurityEvent.Category.NETWORK, EndpointCollector.category("dns.query"));
    }

    @Test
    void badLinesInASignedBatchAreRefusedOneByOne() {
        EndpointCollector c = new EndpointCollector("r1", KEYS);
        Instant in = T.plus(Duration.ofMinutes(10));
        String body = line("laptop-b", in, "process.start", "")                      // names another device
                + line("laptop-a", T.minus(Duration.ofHours(3)), "process.start", "") // outside its batch
                + line("laptop-a", in, "Process.Start", "")                           // bad type
                + "{\"ts\":\"" + in + "\",\"device\":\"laptop-a\",\"type\":\"x\",\"n\":1}\n" // not a string
                + "{\"ts\":\"" + in + "\",\"type\":\"x\"}\n"                         // no device
                + "[1]\n" + "{\"ts\":\n" + "\n"
                + line("laptop-a", in, "file.read", ",\"path\":\"//fs01/finance/a\"");
        assertEquals(1, c.offer(batch(AGENT, "agent-laptop-a", "laptop-a", 1, SEALED, body), SEALED));
        List<SecurityEvent> es = drain(c);
        assertEquals(8, es.size());
        assertEquals(7, es.stream().filter(e -> e.action().equals("parse.failure")).count());
        assertTrue(es.stream().filter(e -> e.action().equals("parse.failure")).allMatch(e ->
                e.provenance() == SecurityEvent.Provenance.SIGNED_SENSOR && e.entities().equals(List.of(Entity.device("laptop-a")))),
                "the batch was signed: the device really sent the bad lines");
        assertEquals("line names another device", es.getFirst().field("reason").orElseThrow());
    }

    // ---- cloud ------------------------------------------------------------------------------------------------

    private static String cloud(String extra) {
        return "{\"time\":\"2026-11-04T10:00:00Z\",\"app\":\"drive\",\"user\":\"u9\",\"ip\":\"10.20.0.5\","
                + "\"op\":\"file.download\",\"object\":\"/finance/a.zip\",\"bytes\":31000000,\"share\":\"none\"" + extra + "}";
    }

    @Test
    void cloudLinesAreStrict() {
        CloudCollector c = new CloudCollector("r1", LEASES);
        List<String> bad = List.of("{\"time\":", "[]", "{\"time\":\"2026-11-04T10:00:00Z\",\"op\":\"x\"}",
                cloud(",\"user\":\"u10\""),                                       // duplicate key
                cloud("").replace("31000000", "\"31000000\""),                     // bytes as text
                cloud("").replace("31000000", "-5"),
                cloud("").replace("31000000", "1.5"),
                cloud("").replace("\"none\"", "{\"a\":\"b\"}"),                   // nested
                cloud("").replace("file.download", "File Download"),
                cloud("").replace("\"u9\"", "\"bad user!\""),
                cloud("").replace("2026-11-04T10:00:00Z", "yesterday"),
                cloud("").replace("\"drive\"", "7"),
                "{\"x\":\"" + "y".repeat(CloudCollector.MAX_LINE) + "\"}");
        for (String l : bad) {
            assertFalse(c.offer(l, T));
        }
        assertEquals(bad.size(), c.refused());
        assertTrue(drain(c).stream().allMatch(e -> e.action().equals("parse.failure")));
        assertTrue(c.offer(cloud(",\"result\":\"denied\",\"extra\":\"z\""), T));
        SecurityEvent e = drain(c).getFirst();
        assertEquals("file.download", e.action());
        assertEquals(SecurityEvent.Category.CLOUD, e.category());
        assertEquals(SecurityEvent.EventOutcome.FAILURE, e.outcome());
        assertEquals(SecurityEvent.Provenance.COLLECTED, e.provenance());
        assertEquals(List.of(Entity.subject("u9"), Entity.ip("10.20.0.5"), Entity.device("laptop-u4"),
                new Entity(Entity.Kind.RESOURCE, "/finance/a.zip")), e.entities());
        assertEquals("31000000", e.field("bytes").orElseThrow());
        assertEquals("1", e.field("extraFields").orElseThrow());
        assertTrue(c.offer(cloud(",\"result\":\"ok\"").replace("\"/finance/a.zip\"", "\"../etc\""), T));
        SecurityEvent ok = drain(c).getFirst();
        assertEquals(SecurityEvent.EventOutcome.SUCCESS, ok.outcome());
        assertFalse(ok.entities().stream().anyMatch(x -> x.kind() == Entity.Kind.RESOURCE), "not an id: field only");
    }
}

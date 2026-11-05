package dev.dwarpal.soc;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.sim.SimOrganisation;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 5.2 part 0: the common event format and its bridge to the audit chain. Abuse cases first. */
class SecurityEventTest {

    private static final Instant T = Instant.parse("2026-11-03T10:00:00Z");

    private static SecretKey key() {
        try {
            return KeyGenerator.getInstance("HmacSHA256").generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static SecurityEvent flow(SecurityEvent.Provenance p, String dataset, Map<String, String> fields) {
        return new SecurityEvent("fw-1", T, dataset, SecurityEvent.Category.NETWORK, "network.flow",
                SecurityEvent.EventOutcome.SUCCESS, p, List.of(Entity.ip("10.20.0.5"), Entity.device("laptop-u4")),
                fields);
    }

    private static AuditEvent read(InMemoryAuditSink sink, int i) {
        return AuditEvent.of(sink.snapshot().get(i));
    }

    // ---- abuse: collected events posing as something they are not ------------------------------------------

    @Test
    void aCollectedEventCanNeverPoseAsDwarpalsOwnRecord() {
        assertThrows(IllegalArgumentException.class, () -> SecurityEvents.toAuditFields(
                flow(SecurityEvent.Provenance.VERIFIED_AUDIT, "firewall", Map.of())));
        assertThrows(IllegalArgumentException.class, () -> SecurityEvents.toAuditFields(
                flow(SecurityEvent.Provenance.COLLECTED, SecurityEvents.NATIVE_DATASET, Map.of())));

        // A collector that writes the record by hand, claiming VERIFIED_AUDIT, is caught on reading.
        InMemoryAuditSink sink = new InMemoryAuditSink();
        AuditLog log = new AuditLog(key(), sink);
        Map<String, String> f = new LinkedHashMap<>(SecurityEvents.toAuditFields(
                flow(SecurityEvent.Provenance.COLLECTED, "firewall", Map.of())));
        f.put("provenance", "VERIFIED_AUDIT");
        log.append(SecurityEvents.RECORD_TYPE, SecurityEvents.collectorActor("firewall"), T, f);
        assertThrows(IllegalArgumentException.class, () -> SecurityEvents.fromAudit(read(sink, 0)));
    }

    @Test
    void aCollectorCanOnlyWriteItsOwnDataset() {
        InMemoryAuditSink sink = new InMemoryAuditSink();
        AuditLog log = new AuditLog(key(), sink);
        Map<String, String> f = SecurityEvents.toAuditFields(flow(SecurityEvent.Provenance.SIGNED_SENSOR, "endpoint",
                Map.of()));
        // The firewall collector (unauthenticated syslog) tries to pass its events off as signed endpoint data.
        log.append(SecurityEvents.RECORD_TYPE, SecurityEvents.collectorActor("firewall"), T, f);
        log.append(SecurityEvents.RECORD_TYPE, "pdp", T, f);
        assertThrows(IllegalArgumentException.class, () -> SecurityEvents.fromAudit(read(sink, 0)));
        assertThrows(IllegalArgumentException.class, () -> SecurityEvents.fromAudit(read(sink, 1)));
    }

    @Test
    void malformedSecurityEventRecordsAreRefusedNotGuessed() {
        InMemoryAuditSink sink = new InMemoryAuditSink();
        AuditLog log = new AuditLog(key(), sink);
        Map<String, String> good = SecurityEvents.toAuditFields(flow(SecurityEvent.Provenance.COLLECTED, "firewall",
                Map.of()));
        String actor = SecurityEvents.collectorActor("firewall");
        List<Map<String, String>> bad = new ArrayList<>();
        for (String missing : List.of("eventId", "eventTime", "category", "action", "outcome", "provenance", "entities")) {
            Map<String, String> m = new HashMap<>(good);
            m.remove(missing);
            bad.add(m);
        }
        for (String[] change : new String[][]{{"eventTime", "yesterday"}, {"category", "MAGIC"},
                {"entities", "SUBJECT"}, {"entities", "PERSON=ceo"}, {"entities", "SUBJECT=a b"},
                {"entities", "SUBJECT=ceo;SUBJECT=ceo"}, {"action", "Network-Flow"}, {"outcome", "MAYBE"}}) {
            Map<String, String> m = new HashMap<>(good);
            m.put(change[0], change[1]);
            bad.add(m);
        }
        StringBuilder many = new StringBuilder();
        for (int i = 0; i < 17; i++) {
            many.append(i == 0 ? "" : ";").append("IP=10.0.0.").append(i);
        }
        Map<String, String> m = new HashMap<>(good);
        m.put("entities", many.toString());
        bad.add(m);
        for (Map<String, String> b : bad) {
            log.append(SecurityEvents.RECORD_TYPE, actor, T, b);
        }
        for (int i = 0; i < bad.size(); i++) {
            AuditEvent e = read(sink, i);
            assertThrows(IllegalArgumentException.class, () -> SecurityEvents.fromAudit(e), bad.get(i).toString());
        }
    }

    @Test
    void eventsAreBoundedAndTheirTextIsSafeToShow() {
        assertThrows(IllegalArgumentException.class, () -> new SecurityEvent("x", T, "fw", SecurityEvent.Category.NETWORK,
                "Network.Flow", SecurityEvent.EventOutcome.SUCCESS, SecurityEvent.Provenance.COLLECTED, List.of(), Map.of()));
        assertThrows(IllegalArgumentException.class, () -> SecurityEvent.action("9flow"));
        assertThrows(IllegalArgumentException.class, () -> SecurityEvent.action(""));
        assertThrows(IllegalArgumentException.class, () -> SecurityEvent.action("a".repeat(65)));
        assertThrows(IllegalArgumentException.class, () -> SecurityEvent.name("_x"));
        assertThrows(IllegalArgumentException.class, () -> SecurityEvent.name("a-b"));
        assertThrows(IllegalArgumentException.class, () -> SecurityEvent.name("a".repeat(65)));
        assertThrows(IllegalArgumentException.class, () -> SecurityEvent.name(""));
        assertThrows(IllegalArgumentException.class, () -> flow(SecurityEvent.Provenance.COLLECTED, "fw",
                Map.of("bad name", "v")));
        Map<String, String> tooMany = new HashMap<>();
        for (int i = 0; i <= SecurityEvent.MAX_FIELDS; i++) {
            tooMany.put("f" + i, "v");
        }
        assertThrows(IllegalArgumentException.class, () -> flow(SecurityEvent.Provenance.COLLECTED, "fw", tooMany));
        List<Entity> seventeen = new ArrayList<>();
        for (int i = 0; i < 17; i++) {
            seventeen.add(Entity.ip("10.0.0." + i));
        }
        assertThrows(IllegalArgumentException.class, () -> new SecurityEvent("x", T, "fw", SecurityEvent.Category.NETWORK,
                "network.flow", SecurityEvent.EventOutcome.SUCCESS, SecurityEvent.Provenance.COLLECTED, seventeen, Map.of()));
        assertThrows(IllegalArgumentException.class, () -> new SecurityEvent("x", T, "fw", SecurityEvent.Category.NETWORK,
                "network.flow", SecurityEvent.EventOutcome.SUCCESS, SecurityEvent.Provenance.COLLECTED,
                List.of(Entity.ip("10.0.0.1"), Entity.ip("10.0.0.1")), Map.of()));

        String forged = "ok\nALERT cleared by admin\u202e";
        SecurityEvent e = flow(SecurityEvent.Provenance.COLLECTED, "fw", Map.of("note", forged, "big", "x".repeat(5000)));
        assertFalse(e.field("note").orElseThrow().contains("\n"));
        assertFalse(e.field("note").orElseThrow().contains("\u202e"));
        assertTrue(e.field("big").orElseThrow().length() <= SecurityEvent.MAX_VALUE);
        assertThrows(UnsupportedOperationException.class, () -> e.fields().put("x", "y"));
        assertFalse(SecurityEvent.Provenance.COLLECTED.actionable());
        assertTrue(SecurityEvent.Provenance.SIGNED_SENSOR.actionable());
        assertTrue(SecurityEvent.Provenance.VERIFIED_AUDIT.actionable());
        assertEquals(Entity.device("laptop-u4"), e.first(Entity.Kind.DEVICE).orElseThrow());
        assertTrue(e.first(Entity.Kind.SUBJECT).isEmpty());
    }

    // ---- the round trip through the chain -------------------------------------------------------------------

    @Test
    void aCollectedEventComesBackFromTheVerifiedChainExactlyAsItWent() {
        SecretKey k = key();
        InMemoryAuditSink sink = new InMemoryAuditSink();
        AuditLog log = new AuditLog(k, sink);
        log.append("SERVICE_STARTED", "dwarpal", T, Map.of());
        SecurityEvent sent = flow(SecurityEvent.Provenance.SIGNED_SENSOR, "endpoint",
                Map.of("process", "updsvc.exe", "dport", "4444", "x.y_z", ""));
        log.append(SecurityEvents.RECORD_TYPE, SecurityEvents.collectorActor("endpoint"), T.plusSeconds(5),
                SecurityEvents.toAuditFields(sent));
        SecurityEvent none = new SecurityEvent("c-9", T, "cloud", SecurityEvent.Category.CLOUD, "file.download",
                SecurityEvent.EventOutcome.UNKNOWN, SecurityEvent.Provenance.COLLECTED, List.of(), Map.of());
        log.append(SecurityEvents.RECORD_TYPE, SecurityEvents.collectorActor("cloud"), T.plusSeconds(6),
                SecurityEvents.toAuditFields(none));

        List<AuditEvent> events = AuditCursor.fromStart(sink, k).next(10).events();
        ChainedEvent back = SecurityEvents.fromAudit(events.get(1));
        assertEquals(sent, back.event());
        assertEquals(2, back.sequence(), "evidence is the audit sequence number");
        assertEquals(T.plusSeconds(5), back.recordedAt());
        assertEquals(none, SecurityEvents.fromAudit(events.get(2)).event());
        assertThrows(IllegalArgumentException.class, () -> new ChainedEvent(0, T, sent));
    }

    // ---- Dwarpal's own records ----------------------------------------------------------------------------

    @Test
    void everyRecordOfTheSimulatedOrganisationBecomesAVerifiedEvent() {
        SimOrganisation org = SimOrganisation.create(7, 20);
        org.run(org.pipeline(org.engine()), org.traffic());
        Map<SecurityEvent.EventOutcome, Integer> outcomes = new EnumMap<>(SecurityEvent.EventOutcome.class);
        int decisions = 0;
        for (AuditRecord r : org.sink.snapshot()) {
            AuditEvent a = AuditEvent.of(r);
            SecurityEvent e = SecurityEvents.fromAudit(a).event();
            assertEquals(SecurityEvent.Provenance.VERIFIED_AUDIT, e.provenance());
            assertEquals(SecurityEvents.NATIVE_DATASET, e.dataset());
            assertEquals("audit-" + r.sequence(), e.id());
            if (a.type().equals("ACCESS_DECISION")) {
                decisions++;
                assertEquals(SecurityEvent.Category.ACCESS, e.category());
                assertEquals("access.decision", e.action());
                assertEquals(a.field("subject").orElseThrow(), e.first(Entity.Kind.SUBJECT).orElseThrow().id());
                assertEquals(a.field("sourceIp").orElseThrow(), e.first(Entity.Kind.IP).orElseThrow().id());
                assertTrue(e.first(Entity.Kind.DEVICE).isPresent() && e.first(Entity.Kind.RESOURCE).isPresent());
                assertEquals(a.field("signals").orElseThrow(), e.field("signals").orElseThrow());
                outcomes.merge(e.outcome(), 1, Integer::sum);
            }
        }
        assertTrue(decisions > 0);
        assertTrue(outcomes.keySet().containsAll(List.of(SecurityEvent.EventOutcome.SUCCESS,
                SecurityEvent.EventOutcome.FAILURE, SecurityEvent.EventOutcome.CHALLENGED)), outcomes.toString());
    }

    @Test
    void nativeTypesMapToCategoriesActionsAndOutcomes() {
        InMemoryAuditSink sink = new InMemoryAuditSink();
        AuditLog log = new AuditLog(key(), sink);
        String[][] cases = {
                {"SESSION_OPENED", "SESSION", "session.opened", "SUCCESS"},
                {"SESSION_REPLAY_REFUSED", "SESSION", "session.replay.refused", "FAILURE"},
                {"SESSION_MFA_REQUIRED", "SESSION", "session.mfa.required", "CHALLENGED"},
                {"SESSION_REVOKED", "SESSION", "session.revoked", "UNKNOWN"},
                {"ELEVATION_GRANTED", "PRIVILEGE", "elevation.granted", "SUCCESS"},
                {"BREAK_GLASS_REFUSED", "PRIVILEGE", "break.glass.refused", "FAILURE"},
                {"casb.dlp", "DATA", "casb.dlp", "FAILURE"},
                {"SIGNAL_DENY", "SOC", "signal.deny", "UNKNOWN"},
                {"VERDICT_ACCEPTED", "SOC", "verdict.accepted", "SUCCESS"},
                {"API_REFUSED", "AUTHENTICATION", "api.refused", "FAILURE"},
                {"POLICY_INSTALLED", "SYSTEM", "policy.installed", "SUCCESS"},
                {"9LIVES", "SYSTEM", "audit.9lives", "UNKNOWN"},
        };
        for (String[] c : cases) {
            Map<String, String> f = new LinkedHashMap<>();
            f.put("subjectId", "u1");
            f.put("deviceId", "bad id with spaces");
            f.put("sessionId", "");
            f.put("bad-name", "dropped");
            if (c[0].equals("casb.dlp")) {
                f.put("action", "BLOCK");
            }
            log.append(c[0], "dwarpal", T, f);
        }
        for (int i = 0; i < cases.length; i++) {
            SecurityEvent e = SecurityEvents.fromAudit(read(sink, i)).event();
            assertEquals(cases[i][1], e.category().name(), cases[i][0]);
            assertEquals(cases[i][2], e.action(), cases[i][0]);
            assertEquals(cases[i][3], e.outcome().name(), cases[i][0]);
            assertEquals(cases[i][0], e.field("auditType").orElseThrow());
            assertEquals(Entity.subject("u1"), e.first(Entity.Kind.SUBJECT).orElseThrow());
            assertTrue(e.first(Entity.Kind.DEVICE).orElseThrow().id().startsWith("invalid-"),
                    "an invalid value is named, not dropped");
            assertTrue(e.first(Entity.Kind.SESSION).isEmpty());
            assertTrue(e.field("bad-name").isEmpty());
        }
        Map<String, String> dlpAudit = Map.of("action", "AUDIT");
        log.append("casb.dlp", "dwarpal", T, dlpAudit);
        assertEquals(SecurityEvent.EventOutcome.SUCCESS, SecurityEvents.fromAudit(read(sink, cases.length)).event().outcome());
    }

    @Test
    void entitiesEncodeAndDecode() {
        List<Entity> es = List.of(Entity.subject("u1"), Entity.device("laptop-u1"), Entity.ip("10.20.0.2"));
        assertEquals(es, SecurityEvents.decode(SecurityEvents.encode(es)));
        assertEquals(List.of(), SecurityEvents.decode(""));
        assertThrows(IllegalArgumentException.class, () -> SecurityEvents.decode("=u1"));
        assertThrows(IllegalArgumentException.class, () -> SecurityEvents.collectorActor("bad dataset"));
    }
}

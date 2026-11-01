package dev.dwarpal.audit;

import dev.dwarpal.Fixtures;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.engine.PolicyEngineTest;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditLogTest {

    static SecretKey newKey() {
        try {
            return KeyGenerator.getInstance("HmacSHA256").generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private final SecretKey key = newKey();
    private final InMemoryAuditSink sink = new InMemoryAuditSink();
    private final AuditLog log = new AuditLog(key, sink);

    private List<AuditRecord> writeThree() {
        for (int i = 1; i <= 3; i++) {
            log.append("TEST_EVENT", "tester", Fixtures.T0.plusSeconds(i), Map.of("n", Integer.toString(i)));
        }
        return new ArrayList<>(sink.snapshot());
    }

    private static AuditRecord withPayload(AuditRecord r, String payload) {
        return new AuditRecord(r.sequence(), r.at(), r.type(), r.actor(), payload, r.previousMac(), r.mac());
    }

    @Test
    void intactTrailVerifiesIncludingTheAnchoredHead() {
        List<AuditRecord> trail = writeThree();
        assertTrue(AuditLog.verify(trail, key, log.head()).intact());
        assertEquals(3, log.head().sequence());
        assertEquals(AuditLog.GENESIS, trail.get(0).previousMac());
    }

    @Test
    void editingARecordIsDetected() {
        List<AuditRecord> trail = writeThree();
        trail.set(1, withPayload(trail.get(1), "{\"n\":\"999\"}"));
        AuditLog.Verification v = AuditLog.verify(trail, key, null);
        assertFalse(v.intact());
        assertEquals(2, v.firstBadSequence());
    }

    @Test
    void deletingReorderingOrInsertingIsDetected() {
        List<AuditRecord> deleted = writeThree();
        deleted.remove(1);
        assertFalse(AuditLog.verify(deleted, key, null).intact());

        List<AuditRecord> reordered = new ArrayList<>(sink.snapshot());
        Collections.swap(reordered, 0, 1);
        assertFalse(AuditLog.verify(reordered, key, null).intact());
    }

    @Test
    void rebuildingTheChainWithoutTheKeyFails() {
        List<AuditRecord> trail = writeThree();
        // Attacker rewrites history with their own key: every MAC is self-consistent, but not ours.
        InMemoryAuditSink forgedSink = new InMemoryAuditSink();
        AuditLog forger = new AuditLog(newKey(), forgedSink);
        for (AuditRecord r : trail) {
            forger.append(r.type(), r.actor(), r.at(), Map.of("n", "rewritten"));
        }
        assertFalse(AuditLog.verify(forgedSink.snapshot(), key, null).intact());
    }

    @Test
    void truncationIsOnlyVisibleAgainstAnExternalAnchor() {
        List<AuditRecord> trail = writeThree();
        AuditLog.Head anchored = log.head();
        List<AuditRecord> truncated = trail.subList(0, 2);
        assertTrue(AuditLog.verify(truncated, key, null).intact(), "documented limit: tail cut is invisible alone");
        assertFalse(AuditLog.verify(truncated, key, anchored).intact(), "...but caught by the anchor");
    }

    @Test
    void failedWriteDoesNotAdvanceTheChain() {
        AuditLog failing = new AuditLog(key, r -> {
            throw new IllegalStateException("disk full");
        });
        assertThrows(IllegalStateException.class,
                () -> failing.append("X", "pdp", Fixtures.T0, Map.of()));
        assertEquals(0, failing.head().sequence());
    }

    @Test
    void weakKeysAreRefused() {
        assertThrows(IllegalArgumentException.class, () -> new AuditLog(new SecretKeySpec(new byte[16], "HmacSHA256"), sink));
        assertThrows(IllegalArgumentException.class, () -> AuditLog.verify(List.of(), new SecretKeySpec(new byte[8], "HmacSHA256"), null));
    }

    @Test
    void jsonEscapingIsCompleteAndRecordsSerialise() {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("q", "a\"b\\c\nd\re\tf\bg\fh" + (char) 1 + (char) 0x2028 + (char) 0x202E + "z");
        assertEquals("{\"q\":\"a\\\"b\\\\c\\nd\\re\\tf\\bg\\fh\\u0001\\u2028\\u202ez\"}", Json.object(f));
        assertEquals("{}", Json.object(Map.of()));
        AuditRecord r = log.append("TEST_EVENT", "tester", Fixtures.T0, f);
        assertTrue(r.toJsonLine().startsWith("{\"seq\":1,"));
        assertFalse(r.toJsonLine().contains("\n"));
    }

    @Test
    void auditedDecisionPointRecordsEveryDecisionWithItsExplanation() {
        PolicyEngine engine = PolicyEngineTest.engine().withDirectory(Fixtures.directoryFor(Fixtures.request().build()));
        Clock clock = Clock.fixed(Fixtures.T0.plusSeconds(5), ZoneOffset.UTC);
        AuditedDecisionPoint pdp = new AuditedDecisionPoint(engine, log, clock);
        Decision d = pdp.decide(Fixtures.request().build(), SignalSnapshot.empty());
        assertEquals(Outcome.ALLOW, d.outcome());
        AuditRecord r = sink.snapshot().get(0);
        assertEquals("ACCESS_DECISION", r.type());
        assertEquals(Fixtures.T0.plusSeconds(5), r.at(), "audit time is the PDP clock, not the request");
        assertTrue(r.payloadJson().contains("\"outcome\":\"ALLOW\""));
        assertTrue(r.payloadJson().contains("\"policy\":\"P-01-employees-internal-apps\""));
        assertTrue(AuditLog.verify(sink.snapshot(), key, log.head()).intact());
    }

    @Test
    void noAuditNoAccess() {
        PolicyEngine engine = PolicyEngineTest.engine().withDirectory(Fixtures.directoryFor(Fixtures.request().build()));
        AuditLog broken = new AuditLog(key, r -> {
            throw new IllegalStateException("SIEM unreachable");
        });
        Decision d = new AuditedDecisionPoint(engine, broken, Clock.systemUTC())
                .decide(Fixtures.request().build(), SignalSnapshot.empty());
        assertEquals(Outcome.DENY, d.outcome());
        assertEquals("audit-failure", d.matchedPolicyId());
    }

    @Test
    void recordValidation() {
        assertThrows(IllegalArgumentException.class,
                () -> new AuditRecord(0, Fixtures.T0, "T", "a", "{}", AuditLog.GENESIS, "m"));
        assertThrows(IllegalArgumentException.class,
                () -> new AuditRecord(1, Fixtures.T0, "T\nFAKE", "a", "{}", AuditLog.GENESIS, "m"));
    }
}

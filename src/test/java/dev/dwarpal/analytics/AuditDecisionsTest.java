package dev.dwarpal.analytics;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.AuditedDecisionPoint;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.Action;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;

import static dev.dwarpal.analytics.SmallWorld.INTERNAL_APPS;
import static dev.dwarpal.analytics.SmallWorld.policies;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditDecisionsTest {

    /** The small world's engine behind the audit decorator, with a key built at run time. */
    static final class World {
        final SecretKey key = newKey();
        final InMemoryAuditSink sink = new InMemoryAuditSink();
        final AuditLog audit = new AuditLog(key, sink);
        final DecisionPoint pdp = new AuditedDecisionPoint(SmallWorld.engine(policies("v1", INTERNAL_APPS)), audit,
                Clock.fixed(Fixtures.T0, ZoneOffset.UTC));

        void decideSome(int n) {
            for (int i = 0; i < n; i++) {
                pdp.decide(SmallWorld.request("q" + i, i % 2 == 0 ? SmallWorld.ALICE : SmallWorld.BOB,
                        i % 3 == 0 ? SmallWorld.PAYROLL : SmallWorld.WIKI, Action.READ), SignalSnapshot.empty());
            }
        }

        /** A record written straight into the store by someone without the audit key. */
        void forgeOne() {
            AuditLog.Head head = audit.head();
            sink.write(new AuditRecord(head.sequence() + 1, Fixtures.T0, AuditDecisions.TYPE, "pdp",
                    "{\"subject\":\"alice\",\"resource\":\"wiki\",\"action\":\"READ\",\"outcome\":\"ALLOW\","
                            + "\"policy\":\"P-01-internal\",\"pAttack\":\"0.000000\"}",
                    head.mac(), "f".repeat(64)));
        }

        static SecretKey newKey() {
            try {
                return KeyGenerator.getInstance("HmacSHA256").generateKey();
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    @Test
    void readsDecisionsFromAVerifiedTrail() {
        World w = new World();
        w.decideSome(6);
        w.audit.append("OTHER", "x", Fixtures.T0, Map.of("a", "b"));
        AuditDecisions.Result r = AuditDecisions.read(AuditCursor.fromStart(w.sink, w.key), 100);
        assertEquals(6, r.entries().size());
        assertEquals(1, r.otherEvents());
        assertEquals(0, r.malformed());
        assertTrue(r.problem().isEmpty());
        assertFalse(r.truncated());
        assertEquals(7, r.verifiedThrough());
        assertEquals(2, r.entries().stream().filter(e -> e.outcome() == Outcome.DENY).count());   // payroll x2
        assertEquals(6, r.posteriors().size());
        assertTrue(r.source("in-memory").statement().contains("verified through sequence 7"));
        assertEquals(DataSource.Kind.AUDIT_TRAIL, r.source("x").kind());
    }

    @Test
    void stopsAtMaxAndSaysSo() {
        World w = new World();
        w.decideSome(10);
        AuditDecisions.Result r = AuditDecisions.read(AuditCursor.fromStart(w.sink, w.key), 4);
        assertEquals(4, r.entries().size());
        assertTrue(r.truncated());
        assertThrows(IllegalArgumentException.class, () -> AuditDecisions.read(AuditCursor.fromStart(w.sink), 0));
        assertThrows(IllegalArgumentException.class,
                () -> AuditDecisions.read(AuditCursor.fromStart(w.sink), AuditDecisions.MAX_ENTRIES + 1));
    }

    @Test
    void malformedRecordsAreCountedNotGuessed() {
        Instant t = Fixtures.T0;
        Map<String, String> f = new LinkedHashMap<>();
        f.put("subject", "alice");
        f.put("resource", "wiki");
        f.put("action", "READ");
        f.put("outcome", "ALLOW");
        f.put("policy", "P-01");
        f.put("pAttack", "0.5");
        assertTrue(AuditDecisions.parse(new AuditEvent(1, t, AuditDecisions.TYPE, "pdp", f)).isPresent());
        for (String[] bad : new String[][]{{"pAttack", "NaN"}, {"pAttack", "1.5"}, {"pAttack", "x"},
                {"outcome", "MAYBE"}, {"subject", "bad id"}, {"policy", ""}}) {
            Map<String, String> g = new LinkedHashMap<>(f);
            g.put(bad[0], bad[1]);
            assertTrue(AuditDecisions.parse(new AuditEvent(1, t, AuditDecisions.TYPE, "pdp", g)).isEmpty(), bad[0]);
        }
        Map<String, String> missing = new LinkedHashMap<>(f);
        missing.remove("resource");
        assertTrue(AuditDecisions.parse(new AuditEvent(1, t, AuditDecisions.TYPE, "pdp", missing)).isEmpty());

        World w = new World();
        w.audit.append(AuditDecisions.TYPE, "pdp", t, Map.of("subject", "alice"));
        AuditDecisions.Result r = AuditDecisions.read(AuditCursor.fromStart(w.sink, w.key), 10);
        assertEquals(1, r.malformed());
        assertTrue(r.entries().isEmpty());
    }
}

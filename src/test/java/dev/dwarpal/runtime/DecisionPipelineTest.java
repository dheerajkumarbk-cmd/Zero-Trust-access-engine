package dev.dwarpal.runtime;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.behavior.InMemoryBehaviorHistory;
import dev.dwarpal.behavior.TrustLedger;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.engine.PolicyEngineTest;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DecisionPipelineTest {

    private final Clock clock = Clock.fixed(Fixtures.T0, ZoneOffset.UTC);
    private final InMemoryBehaviorHistory history = new InMemoryBehaviorHistory();
    private final TrustLedger trust = new TrustLedger(Duration.ofDays(30));

    private DecisionPoint core() {
        return PolicyEngineTest.engine().withDirectory(Fixtures.directoryFor(Fixtures.request().build()));
    }

    @Test
    void learnsWhatTheUserActuallyGotWhenAuditFails() throws Exception {
        // Red-team finding C4: with learning inside audit, a DENY (audit down) was learned as an ALLOW.
        AuditLog broken = new AuditLog(KeyGenerator.getInstance("HmacSHA256").generateKey(), r -> {
            throw new IllegalStateException("audit down");
        });
        Decision d = DecisionPipeline.standard(core(), broken, history, trust, clock)
                .decide(Fixtures.request().build(), SignalSnapshot.empty());
        assertEquals(Outcome.DENY, d.outcome());
        assertEquals(0, history.logins("alice"), "a denied request must not become familiar");
    }

    @Test
    void normalPathAuditsAndLearns() throws Exception {
        InMemoryAuditSink sink = new InMemoryAuditSink();
        var key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        AuditLog audit = new AuditLog(key, sink);
        Decision d = DecisionPipeline.standard(core(), audit, history, trust, clock)
                .decide(Fixtures.request().build(), SignalSnapshot.empty());
        assertEquals(Outcome.ALLOW, d.outcome());
        assertEquals(1, sink.snapshot().size());
        assertEquals(1, history.logins("alice"));
        assertTrue(AuditLog.verify(sink.snapshot(), key, audit.head()).intact());
    }
}

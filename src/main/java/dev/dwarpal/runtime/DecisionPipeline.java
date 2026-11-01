package dev.dwarpal.runtime;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditedDecisionPoint;
import dev.dwarpal.behavior.InMemoryBehaviorHistory;
import dev.dwarpal.behavior.LearningDecisionPoint;
import dev.dwarpal.behavior.TrustLedger;
import dev.dwarpal.engine.DecisionPoint;

import java.time.Clock;
import java.time.Duration;

/**
 * The one place the decorators are assembled, in the only safe order:
 * <pre>
 *   learning( audited( core ) )
 * </pre>
 * Auditing wraps the core so every decision is recorded, and may turn it into a DENY if the audit
 * trail is down. Learning wraps the audited result, so it learns the decision the user actually
 * got. The reverse order learned an ALLOW that audit had just replaced with a DENY (found by
 * red-teaming). Hand-wiring is how such mistakes happen; use this factory.
 */
public final class DecisionPipeline {

    /** Requests further than this from the clock are decided but never learned. */
    public static final Duration LEARNING_MAX_SKEW = Duration.ofMinutes(5);
    /** Only logins at or below this attack probability earn reputation. */
    public static final double GOOD_EVENT_MAX_RISK = 0.01;

    private DecisionPipeline() {
    }

    /**
     * @param core the engine, or a {@code PolicyInstaller} wrapping it for signed policy updates
     */
    public static DecisionPoint standard(DecisionPoint core, AuditLog audit, InMemoryBehaviorHistory history,
                                         TrustLedger trust, Clock clock) {
        DecisionPoint audited = new AuditedDecisionPoint(core, audit, clock);
        return new LearningDecisionPoint(audited, history, trust, GOOD_EVENT_MAX_RISK, clock, LEARNING_MAX_SKEW);
    }
}

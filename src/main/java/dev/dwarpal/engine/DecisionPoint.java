package dev.dwarpal.engine;

import dev.dwarpal.decision.Decision;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.risk.SignalSnapshot;

/**
 * Anything that answers access requests. Implemented by the engine itself and by decorators that
 * add cross-cutting protection (auditing, policy hot-swap) without the engine knowing about them.
 */
public interface DecisionPoint {

    Decision decide(AccessRequest request, SignalSnapshot signals);
}

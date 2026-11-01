package dev.dwarpal.risk;

import dev.dwarpal.domain.AccessRequest;

import java.util.Optional;

/**
 * Strategy interface for one source of risk evidence (impossible travel, device posture,
 * login-time deviation, ...). New scorers plug in without touching the engine.
 *
 * <p>A scorer may throw when its signal source is unavailable; the engine then applies the
 * resource's {@link dev.dwarpal.domain.FailMode}, never a silent ALLOW.
 */
public interface RiskScorer {

    /** Stable identifier, used in explanations and audit records. */
    String name();

    /** Empty when this scorer has nothing to say about the request. */
    Optional<RiskFactor> score(AccessRequest request, SignalSnapshot signals);
}

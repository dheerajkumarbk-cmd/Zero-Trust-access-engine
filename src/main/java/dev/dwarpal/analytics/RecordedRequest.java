package dev.dwarpal.analytics;

import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.Validate;

import java.util.Objects;

/**
 * One request kept for replay, data-minimised: the signed evidence (posture and authentication proofs)
 * is removed, because a captured proof is a credential that could be replayed within its validity
 * window. What the live engine concluded from that evidence is kept as plain facts instead.
 *
 * <p>Consequence for replay: the engine sees the request without evidence, so its device counts as
 * unverified and any login it carried is ignored. Both policies in a What-If see the same stripped
 * request, so the difference between them is still the policy's alone; {@link WhatIf} measures the
 * drift against the live decision and reports it ("replay fidelity").
 *
 * @param request             the request with {@link Evidence#none()}
 * @param liveOutcome         the outcome the live engine gave
 * @param liveRestricted      whether the live decision was restricted
 * @param liveDeviceVerified  whether the live engine verified the device's agent signature
 * @param hadAuthentication   whether the request carried an authentication claim (not whether it verified)
 * @param livePolicyId        the policy that decided the live request
 * @param livePosterior       the live P(attack | evidence)
 */
public record RecordedRequest(AccessRequest request, Outcome liveOutcome, boolean liveRestricted,
                              boolean liveDeviceVerified, boolean hadAuthentication, String livePolicyId,
                              double livePosterior) {

    public RecordedRequest {
        Objects.requireNonNull(request, "request");
        if (!request.evidence().equals(Evidence.none())) {
            throw new IllegalArgumentException("a recorded request must not keep signed evidence");
        }
        Objects.requireNonNull(liveOutcome, "liveOutcome");
        Validate.id(livePolicyId, "livePolicyId");
        Validate.probability(livePosterior, "livePosterior");
    }

    /** The minimised record of a live request and its decision. */
    public static RecordedRequest of(AccessRequest request, Decision decision) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(decision, "decision");
        AccessRequest stripped = new AccessRequest(request.requestId(), request.timestamp(), request.subject(),
                request.device(), request.resource(), request.action(), request.network(), request.pepRegion(),
                Evidence.none());
        return new RecordedRequest(stripped, decision.outcome(), decision.restricted(), decision.deviceVerified(),
                request.evidence().authentication().isPresent(), decision.matchedPolicyId(),
                decision.risk().posteriorAttack());
    }
}

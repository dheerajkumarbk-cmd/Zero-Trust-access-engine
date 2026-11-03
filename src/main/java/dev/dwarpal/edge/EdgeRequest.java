package dev.dwarpal.edge;

import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.domain.Validate;

import java.time.Instant;
import java.util.Objects;

/**
 * What an enforcement point knows about a request, and nothing more: identifiers, the device's claims,
 * the network it saw, and signed evidence.
 *
 * <p>There are deliberately no roles, departments, classifications or "managed" flags here. Those come
 * from the directory on the engine side, so a compromised or buggy gateway cannot promote a user or
 * downgrade a resource. The posture is only a claim; the engine decides how much to believe it from
 * the signed evidence.
 */
public record EdgeRequest(String requestId, Instant timestamp, String subjectId, String deviceId,
                          DevicePosture claimedPosture, String resourceId, Action action, NetworkContext network,
                          String pepRegion, Evidence evidence) {

    public EdgeRequest {
        Validate.id(requestId, "request.id");
        Objects.requireNonNull(timestamp, "request.timestamp");
        Validate.id(subjectId, "request.subjectId");
        Validate.id(deviceId, "request.deviceId");
        Objects.requireNonNull(claimedPosture, "request.claimedPosture");
        Validate.id(resourceId, "request.resourceId");
        Objects.requireNonNull(action, "request.action");
        Objects.requireNonNull(network, "request.network");
        pepRegion = Validate.label(pepRegion, "request.pepRegion");
        Objects.requireNonNull(evidence, "request.evidence");
    }

    public EdgeRequest withEvidence(Evidence e) {
        return new EdgeRequest(requestId, timestamp, subjectId, deviceId, claimedPosture, resourceId, action, network,
                pepRegion, e);
    }
}

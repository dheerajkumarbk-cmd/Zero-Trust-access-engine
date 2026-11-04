package dev.dwarpal.swg;

import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.domain.Validate;

import java.util.Objects;

/**
 * Who is behind a proxy connection: the subject and device the client agent registered for it, the
 * device's claimed posture and its signed evidence, and the network the connection comes from. Only
 * identifiers and evidence: roles and classifications come from the directory on the engine side.
 */
public record WebIdentity(String subjectId, String deviceId, DevicePosture claimedPosture, Evidence evidence,
                          NetworkContext network) {

    public WebIdentity {
        Validate.id(subjectId, "identity.subjectId");
        Validate.id(deviceId, "identity.deviceId");
        Objects.requireNonNull(claimedPosture, "identity.claimedPosture");
        Objects.requireNonNull(evidence, "identity.evidence");
        Objects.requireNonNull(network, "identity.network");
    }
}

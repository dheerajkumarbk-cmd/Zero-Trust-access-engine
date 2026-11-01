package dev.dwarpal.behavior;

import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.domain.Validate;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Objects;

/**
 * One trusted (ALLOWed) login, as remembered in a user's behavioural baseline.
 *
 * <p>A device is remembered by its id only if it proved that id with a verified agent signature;
 * otherwise it is recorded as {@link #UNVERIFIED_DEVICE}, because a typed-in device id is a claim
 * anyone can copy.
 */
public record LoginEvent(String subjectId, String deviceId, NetworkContext network, Instant at) {

    /** Shared value for every device that did not prove its identity. */
    public static final String UNVERIFIED_DEVICE = "unverified-device";

    public LoginEvent {
        Validate.id(subjectId, "login.subjectId");
        Validate.id(deviceId, "login.deviceId");
        Objects.requireNonNull(network, "login.network");
        Objects.requireNonNull(at, "login.at");
    }

    /**
     * @param deviceVerified whether the engine verified the device's agent signature for this request
     *                       (take it from {@code Decision.deviceVerified()}, never from the request's claim)
     */
    public static LoginEvent of(AccessRequest r, boolean deviceVerified) {
        return new LoginEvent(r.subject().id(), deviceVerified ? r.device().id() : UNVERIFIED_DEVICE,
                r.network(), r.timestamp());
    }

    /**
     * For scorers: whether the device in an engine-verified request proved its identity. Only valid on
     * requests that went through evidence verification, which is what scorers receive.
     */
    public static boolean deviceProven(AccessRequest verifiedRequest) {
        return verifiedRequest.device().posture().assurance().atLeast(AssuranceLevel.AGENT_SIGNED);
    }

    public String value(Feature f) {
        return switch (f) {
            case IP -> network.ip();
            case ASN -> network.asn();
            case COUNTRY -> network.country();
            case DEVICE -> deviceId;
        };
    }

    /** Minute of the day in UTC (0..1439), the raw input of the circular time model. */
    public int minuteOfDayUtc() {
        var t = at.atOffset(ZoneOffset.UTC);
        return t.getHour() * 60 + t.getMinute();
    }
}

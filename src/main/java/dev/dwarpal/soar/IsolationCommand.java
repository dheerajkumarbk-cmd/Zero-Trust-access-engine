package dev.dwarpal.soar;

import dev.dwarpal.domain.Validate;

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;

/**
 * An order to an endpoint sensor: cut the device off the network except for the management channel, or let it
 * back. {@code id} is random and single use; the sensor's acknowledgement must quote it.
 */
public record IsolationCommand(String id, String deviceId, Action action, String caseId, Instant issuedAt) {

    public enum Action { ISOLATE, RELEASE }

    public IsolationCommand {
        Validate.id(id, "command.id");
        Validate.id(deviceId, "command.deviceId");
        Objects.requireNonNull(action, "command.action");
        Validate.id(caseId, "command.caseId");
        Objects.requireNonNull(issuedAt, "command.issuedAt");
    }

    /**
     * The exact body of the batch a sensor signs to acknowledge this command (one JSON line). Compared byte for
     * byte, so there is nothing to parse and nothing to confuse.
     */
    public String ackBody() {
        return "{\"type\":\"isolation.ack\",\"command\":\"" + id + "\",\"device\":\"" + deviceId + "\",\"action\":\""
                + action.name().toLowerCase(Locale.ROOT) + "\"}";
    }
}

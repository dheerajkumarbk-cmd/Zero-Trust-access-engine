package dev.dwarpal.domain;

import java.util.Objects;

public record Device(String id, boolean managed, DevicePosture posture) {

    public Device {
        Validate.id(id, "device.id");
        Objects.requireNonNull(posture, "device.posture");
    }
}

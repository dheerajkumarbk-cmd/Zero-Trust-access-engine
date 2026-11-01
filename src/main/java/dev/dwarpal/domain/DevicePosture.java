package dev.dwarpal.domain;

import java.util.Objects;

/** Device health claims together with how trustworthy those claims are. */
public record DevicePosture(boolean osPatched, boolean diskEncrypted, boolean avHealthy, AssuranceLevel assurance) {

    public DevicePosture {
        Objects.requireNonNull(assurance, "posture.assurance");
    }

    public boolean healthy() {
        return osPatched && diskEncrypted && avHealthy;
    }
}

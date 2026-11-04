package dev.dwarpal.agent;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.edge.ClientProofs;
import dev.dwarpal.edge.EdgeRequest;

import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * The device's endpoint agent, simulated in software (a TPM-held key on a real laptop). On a managed
 * device it signs the posture it measures and binds each new session key to this device for one
 * login; on an unmanaged device there is no key, so the posture is only a claim.
 */
public final class DeviceAgent {

    private final String deviceId;
    private final String keyId;
    private final KeyPair key;
    private volatile DevicePosture measured;

    private DeviceAgent(String deviceId, String keyId, KeyPair key, DevicePosture measured) {
        this.deviceId = Validate.id(deviceId, "deviceId");
        this.keyId = keyId == null ? null : Validate.id(keyId, "keyId");
        this.key = key;
        measured(measured);
    }

    /** A device with an endpoint agent key the engine trusts for {@code deviceId}. */
    public static DeviceAgent managed(String deviceId, String keyId, KeyPair key, DevicePosture measured) {
        return new DeviceAgent(deviceId, Objects.requireNonNull(keyId, "keyId"), Objects.requireNonNull(key, "key"),
                measured);
    }

    /** A device without an agent: its posture is self-reported. */
    public static DeviceAgent unmanaged(String deviceId, DevicePosture claimed) {
        return new DeviceAgent(deviceId, null, null, claimed);
    }

    public String deviceId() {
        return deviceId;
    }

    public DevicePosture posture() {
        return measured;
    }

    /** The agent measured again (for example the disk was decrypted). */
    public void measured(DevicePosture p) {
        Objects.requireNonNull(p, "posture");
        this.measured = new DevicePosture(p.osPatched(), p.diskEncrypted(), p.avHealthy(), AssuranceLevel.SELF_REPORTED);
    }

    /** Signed posture when this device has an agent key; no evidence otherwise. */
    public Evidence evidence(Instant at) {
        if (key == null) {
            return Evidence.none();
        }
        DevicePosture p = measured;
        return Evidence.none().withPostureProof(new SignatureProof(keyId, at,
                Ed25519.sign(key.getPrivate(), SignedMessages.posture(deviceId, p, at))));
    }

    /** "This session key is mine, for this login, now"; only a device with an agent can say it. */
    public Optional<SignatureProof> bind(EdgeRequest login, PublicKey sessionKey, Instant at) {
        if (key == null) {
            return Optional.empty();
        }
        return Optional.of(ClientProofs.bindDevice(key.getPrivate(), keyId, login, sessionKey, at));
    }

    @Override
    public String toString() {
        return "DeviceAgent[deviceId=" + deviceId + ", managed=" + (key != null) + "]";
    }
}

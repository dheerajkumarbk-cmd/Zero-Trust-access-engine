package dev.dwarpal.soar;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.Validate;

import java.time.Instant;
import java.util.Objects;

/**
 * A sensor's acknowledgement: a telemetry batch signed by the device agent's own {@code DEVICE_AGENT} key (bound to
 * the device) in the endpoint-telemetry message domain, whose body is the command's {@link IsolationCommand#ackBody()}.
 */
public record SensorAck(String deviceId, String keyId, long batch, Instant sealedAt, String body, String signature) {

    public static final int MAX_BODY = 1_024;

    public SensorAck {
        Validate.id(deviceId, "ack.deviceId");
        Validate.id(keyId, "ack.keyId");
        if (batch < 1) {
            throw new IllegalArgumentException("batch numbers start at 1");
        }
        Objects.requireNonNull(sealedAt, "ack.sealedAt");
        Objects.requireNonNull(body, "ack.body");
        if (body.length() > MAX_BODY) {
            throw new IllegalArgumentException("an acknowledgement body is at most " + MAX_BODY + " characters");
        }
        Objects.requireNonNull(signature, "ack.signature");
    }

    public SignatureProof proof() {
        return new SignatureProof(keyId, sealedAt, signature);
    }

    public byte[] signedMessage() {
        return SignedMessages.endpointTelemetry(deviceId, batch, sealedAt, Digests.sha256Hex(body));
    }
}

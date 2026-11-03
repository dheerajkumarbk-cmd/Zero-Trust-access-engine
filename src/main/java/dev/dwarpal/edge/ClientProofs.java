package dev.dwarpal.edge;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.Validate;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;

/**
 * What the client side signs: the client agent (session proofs) and the device's endpoint agent (the
 * device binding at login). One implementation for the agent, the tests and the demo, so the bytes a
 * client signs can never drift from the bytes the Policy Administrator verifies.
 */
public final class ClientProofs {

    private ClientProofs() {
    }

    /** Proof of possession for one request on a session; the proof's key id is the session id. */
    public static SignatureProof sign(PrivateKey sessionKey, String sessionId, EdgeRequest r, Instant at) {
        Objects.requireNonNull(sessionKey, "sessionKey");
        Validate.id(sessionId, "sessionId");
        Objects.requireNonNull(at, "at");
        byte[] message = SignedMessages.sessionUse(sessionId, r.requestId(), r.subjectId(), r.deviceId(), r.resourceId(),
                r.action().name(), at);
        return new SignatureProof(sessionId, at, Ed25519.sign(sessionKey, message));
    }

    /** The endpoint agent's statement "this session key is mine, for this login, now". */
    public static SignatureProof bindDevice(PrivateKey agentKey, String agentKeyId, EdgeRequest login,
                                            PublicKey sessionKey, Instant at) {
        Objects.requireNonNull(agentKey, "agentKey");
        Objects.requireNonNull(sessionKey, "sessionKey");
        Objects.requireNonNull(at, "at");
        byte[] message = SignedMessages.sessionBinding(login.deviceId(), login.requestId(),
                Digests.thumbprint(sessionKey), at);
        return new SignatureProof(agentKeyId, at, Ed25519.sign(agentKey, message));
    }
}

package dev.dwarpal.devidp;

import dev.dwarpal.domain.Validate;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * The parts of WebAuthn (W3C Web Authentication, level 2) the development setup simulates in
 * software: a challenge from the relying party, and an assertion signed by the authenticator over
 * {@code authenticatorData || SHA-256(clientDataJSON)}.
 *
 * <pre>
 *   authenticatorData = SHA-256(rpId) (32 bytes) | flags (1 byte: UP 0x01, UV 0x04) | signCount (4 bytes, big-endian)
 *   clientDataJSON    = {"type":"webauthn.get","challenge":&lt;b64url&gt;,"origin":"https://&lt;rpId&gt;"}
 * </pre>
 * The signature algorithm is Ed25519 (COSE -8), which WebAuthn allows. What is left out: attestation,
 * CBOR encoding and extensions; none of them change what the identity provider has to check.
 */
public final class WebAuthn {

    public static final byte FLAG_USER_PRESENT = 0x01;
    public static final byte FLAG_USER_VERIFIED = 0x04;
    public static final String TYPE_GET = "webauthn.get";
    static final int AUTH_DATA_BYTES = 37;

    /** What the relying party (identity provider) sends to be signed. */
    public record Challenge(String challengeId, String challenge, String rpId) {
        public Challenge {
            Validate.id(challengeId, "challengeId");
            Objects.requireNonNull(challenge, "challenge");
            if (challenge.length() < 43 || challenge.length() > 128) {
                throw new IllegalArgumentException("challenge has an invalid length");
            }
            Validate.id(rpId, "rpId");
        }
    }

    /** What the authenticator answers; binary fields base64url, signature base64. */
    public record Assertion(String credentialId, String authenticatorData, String clientData, String signature) {
        public Assertion {
            Validate.id(credentialId, "credentialId");
            for (String s : new String[]{authenticatorData, clientData, signature}) {
                if (s == null || s.isEmpty() || s.length() > 1024) {
                    throw new IllegalArgumentException("assertion field has an invalid length");
                }
            }
        }
    }

    private WebAuthn() {
    }

    public static String origin(String rpId) {
        return "https://" + rpId;
    }

    static byte[] authenticatorData(String rpId, byte flags, long signCount) {
        return ByteBuffer.allocate(AUTH_DATA_BYTES).put(sha256(rpId.getBytes(StandardCharsets.UTF_8))).put(flags)
                .putInt((int) signCount).array();
    }

    static byte[] clientData(String type, String challenge, String origin) {
        return JsonWriter.bytes(JsonValue.object().put("type", type).put("challenge", challenge)
                .put("origin", origin).build());
    }

    static byte[] signedBytes(byte[] authenticatorData, byte[] clientData) {
        return ByteBuffer.allocate(authenticatorData.length + 32).put(authenticatorData).put(sha256(clientData)).array();
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}

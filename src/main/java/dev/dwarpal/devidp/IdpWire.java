package dev.dwarpal.devidp;

import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.edge.WireFormat;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonValue.JObject;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * JSON of the development identity provider's two calls, used by its server and by the client agent.
 * Strict like {@link WireFormat}: unknown, missing or wrong-typed members are errors, and messages never
 * echo values. Signature proofs use {@link WireFormat}'s proof object.
 *
 * <pre>
 * POST /v1/challenge      {"subjectId","deviceId","keyThumbprint"}            -> {"challengeId","challenge","rpId"}
 * POST /v1/authenticate   {"challengeId","subjectId","password",
 *                          "assertion":{"credentialId","authenticatorData","clientData","signature"}}
 *                                                                              -> {"authentication":{"method","authenticatedAt","keyThumbprint"},"proof"}
 * </pre>
 */
public final class IdpWire {

    /** Body of a challenge request. */
    public record ChallengeRequest(String subjectId, String deviceId, String keyThumbprint) {
    }

    private static final int MAX = 1024;

    private IdpWire() {
    }

    public static JObject challengeRequest(ChallengeRequest r) {
        return JsonValue.object().put("subjectId", r.subjectId()).put("deviceId", r.deviceId())
                .put("keyThumbprint", r.keyThumbprint()).build();
    }

    public static ChallengeRequest readChallengeRequest(JsonValue v) {
        JObject o = only(v, Set.of("subjectId", "deviceId", "keyThumbprint"));
        return new ChallengeRequest(string(o, "subjectId"), string(o, "deviceId"), string(o, "keyThumbprint"));
    }

    public static JObject challenge(WebAuthn.Challenge c) {
        return JsonValue.object().put("challengeId", c.challengeId()).put("challenge", c.challenge())
                .put("rpId", c.rpId()).build();
    }

    public static WebAuthn.Challenge readChallenge(JsonValue v) {
        JObject o = only(v, Set.of("challengeId", "challenge", "rpId"));
        try {
            return new WebAuthn.Challenge(string(o, "challengeId"), string(o, "challenge"), string(o, "rpId"));
        } catch (IllegalArgumentException e) {
            throw new JsonException("invalid challenge");
        }
    }

    public static JObject attempt(IdentityProvider.Attempt a) {
        WebAuthn.Assertion s = a.assertion();
        return JsonValue.object().put("challengeId", a.challengeId()).put("subjectId", a.subjectId())
                .put("password", a.password())
                .put("assertion", JsonValue.object().put("credentialId", s.credentialId())
                        .put("authenticatorData", s.authenticatorData()).put("clientData", s.clientData())
                        .put("signature", s.signature()).build())
                .build();
    }

    public static IdentityProvider.Attempt readAttempt(JsonValue v) {
        JObject o = only(v, Set.of("challengeId", "subjectId", "password", "assertion"));
        JObject s = only(o.get("assertion").orElseThrow(),
                Set.of("credentialId", "authenticatorData", "clientData", "signature"));
        try {
            return new IdentityProvider.Attempt(string(o, "challengeId"), string(o, "subjectId"), string(o, "password"),
                    new WebAuthn.Assertion(string(s, "credentialId"), string(s, "authenticatorData"),
                            string(s, "clientData"), string(s, "signature")));
        } catch (IllegalArgumentException e) {
            throw new JsonException("invalid attempt");
        }
    }

    public static JObject mfa(IdentityProvider.MfaProof m) {
        AuthenticationContext a = m.authentication();
        return JsonValue.object()
                .put("authentication", JsonValue.object().put("method", a.method().name())
                        .put("authenticatedAt", a.authenticatedAt().toString())
                        .put("keyThumbprint", a.keyThumbprint().orElseThrow()).build())
                .put("proof", WireFormat.proof(m.proof()))
                .build();
    }

    public static IdentityProvider.MfaProof readMfa(JsonValue v) {
        JObject o = only(v, Set.of("authentication", "proof"));
        JObject a = only(o.get("authentication").orElseThrow(), Set.of("method", "authenticatedAt", "keyThumbprint"));
        try {
            AuthMethod method = AuthMethod.valueOf(string(a, "method"));
            AuthenticationContext ctx = new AuthenticationContext(method, Instant.parse(string(a, "authenticatedAt")),
                    Optional.of(string(a, "keyThumbprint")));
            return new IdentityProvider.MfaProof(ctx, WireFormat.readProof(o.get("proof").orElseThrow()));
        } catch (IllegalArgumentException | DateTimeParseException e) {
            throw new JsonException("invalid MFA proof");
        }
    }

    private static JObject only(JsonValue v, Set<String> members) {
        if (!(v instanceof JObject o)) {
            throw new JsonException("expected an object");
        }
        if (!new HashSet<>(o.keys()).equals(members)) {
            throw new JsonException("missing or unknown member");
        }
        return o;
    }

    private static String string(JObject o, String key) {
        if (o.get(key).orElseThrow() instanceof JsonValue.JString s && s.value().length() <= MAX) {
            return s.value();
        }
        throw new JsonException(key + " must be a string of at most " + MAX + " characters");
    }
}

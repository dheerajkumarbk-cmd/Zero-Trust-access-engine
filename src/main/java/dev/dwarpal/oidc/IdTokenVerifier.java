package dev.dwarpal.oidc;

import dev.dwarpal.oidc.OidcException.Reason;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonValue.JArray;
import dev.dwarpal.wire.JsonValue.JNumber;
import dev.dwarpal.wire.JsonValue.JObject;
import dev.dwarpal.wire.JsonValue.JString;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * Checks an OpenID Connect ID token (OIDC Core, section 3.1.3.7) against a set of public keys and a
 * {@link OidcPolicy}. It does pure logic only: no network, no clock of its own (the caller passes
 * {@code now}), no state, so one instance may be shared between threads.
 *
 * <p>The order matters. First the shape of the token is checked (compact JWS of three parts, at most
 * 16 KiB, strict base64url). Then the header: the algorithm must be on the policy's allow-list, a
 * {@code crit} header refuses the token, a logout-token type is refused, and the headers {@code jku},
 * {@code x5u}, {@code x5c} and {@code jwk} are ignored (a key is only ever taken from the key set the caller
 * passes). Then the key is chosen and the signature is checked. Only after the signature is the payload read
 * and are the claims checked. A refusal throws {@link OidcException}; its message never repeats the token.
 *
 * <p>Signatures: RS256 is {@code SHA256withRSA}; ES256 is {@code SHA256withECDSAinP1363Format} (the raw
 * 64-byte R||S form of RFC 7518, so a DER-encoded signature is refused); EdDSA is Ed25519.
 * Every signature failure gives the same reason, {@code BAD_SIGNATURE}.
 *
 * <p>Replay: the nonce is compared here, but remembering that a state or nonce was used once is the
 * caller's job (it belongs to the login flow, not to the token).
 */
public final class IdTokenVerifier {

    /** Longest token accepted, in characters. */
    public static final int MAX_TOKEN_CHARS = 16 * 1024;

    private static final JsonLimits LIMITS = new JsonLimits(MAX_TOKEN_CHARS, 8, 4096, 128, 256, 32, 2000);
    private static final long MAX_EPOCH_SECOND = Instant.parse("2200-01-01T00:00:00Z").getEpochSecond();
    private static final int MAX_NAME_CHARS = 256;
    private static final int MAX_SUB_CHARS = 255;
    private static final int MAX_ACR_CHARS = 128;
    private static final int MAX_AMR_ENTRIES = 16;
    private static final int MAX_AMR_CHARS = 64;
    private static final int MAX_AUD_ENTRIES = 32;
    private static final int ES256_SIGNATURE_BYTES = 64;
    private static final int ED25519_SIGNATURE_BYTES = 64;

    private final OidcPolicy policy;

    public IdTokenVerifier(OidcPolicy policy) {
        this.policy = Objects.requireNonNull(policy, "policy");
    }

    /** Verifies a token with no limit on how long ago the person authenticated. */
    public VerifiedIdToken verify(String token, JwkSet keys, String expectedNonce, Instant now) {
        return verify(token, keys, expectedNonce, now, null);
    }

    /**
     * Verifies a token.
     *
     * @param token         the compact JWS as received
     * @param keys          the identity provider's keys; the verifier never fetches any
     * @param expectedNonce the nonce sent in this login's authentication request (not null, not blank)
     * @param now           the current time (the caller's clock)
     * @param maxAuthAge    if not null, the token must carry {@code auth_time} and it must be at most this old
     * @throws IllegalArgumentException if {@code expectedNonce} is null or blank
     * @throws OidcException            if the token is refused for any reason
     */
    public VerifiedIdToken verify(String token, JwkSet keys, String expectedNonce, Instant now,
                                  Duration maxAuthAge) {
        if (expectedNonce == null || expectedNonce.isBlank()) {
            throw new IllegalArgumentException("an expected nonce is required");
        }
        Objects.requireNonNull(keys, "keys");
        Objects.requireNonNull(now, "now");

        // 1. shape
        if (token == null || token.length() > MAX_TOKEN_CHARS) {
            throw new OidcException(Reason.MALFORMED);
        }
        int firstDot = token.indexOf('.');
        int lastDot = token.lastIndexOf('.');
        if (firstDot <= 0 || lastDot == firstDot || token.indexOf('.', firstDot + 1) != lastDot
                || lastDot == firstDot + 1) {
            throw new OidcException(Reason.MALFORMED);
        }
        String headerPart = token.substring(0, firstDot);
        String payloadPart = token.substring(firstDot + 1, lastDot);
        String signaturePart = token.substring(lastDot + 1);
        byte[] headerBytes = Base64Url.decode(headerPart, Reason.MALFORMED);
        byte[] payloadBytes = Base64Url.decode(payloadPart, Reason.MALFORMED);
        byte[] signature = Base64Url.decode(signaturePart, Reason.MALFORMED);
        JObject header = object(headerBytes);

        // 2. header
        String alg = checkHeader(header);
        String kid = optionalHeaderString(header, "kid");

        // 3. key and signature, before any claim is read
        Jwk key = keys.select(kid, alg);
        byte[] signingInput = token.substring(0, lastDot).getBytes(StandardCharsets.US_ASCII);
        if (!signatureValid(key, alg, signingInput, signature)) {
            throw new OidcException(Reason.BAD_SIGNATURE);
        }

        // 4. claims
        JObject claims = object(payloadBytes);
        return checkClaims(claims, key, alg, expectedNonce, now, maxAuthAge);
    }

    private static JObject object(byte[] json) {
        try {
            if (new JsonReader(LIMITS).read(json) instanceof JObject o) {
                return o;
            }
        } catch (JsonException e) {
            // fall through: the message of a parse error could repeat input, so it is dropped
        }
        throw new OidcException(Reason.MALFORMED);
    }

    private String checkHeader(JObject header) {
        if (header.get("crit").isPresent()) {
            throw new OidcException(Reason.ALG_REFUSED);
        }
        String alg = header.get("alg").filter(JString.class::isInstance).map(v -> ((JString) v).value()).orElse(null);
        if (alg == null || !policy.algorithms().contains(alg)) {
            throw new OidcException(Reason.ALG_REFUSED);
        }
        String typ = optionalHeaderString(header, "typ");
        if (typ != null) {
            String t = typ.toLowerCase(Locale.ROOT);
            if (t.startsWith("application/")) {
                t = t.substring("application/".length());
            }
            if (t.equals("logout+jwt")) {
                throw new OidcException(Reason.TYPE_REFUSED);
            }
        }
        return alg;
    }

    private static String optionalHeaderString(JObject header, String name) {
        Optional<JsonValue> v = header.get(name);
        if (v.isEmpty()) {
            return null;
        }
        if (v.get() instanceof JString s && s.value().length() <= MAX_NAME_CHARS) {
            return s.value();
        }
        throw new OidcException(Reason.MALFORMED);
    }

    private static boolean signatureValid(Jwk key, String alg, byte[] input, byte[] signature) {
        try {
            Signature s;
            switch (alg) {
                case OidcPolicy.RS256 -> s = Signature.getInstance("SHA256withRSA");
                case OidcPolicy.ES256 -> {
                    if (signature.length != ES256_SIGNATURE_BYTES) {
                        return false;
                    }
                    s = Signature.getInstance("SHA256withECDSAinP1363Format");
                }
                case OidcPolicy.EDDSA -> {
                    if (signature.length != ED25519_SIGNATURE_BYTES) {
                        return false;
                    }
                    s = Signature.getInstance("Ed25519");
                }
                default -> {
                    return false;
                }
            }
            s.initVerify(key.publicKey());
            s.update(input);
            return s.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    private VerifiedIdToken checkClaims(JObject c, Jwk key, String alg, String expectedNonce, Instant now,
                                        Duration maxAuthAge) {
        Duration skew = policy.skew();

        String iss = requiredString(c, "iss");
        if (!iss.equals(policy.issuer())) {
            throw new OidcException(Reason.ISSUER_MISMATCH);
        }

        checkAudience(c);

        Instant exp = requiredTime(c, "exp");
        if (!now.isBefore(exp.plus(skew))) {
            throw new OidcException(Reason.EXPIRED);
        }
        Instant iat = requiredTime(c, "iat");
        if (iat.isAfter(now.plus(skew))) {
            throw new OidcException(Reason.NOT_YET_VALID);
        }
        if (iat.isBefore(now.minus(policy.maxTokenAge()))) {
            throw new OidcException(Reason.TOO_OLD);
        }
        Optional<Instant> nbf = optionalTime(c, "nbf");
        if (nbf.isPresent() && nbf.get().isAfter(now.plus(skew))) {
            throw new OidcException(Reason.NOT_YET_VALID);
        }

        String sub = requiredString(c, "sub");
        if (sub.isEmpty() || sub.length() > MAX_SUB_CHARS || !printableAscii(sub)) {
            throw new OidcException(Reason.CLAIM_INVALID);
        }

        checkNonce(c, expectedNonce);

        Optional<Instant> authTime = optionalTime(c, "auth_time");
        if (authTime.isPresent() && authTime.get().isAfter(now.plus(skew))) {
            throw new OidcException(Reason.NOT_YET_VALID);
        }
        if (maxAuthAge != null) {
            if (authTime.isEmpty()) {
                throw new OidcException(Reason.CLAIM_INVALID);
            }
            if (authTime.get().isBefore(now.minus(maxAuthAge))) {
                throw new OidcException(Reason.TOO_OLD);
            }
        }

        String acr = optionalString(c, "acr");
        if (acr != null && (acr.length() > MAX_ACR_CHARS || !printableAscii(acr))) {
            throw new OidcException(Reason.CLAIM_INVALID);
        }
        List<String> amr = amr(c);

        return new VerifiedIdToken(sub, iss, acr == null ? "" : acr, amr, authTime, iat, exp,
                key.kid().orElse(""), alg);
    }

    private void checkAudience(JObject c) {
        JsonValue aud = c.get("aud").orElseThrow(() -> new OidcException(Reason.CLAIM_INVALID));
        List<String> values = new ArrayList<>();
        if (aud instanceof JString s) {
            values.add(s.value());
        } else if (aud instanceof JArray a && a.size() >= 1 && a.size() <= MAX_AUD_ENTRIES) {
            for (JsonValue v : a.elements()) {
                if (!(v instanceof JString s)) {
                    throw new OidcException(Reason.CLAIM_INVALID);
                }
                values.add(s.value());
            }
        } else {
            throw new OidcException(Reason.CLAIM_INVALID);
        }
        String azp = optionalString(c, "azp");
        if (!values.contains(policy.clientId())) {
            throw new OidcException(Reason.AUDIENCE_MISMATCH);
        }
        if (values.size() > 1 && azp == null) {
            throw new OidcException(Reason.AUDIENCE_MISMATCH);
        }
        if (azp != null && !azp.equals(policy.clientId())) {
            throw new OidcException(Reason.AUDIENCE_MISMATCH);
        }
    }

    private static void checkNonce(JObject c, String expectedNonce) {
        String nonce = optionalString(c, "nonce");
        if (nonce == null) {
            throw new OidcException(Reason.NONCE_MISMATCH);
        }
        byte[] got = nonce.getBytes(StandardCharsets.UTF_8);
        byte[] want = expectedNonce.getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(got, want)) {
            throw new OidcException(Reason.NONCE_MISMATCH);
        }
    }

    private static List<String> amr(JObject c) {
        Optional<JsonValue> v = c.get("amr");
        if (v.isEmpty()) {
            return List.of();
        }
        if (!(v.get() instanceof JArray a) || a.size() > MAX_AMR_ENTRIES) {
            throw new OidcException(Reason.CLAIM_INVALID);
        }
        List<String> out = new ArrayList<>();
        for (JsonValue e : a.elements()) {
            if (!(e instanceof JString s) || s.value().isEmpty() || s.value().length() > MAX_AMR_CHARS
                    || !amrChars(s.value())) {
                throw new OidcException(Reason.CLAIM_INVALID);
            }
            out.add(s.value());
        }
        return out;
    }

    private static boolean amrChars(String s) {
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            boolean ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
                    || ch == '_' || ch == '-';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static boolean printableAscii(String s) {
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch < 0x20 || ch > 0x7E) {
                return false;
            }
        }
        return true;
    }

    private static String requiredString(JObject c, String name) {
        String v = optionalString(c, name);
        if (v == null) {
            throw new OidcException(Reason.CLAIM_INVALID);
        }
        return v;
    }

    private static String optionalString(JObject c, String name) {
        Optional<JsonValue> v = c.get(name);
        if (v.isEmpty()) {
            return null;
        }
        if (v.get() instanceof JString s) {
            return s.value();
        }
        throw new OidcException(Reason.CLAIM_INVALID);
    }

    private static Instant requiredTime(JObject c, String name) {
        return optionalTime(c, name).orElseThrow(() -> new OidcException(Reason.CLAIM_INVALID));
    }

    /** A whole number of seconds since the epoch, from 0 to the year 2200; floats and exponents are refused. */
    private static Optional<Instant> optionalTime(JObject c, String name) {
        Optional<JsonValue> v = c.get(name);
        if (v.isEmpty()) {
            return Optional.empty();
        }
        if (!(v.get() instanceof JNumber n)) {
            throw new OidcException(Reason.CLAIM_INVALID);
        }
        long seconds;
        try {
            seconds = n.asLong();
        } catch (JsonException e) {
            throw new OidcException(Reason.CLAIM_INVALID);
        }
        if (seconds < 0 || seconds > MAX_EPOCH_SECOND) {
            throw new OidcException(Reason.CLAIM_INVALID);
        }
        return Optional.of(Instant.ofEpochSecond(seconds));
    }
}

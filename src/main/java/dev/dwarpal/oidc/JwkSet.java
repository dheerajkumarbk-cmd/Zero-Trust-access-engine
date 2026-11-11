package dev.dwarpal.oidc;

import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A JSON Web Key Set (RFC 7517) of the signing keys of one identity provider, parsed under hard limits:
 * at most 256 KiB of input, at most 20 keys, and no two keys with the same {@code kid} (a set that
 * breaks a rule is refused whole, so a half-trusted set never exists). Symmetric ({@code oct}) keys and
 * unsupported curves are skipped. A key of a usable type that is too weak or not valid (RSA under 2048
 * bits, an EC point off the curve) refuses the whole set.
 *
 * <p>The set is immutable. It does no network access; whoever fetches it enforces the size cap before
 * parsing, and parsing refuses anything bigger again.
 */
public final class JwkSet {

    /** Largest JWKS text accepted. */
    public static final int MAX_BYTES = 256 * 1024;
    /** Most keys in one set. */
    public static final int MAX_KEYS = 20;

    private static final JsonLimits LIMITS = new JsonLimits(MAX_BYTES, 8, 8192, 64, 64, 32, 5000);

    private final List<Jwk> keys;
    private final Map<String, Jwk> byKid;

    private JwkSet(List<Jwk> keys) {
        this.keys = List.copyOf(keys);
        Map<String, Jwk> index = new HashMap<>();
        for (Jwk k : this.keys) {
            if (k.kid().isPresent() && index.put(k.kid().get(), k) != null) {
                throw new OidcException(OidcException.Reason.KEYS_INVALID);
            }
        }
        this.byKid = Map.copyOf(index);
    }

    /** Parses a JWKS document; throws {@link OidcException} ({@code KEYS_INVALID}) if it is not acceptable. */
    public static JwkSet parse(String json) {
        if (json == null || json.length() > MAX_BYTES) {
            throw new OidcException(OidcException.Reason.KEYS_INVALID);
        }
        return parse(json.getBytes(StandardCharsets.UTF_8));
    }

    /** Parses a JWKS document from UTF-8 bytes. */
    public static JwkSet parse(byte[] utf8) {
        if (utf8 == null || utf8.length > MAX_BYTES) {
            throw new OidcException(OidcException.Reason.KEYS_INVALID);
        }
        JsonValue root;
        try {
            root = new JsonReader(LIMITS).read(utf8);
        } catch (JsonException e) {
            throw new OidcException(OidcException.Reason.KEYS_INVALID);
        }
        if (!(root instanceof JsonValue.JObject top)
                || !(top.get("keys").orElse(null) instanceof JsonValue.JArray array)
                || array.size() > MAX_KEYS) {
            throw new OidcException(OidcException.Reason.KEYS_INVALID);
        }
        List<Jwk> usable = new ArrayList<>();
        for (JsonValue element : array.elements()) {
            if (!(element instanceof JsonValue.JObject o)) {
                throw new OidcException(OidcException.Reason.KEYS_INVALID);
            }
            Jwk.fromJson(o).ifPresent(usable::add);
        }
        return new JwkSet(usable);
    }

    /** The number of usable keys (skipped keys are not counted). */
    public int size() {
        return keys.size();
    }

    /** The key with this {@code kid}, if the set has one. */
    public Optional<Jwk> find(String kid) {
        return Optional.ofNullable(byKid.get(kid));
    }

    /**
     * Chooses the key for a token. With a {@code kid} that key must exist; without one, exactly one key of
     * the right type must exist. The key must be of the type that belongs to {@code alg}, must not declare
     * a different {@code alg}, and must not declare a {@code use} other than {@code sig}.
     *
     * @throws OidcException {@code KEY_NOT_FOUND} or {@code KEY_MISMATCH}
     */
    Jwk select(String kid, String alg) {
        Jwk chosen;
        if (kid != null) {
            chosen = byKid.get(kid);
        } else {
            List<Jwk> candidates = keys.stream().filter(k -> k.fits(alg)).toList();
            chosen = candidates.size() == 1 ? candidates.get(0) : null;
        }
        if (chosen == null) {
            throw new OidcException(OidcException.Reason.KEY_NOT_FOUND);
        }
        boolean fine = chosen.fits(alg)
                && chosen.alg().map(alg::equals).orElse(true)
                && chosen.use().map("sig"::equals).orElse(true);
        if (!fine) {
            throw new OidcException(OidcException.Reason.KEY_MISMATCH);
        }
        return chosen;
    }
}

package dev.dwarpal.oidc;

/**
 * An ID token or key set that was refused. The message is fixed for each {@link Reason}: it never
 * contains any part of the token, a claim value or a key, so it is safe to log and to show. All
 * signature failures carry the same message, so a caller cannot learn why a signature was wrong.
 */
public final class OidcException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Why a token or key set was refused. */
    public enum Reason {
        /** Not a compact JWS, not strict base64url, too large, or header or payload is not a JSON object. */
        MALFORMED("the token is malformed"),
        /** The algorithm is missing, not on the allow-list, or a header the verifier cannot honour was present. */
        ALG_REFUSED("the token algorithm is not accepted"),
        /** The header type marks another kind of token (for example a logout token). */
        TYPE_REFUSED("the token type is not accepted"),
        /** No key in the set matches the token (unknown key id, or no unique key when the token names none). */
        KEY_NOT_FOUND("no matching key"),
        /** The key found cannot be used for this token (wrong key type, algorithm or use). */
        KEY_MISMATCH("the key does not fit the token"),
        /** The signature does not verify. Every signature failure gives this one reason. */
        BAD_SIGNATURE("the token signature is not valid"),
        /** A claim is missing, has the wrong type, or is out of range. */
        CLAIM_INVALID("a claim is missing or invalid"),
        /** The issuer claim is not the configured issuer. */
        ISSUER_MISMATCH("the token issuer is not accepted"),
        /** The audience (or authorised party) does not name this client. */
        AUDIENCE_MISMATCH("the token audience is not accepted"),
        /** The nonce is missing or is not the expected one. */
        NONCE_MISMATCH("the token nonce does not match"),
        /** The token has expired. */
        EXPIRED("the token has expired"),
        /** The token or the authentication in it is older than the policy allows. */
        TOO_OLD("the token is too old"),
        /** The token is not valid yet (issued or valid-from time in the future). */
        NOT_YET_VALID("the token is not valid yet"),
        /** A key set could not be read or broke a rule (size, count, duplicate id, weak or invalid key). */
        KEYS_INVALID("the key set is not acceptable"),
        /** No usable keys are available (reserved for the key source). */
        KEYS_UNAVAILABLE("no usable keys are available");

        private final String message;

        Reason(String message) {
            this.message = message;
        }

        /** The fixed message for this reason. */
        public String message() {
            return message;
        }
    }

    private final Reason reason;

    public OidcException(Reason reason) {
        super(reason.message());
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}

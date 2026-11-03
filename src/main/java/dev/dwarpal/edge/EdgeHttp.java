package dev.dwarpal.edge;

import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.Validate;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * The HTTP side of enforcement, shared by every enforcement point so they all speak the same protocol
 * and map results the same way.
 *
 * <p>Client to enforcement point, on every request in a session:
 * <pre>
 *   Authorization:      Dwarpal &lt;token&gt;
 *   Dwarpal-Session:    &lt;session id&gt;
 *   Dwarpal-Request-Id: &lt;fresh id, used once&gt;
 *   Dwarpal-Proof-Time: &lt;ISO-8601 instant&gt;
 *   Dwarpal-Proof:      &lt;Ed25519 signature, base64, over the session-use message&gt;
 * </pre>
 * All of these are removed before a request is forwarded to an application.
 */
public final class EdgeHttp {

    public static final String AUTHORIZATION = "Authorization";
    public static final String SCHEME = "Dwarpal";
    public static final String SESSION = "Dwarpal-Session";
    public static final String REQUEST_ID = "Dwarpal-Request-Id";
    public static final String PROOF = "Dwarpal-Proof";
    public static final String PROOF_TIME = "Dwarpal-Proof-Time";
    /** Sent to the client with 401: which authenticator to use. */
    public static final String CHALLENGE = "WWW-Authenticate";
    /** Sent with an allowed read-only response. */
    public static final String READ_ONLY = "Dwarpal-Read-Only";
    /** Added by an enforcement point for the application behind it; never accepted from a client. */
    public static final String UPSTREAM_SUBJECT = "X-Dwarpal-Subject";
    public static final String UPSTREAM_SESSION = "X-Dwarpal-Session";

    /** The defined client-only headers; {@link #clientOnly} also covers every other name in the same name spaces. */
    public static final List<String> CLIENT_ONLY_HEADERS = List.of(AUTHORIZATION, SESSION, REQUEST_ID, PROOF, PROOF_TIME,
            READ_ONLY, UPSTREAM_SUBJECT, UPSTREAM_SESSION);

    public static final int MAX_HEADER_VALUE_LENGTH = 8192;
    private static final int TOKEN_CHARS = 43;
    private static final int MAX_TIME_CHARS = 40;
    private static final char QUOTE = 0x22;

    private EdgeHttp() {
    }

    /** HTTP status an enforcement point answers with. */
    public static int status(EdgeResult r) {
        return switch (r.status()) {
            case OPENED -> 201;
            case GRANTED, GRANTED_LIMITED -> 200;
            case STEP_UP -> 401;
            case DENIED, REJECTED -> 403;
        };
    }

    /** {@code WWW-Authenticate} value for a step-up. */
    public static String challengeHeader(AuthMethod method) {
        return SCHEME + " challenge=" + QUOTE + method.name() + QUOTE;
    }

    /**
     * The action an HTTP request performs. Unknown or unusual methods (TRACE, CONNECT, custom verbs)
     * have no action, and an enforcement point must refuse them.
     *
     * @param downloadRoute the route serves file downloads
     * @param adminRoute    the route is administrative
     */
    public static Optional<Action> action(String method, boolean downloadRoute, boolean adminRoute) {
        if (method == null) {
            return Optional.empty();
        }
        Optional<Action> base = switch (method) {
            case "GET", "HEAD" -> Optional.of(Action.READ);
            case "POST", "PUT", "PATCH", "DELETE" -> Optional.of(Action.WRITE);
            default -> Optional.empty();
        };
        if (base.isEmpty()) {
            return base;
        }
        if (adminRoute) {
            return Optional.of(Action.ADMIN);
        }
        if (downloadRoute && base.get() == Action.READ) {
            return Optional.of(Action.DOWNLOAD);
        }
        return base;
    }

    /** The token from {@code Authorization: Dwarpal <token>}; exactly one space, a well-formed token. */
    public static Optional<String> bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(SCHEME + " ")) {
            return Optional.empty();
        }
        String token = authorization.substring(SCHEME.length() + 1);
        return wellFormedToken(token) ? Optional.of(token) : Optional.empty();
    }

    /** The proof of possession from the three proof headers, or empty if any is missing or malformed. */
    public static Optional<SignatureProof> proof(String sessionId, String signature, String time) {
        if (sessionId == null || signature == null || time == null || time.length() > MAX_TIME_CHARS) {
            return Optional.empty();
        }
        try {
            Validate.id(sessionId, "sessionId");
            if (!base64(signature)) {
                return Optional.empty();
            }
            return Optional.of(new SignatureProof(sessionId, Instant.parse(time), signature));
        } catch (IllegalArgumentException | DateTimeParseException e) {
            return Optional.empty();
        }
    }

    /** Exactly 43 base64url characters (256 random bits). */
    public static boolean wellFormedToken(String token) {
        if (token == null || token.length() != TOKEN_CHARS) {
            return false;
        }
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) {
                return false;
            }
        }
        return true;
    }

    /** A header value that cannot split a response or smuggle a request: no CR, LF or NUL, bounded length. */
    public static boolean safeHeaderValue(String v) {
        if (v == null || v.length() > MAX_HEADER_VALUE_LENGTH) {
            return false;
        }
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == 0x0D || c == 0x0A || c == 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * True for every header an enforcement point must remove from a client request before forwarding:
     * {@code Authorization} and <em>anything</em> in the {@code Dwarpal-} and {@code X-Dwarpal-} name
     * spaces, including names nobody has defined yet (a client inventing {@code X-Dwarpal-Roles} must
     * not reach an application that might trust it). Compared case-insensitively, with underscores
     * treated as dashes, because some servers and frameworks convert one into the other.
     */
    public static boolean clientOnly(String name) {
        if (name == null) {
            return false;
        }
        String n = name.strip().toLowerCase(Locale.ROOT).replace('_', '-');
        return n.equals("authorization") || n.startsWith("dwarpal-") || n.startsWith("x-dwarpal-");
    }

    private static boolean base64(String s) {
        if (s.isEmpty() || s.length() > SignatureProof.MAX_SIGNATURE_CHARS) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/'
                    || c == '=')) {
                return false;
            }
        }
        return true;
    }
}

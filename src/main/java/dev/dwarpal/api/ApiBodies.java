package dev.dwarpal.api;

import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.edge.WireFormat;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonValue.JObject;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Version 1 bodies of the administrative endpoints (revocation and privileged access), which
 * {@link WireFormat} does not cover. Same strict rules: unknown, missing and wrong-typed members are
 * errors, and messages never echo values.
 *
 * <pre>
 * revoke       {"v":1,"scope":"session"|"subject"|"device","id","reason"}
 * pam request  {"v":1,"subjectId","deviceId","role","minutes","justification",
 *               "authentication":{"method","authenticatedAt","keyThumbprint"?},"authenticationProof":proof}
 * approval     {"v":1,"requestId","approverId","approval":proof}
 * break-glass  {"v":1,"accountId","role","justification","sealed":proof}
 * review       {"v":1,"grantId","reviewerId","verdict","signed":proof}
 * answers      {"revoked":n}   {"ok":true,"id"} or {"ok":false}   {"error":"..."}
 * </pre>
 */
public final class ApiBodies {

    private static final int MAX_ID = 128;
    private static final int MAX_TIME = 40;
    private static final int MAX_TEXT = 500;
    private static final int MAX_REASON = 200;
    private static final long MAX_MINUTES = 8 * 60;

    private ApiBodies() {
    }

    /** What a revocation ends: one session, every session of a subject, or every session on a device. */
    public enum Scope { SESSION, SUBJECT, DEVICE }

    public record RevokeBody(Scope scope, String id, String reason) {
        public RevokeBody {
            Objects.requireNonNull(scope, "scope");
            Validate.id(id, "id");
            Objects.requireNonNull(reason, "reason");
            if (reason.isBlank() || reason.length() > MAX_REASON) {
                throw new IllegalArgumentException("reason must be 1 to " + MAX_REASON + " characters");
            }
        }
    }

    public record ElevationBody(String subjectId, String deviceId, String role, Duration duration, String justification,
                                AuthenticationContext authentication, SignatureProof authenticationProof) {
        public ElevationBody {
            Validate.id(subjectId, "subjectId");
            Validate.id(deviceId, "deviceId");
            Validate.id(role, "role");
            Objects.requireNonNull(duration, "duration");
            Objects.requireNonNull(justification, "justification");
            Objects.requireNonNull(authentication, "authentication");
            Objects.requireNonNull(authenticationProof, "authenticationProof");
        }
    }

    public record ApprovalBody(String requestId, String approverId, SignatureProof approval) {
        public ApprovalBody {
            Validate.id(requestId, "requestId");
            Validate.id(approverId, "approverId");
            Objects.requireNonNull(approval, "approval");
        }
    }

    public record BreakGlassBody(String accountId, String role, String justification, SignatureProof sealed) {
        public BreakGlassBody {
            Validate.id(accountId, "accountId");
            Validate.id(role, "role");
            Objects.requireNonNull(justification, "justification");
            Objects.requireNonNull(sealed, "sealed");
        }
    }

    public record ReviewBody(String grantId, String reviewerId, String verdict, SignatureProof signed) {
        public ReviewBody {
            Validate.id(grantId, "grantId");
            Validate.id(reviewerId, "reviewerId");
            Validate.id(verdict, "verdict");
            Objects.requireNonNull(signed, "signed");
        }
    }

    // ---- writing (for the console, the SOC tools and tests) ----------------------------------------------

    public static JObject revoke(RevokeBody b) {
        return versioned().put("scope", b.scope().name().toLowerCase(Locale.ROOT)).put("id", b.id())
                .put("reason", b.reason()).build();
    }

    public static JObject elevation(ElevationBody b) {
        AuthenticationContext a = b.authentication();
        JObject.Builder auth = JsonValue.object().put("method", a.method().name())
                .put("authenticatedAt", a.authenticatedAt().toString());
        a.keyThumbprint().ifPresent(t -> auth.put("keyThumbprint", t));
        return versioned().put("subjectId", b.subjectId()).put("deviceId", b.deviceId()).put("role", b.role())
                .put("minutes", JsonValue.num(b.duration().toMinutes())).put("justification", b.justification())
                .put("authentication", auth.build()).put("authenticationProof", WireFormat.proof(b.authenticationProof()))
                .build();
    }

    public static JObject approval(ApprovalBody b) {
        return versioned().put("requestId", b.requestId()).put("approverId", b.approverId())
                .put("approval", WireFormat.proof(b.approval())).build();
    }

    public static JObject breakGlass(BreakGlassBody b) {
        return versioned().put("accountId", b.accountId()).put("role", b.role()).put("justification", b.justification())
                .put("sealed", WireFormat.proof(b.sealed())).build();
    }

    public static JObject review(ReviewBody b) {
        return versioned().put("grantId", b.grantId()).put("reviewerId", b.reviewerId()).put("verdict", b.verdict())
                .put("signed", WireFormat.proof(b.signed())).build();
    }

    static JObject error(String text) {
        return JsonValue.object().put("error", text).build();
    }

    static JObject revoked(int n) {
        return JsonValue.object().put("revoked", JsonValue.num(n)).build();
    }

    static JObject pamAnswer(boolean ok, Optional<String> id) {
        return JsonValue.object().put("ok", JsonValue.bool(ok))
                .putIfPresent("id", ok ? id.map(JsonValue::str) : Optional.empty()).build();
    }

    // ---- reading ---------------------------------------------------------------------------------------

    public static RevokeBody readRevoke(JsonValue v) {
        JObject o = object(v, "revoke");
        only(o, "revoke", Set.of("v", "scope", "id", "reason"));
        version(o);
        Scope scope = switch (string(o, "scope", 16)) {
            case "session" -> Scope.SESSION;
            case "subject" -> Scope.SUBJECT;
            case "device" -> Scope.DEVICE;
            default -> throw new JsonException("scope has an unknown value");
        };
        return build(() -> new RevokeBody(scope, string(o, "id", MAX_ID), string(o, "reason", MAX_REASON)), "revoke");
    }

    public static ElevationBody readElevation(JsonValue v) {
        JObject o = object(v, "elevation");
        only(o, "elevation", Set.of("v", "subjectId", "deviceId", "role", "minutes", "justification", "authentication",
                "authenticationProof"));
        version(o);
        long minutes = integer(o, "minutes");
        if (minutes < 1 || minutes > MAX_MINUTES) {
            throw new JsonException("minutes out of range");
        }
        AuthenticationContext auth = readAuthentication(member(o, "authentication"));
        SignatureProof proof = WireFormat.readProof(member(o, "authenticationProof"));
        return build(() -> new ElevationBody(string(o, "subjectId", MAX_ID), string(o, "deviceId", MAX_ID),
                string(o, "role", MAX_ID), Duration.ofMinutes(minutes), string(o, "justification", MAX_TEXT), auth, proof),
                "elevation");
    }

    public static ApprovalBody readApproval(JsonValue v) {
        JObject o = object(v, "approval");
        only(o, "approval", Set.of("v", "requestId", "approverId", "approval"));
        version(o);
        SignatureProof proof = WireFormat.readProof(member(o, "approval"));
        return build(() -> new ApprovalBody(string(o, "requestId", MAX_ID), string(o, "approverId", MAX_ID), proof),
                "approval");
    }

    public static BreakGlassBody readBreakGlass(JsonValue v) {
        JObject o = object(v, "breakGlass");
        only(o, "breakGlass", Set.of("v", "accountId", "role", "justification", "sealed"));
        version(o);
        SignatureProof proof = WireFormat.readProof(member(o, "sealed"));
        return build(() -> new BreakGlassBody(string(o, "accountId", MAX_ID), string(o, "role", MAX_ID),
                string(o, "justification", MAX_TEXT), proof), "breakGlass");
    }

    public static ReviewBody readReview(JsonValue v) {
        JObject o = object(v, "review");
        only(o, "review", Set.of("v", "grantId", "reviewerId", "verdict", "signed"));
        version(o);
        SignatureProof proof = WireFormat.readProof(member(o, "signed"));
        return build(() -> new ReviewBody(string(o, "grantId", MAX_ID), string(o, "reviewerId", MAX_ID),
                string(o, "verdict", 32), proof), "review");
    }

    private static AuthenticationContext readAuthentication(JsonValue v) {
        JObject o = object(v, "authentication");
        Set<String> keys = new HashSet<>(o.keys());
        keys.remove("keyThumbprint");
        if (!keys.equals(Set.of("method", "authenticatedAt"))) {
            throw new JsonException("authentication: missing or unknown member");
        }
        Optional<String> thumb = o.get("keyThumbprint").map(t -> stringValue(t, "keyThumbprint", 64));
        String m = string(o, "method", 32);
        AuthMethod method = null;
        for (AuthMethod candidate : AuthMethod.values()) {
            if (candidate.name().equals(m)) {
                method = candidate;
            }
        }
        if (method == null) {
            throw new JsonException("method has an unknown value");
        }
        AuthMethod chosen = method;
        Instant at = instant(o, "authenticatedAt");
        return build(() -> new AuthenticationContext(chosen, at, thumb), "authentication");
    }

    // ---- strict field access ------------------------------------------------------------------------------

    private static <T> T build(Supplier<T> maker, String what) {
        try {
            return maker.get();
        } catch (IllegalArgumentException e) {
            throw new JsonException("invalid " + what);
        }
    }

    private static JObject.Builder versioned() {
        return JsonValue.object().put("v", JsonValue.num(WireFormat.VERSION));
    }

    private static JObject object(JsonValue v, String what) {
        if (v instanceof JObject o) {
            return o;
        }
        throw new JsonException(what + " must be an object");
    }

    private static JsonValue member(JObject o, String key) {
        return o.get(key).orElseThrow(() -> new JsonException("missing " + key));
    }

    private static void only(JObject o, String what, Set<String> required) {
        if (!new HashSet<>(o.keys()).equals(required)) {
            throw new JsonException(what + ": missing or unknown member");
        }
    }

    private static void version(JObject o) {
        if (integer(o, "v") != WireFormat.VERSION) {
            throw new JsonException("unsupported version");
        }
    }

    private static long integer(JObject o, String key) {
        if (member(o, key) instanceof JsonValue.JNumber n) {
            return n.asLong();
        }
        throw new JsonException(key + " must be an integer");
    }

    private static String string(JObject o, String key, int max) {
        return stringValue(member(o, key), key, max);
    }

    private static String stringValue(JsonValue v, String key, int max) {
        if (v instanceof JsonValue.JString s) {
            if (s.value().length() > max) {
                throw new JsonException(key + " too long");
            }
            return s.value();
        }
        throw new JsonException(key + " must be a string");
    }

    private static Instant instant(JObject o, String key) {
        try {
            return Instant.parse(string(o, key, MAX_TIME));
        } catch (DateTimeParseException e) {
            throw new JsonException(key + " must be an ISO-8601 instant");
        }
    }
}

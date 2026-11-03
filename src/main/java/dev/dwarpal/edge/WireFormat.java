package dev.dwarpal.edge;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonValue.JObject;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Version 1 of the JSON exchanged between enforcement points and the engine API. One definition used
 * by both sides, with a strict schema: unknown members, missing members and wrong types are all errors
 * (an unknown member is either a typo or an attempt to smuggle something past one side), and messages
 * name the field, never its value.
 *
 * <pre>
 * request  {"requestId","timestamp","subjectId","deviceId","posture":{"osPatched","diskEncrypted","avHealthy"},
 *           "resourceId","action","network":{"ip","asn","country","latitude","longitude","accuracyKm"},"pepRegion",
 *           "evidence":{"postureProof"?,"authentication"?:{"method","authenticatedAt","keyThumbprint"?},"authenticationProof"?}}
 * proof    {"keyId","signedAt","signature"}
 * open     {"v":1,"login":request,"sessionKey":base64 X.509,"deviceBinding"?:proof}
 * use      {"v":1,"token","proof":proof,"request":request}
 * decide   {"v":1,"request":request}
 * result   {"status","reference","message","restricted","challenge"?,"sessionEnded",
 *           "grant"?:{"sessionId","token","expiresAt","reauthDue","restricted"}}
 * </pre>
 */
public final class WireFormat {

    public static final int VERSION = 1;
    private static final int MAX_ID = 128;
    private static final int MAX_TIME = 40;
    private static final int MAX_KEY = 100;
    private static final int MAX_MESSAGE = EdgeResult.MAX_MESSAGE_LENGTH;
    private static final int MAX_SIGNATURE = SignatureProof.MAX_SIGNATURE_CHARS;

    private WireFormat() {
    }

    /** Body of a session-opening call. */
    public record OpenBody(EdgeRequest login, PublicKey sessionKey, Optional<SignatureProof> deviceBinding) {
        public OpenBody {
            Objects.requireNonNull(login, "login");
            Objects.requireNonNull(sessionKey, "sessionKey");
            Objects.requireNonNull(deviceBinding, "deviceBinding");
        }
    }

    /** Body of a session-use call. Holds the bearer token, so {@link #toString()} redacts it. */
    public record UseBody(String token, SignatureProof proof, EdgeRequest request) {
        public UseBody {
            if (!EdgeHttp.wellFormedToken(token)) {
                throw new IllegalArgumentException("malformed session token");
            }
            Objects.requireNonNull(proof, "proof");
            Objects.requireNonNull(request, "request");
        }

        @Override
        public String toString() {
            return "UseBody[token=<redacted>, proof=" + proof + ", request=" + request + "]";
        }
    }

    /** Body of a single-decision call. */
    public record DecideBody(EdgeRequest request) {
        public DecideBody {
            Objects.requireNonNull(request, "request");
        }
    }

    // ---- writing ---------------------------------------------------------------------------------------

    public static JObject request(EdgeRequest r) {
        JObject.Builder ev = JsonValue.object();
        r.evidence().postureProof().ifPresent(p -> ev.put("postureProof", proof(p)));
        r.evidence().authentication().ifPresent(a -> {
            JObject.Builder auth = JsonValue.object().put("method", a.method().name())
                    .put("authenticatedAt", a.authenticatedAt().toString());
            a.keyThumbprint().ifPresent(t -> auth.put("keyThumbprint", t));
            ev.put("authentication", auth.build());
        });
        r.evidence().authenticationProof().ifPresent(p -> ev.put("authenticationProof", proof(p)));
        NetworkContext n = r.network();
        return JsonValue.object()
                .put("requestId", r.requestId())
                .put("timestamp", r.timestamp().toString())
                .put("subjectId", r.subjectId())
                .put("deviceId", r.deviceId())
                .put("posture", JsonValue.object()
                        .put("osPatched", JsonValue.bool(r.claimedPosture().osPatched()))
                        .put("diskEncrypted", JsonValue.bool(r.claimedPosture().diskEncrypted()))
                        .put("avHealthy", JsonValue.bool(r.claimedPosture().avHealthy())).build())
                .put("resourceId", r.resourceId())
                .put("action", r.action().name())
                .put("network", JsonValue.object()
                        .put("ip", n.ip()).put("asn", n.asn()).put("country", n.country())
                        .put("latitude", number(n.latitude())).put("longitude", number(n.longitude()))
                        .put("accuracyKm", number(n.accuracyKm())).build())
                .put("pepRegion", r.pepRegion())
                .put("evidence", ev.build())
                .build();
    }

    public static JObject proof(SignatureProof p) {
        return JsonValue.object().put("keyId", p.keyId()).put("signedAt", p.signedAt().toString())
                .put("signature", p.signature()).build();
    }

    public static JObject open(OpenBody b) {
        return JsonValue.object().put("v", JsonValue.num(VERSION)).put("login", request(b.login()))
                .put("sessionKey", publicKey(b.sessionKey()))
                .putIfPresent("deviceBinding", b.deviceBinding().map(WireFormat::proof)).build();
    }

    public static JObject use(UseBody b) {
        return JsonValue.object().put("v", JsonValue.num(VERSION)).put("token", b.token())
                .put("proof", proof(b.proof())).put("request", request(b.request())).build();
    }

    public static JObject decide(DecideBody b) {
        return JsonValue.object().put("v", JsonValue.num(VERSION)).put("request", request(b.request())).build();
    }

    public static JObject result(EdgeResult r) {
        return JsonValue.object()
                .put("status", r.status().name())
                .put("reference", r.reference())
                .put("message", r.userMessage())
                .put("restricted", JsonValue.bool(r.restricted()))
                .putIfPresent("challenge", r.challenge().map(m -> JsonValue.str(m.name())))
                .put("sessionEnded", JsonValue.bool(r.sessionEnded()))
                .putIfPresent("grant", r.grant().map(g -> JsonValue.object()
                        .put("sessionId", g.sessionId()).put("token", g.token())
                        .put("expiresAt", g.expiresAt().toString()).put("reauthDue", g.reauthDue().toString())
                        .put("restricted", JsonValue.bool(g.restricted())).build()))
                .build();
    }

    public static String publicKey(PublicKey k) {
        return Base64.getEncoder().encodeToString(k.getEncoded());
    }

    // ---- reading ---------------------------------------------------------------------------------------

    public static EdgeRequest readRequest(JsonValue v) {
        JObject o = object(v, "request");
        only(o, "request", Set.of("requestId", "timestamp", "subjectId", "deviceId", "posture", "resourceId", "action",
                "network", "pepRegion", "evidence"), Set.of());
        JObject posture = object(member(o, "posture"), "posture");
        only(posture, "posture", Set.of("osPatched", "diskEncrypted", "avHealthy"), Set.of());
        JObject net = object(member(o, "network"), "network");
        only(net, "network", Set.of("ip", "asn", "country", "latitude", "longitude", "accuracyKm"), Set.of());
        JObject ev = object(member(o, "evidence"), "evidence");
        only(ev, "evidence", Set.of(), Set.of("postureProof", "authentication", "authenticationProof"));
        try {
            Optional<AuthenticationContext> auth = ev.get("authentication").map(WireFormat::readAuthentication);
            Evidence evidence = new Evidence(auth, ev.get("authenticationProof").map(WireFormat::readProof),
                    ev.get("postureProof").map(WireFormat::readProof));
            NetworkContext network = new NetworkContext(string(net, "ip", MAX_ID), string(net, "asn", MAX_ID),
                    string(net, "country", 2), dbl(net, "latitude"), dbl(net, "longitude"), dbl(net, "accuracyKm"));
            DevicePosture p = new DevicePosture(bool(posture, "osPatched"), bool(posture, "diskEncrypted"),
                    bool(posture, "avHealthy"), AssuranceLevel.SELF_REPORTED);
            return new EdgeRequest(string(o, "requestId", MAX_ID), instant(o, "timestamp"), string(o, "subjectId", MAX_ID),
                    string(o, "deviceId", MAX_ID), p, string(o, "resourceId", MAX_ID), enumOf(Action.class, o, "action"),
                    network, string(o, "pepRegion", MAX_ID), evidence);
        } catch (IllegalArgumentException e) {
            throw new JsonException("invalid request");
        }
    }

    public static SignatureProof readProof(JsonValue v) {
        JObject o = object(v, "proof");
        only(o, "proof", Set.of("keyId", "signedAt", "signature"), Set.of());
        try {
            return new SignatureProof(string(o, "keyId", MAX_ID), instant(o, "signedAt"), string(o, "signature", MAX_SIGNATURE));
        } catch (IllegalArgumentException e) {
            throw new JsonException("invalid proof");
        }
    }

    public static OpenBody readOpen(JsonValue v) {
        JObject o = object(v, "open");
        only(o, "open", Set.of("v", "login", "sessionKey"), Set.of("deviceBinding"));
        version(o);
        return new OpenBody(readRequest(member(o, "login")), readPublicKey(string(o, "sessionKey", MAX_KEY)),
                o.get("deviceBinding").map(WireFormat::readProof));
    }

    public static UseBody readUse(JsonValue v) {
        JObject o = object(v, "use");
        only(o, "use", Set.of("v", "token", "proof", "request"), Set.of());
        version(o);
        try {
            return new UseBody(string(o, "token", MAX_ID), readProof(member(o, "proof")), readRequest(member(o, "request")));
        } catch (IllegalArgumentException e) {
            throw new JsonException("invalid token");
        }
    }

    public static DecideBody readDecide(JsonValue v) {
        JObject o = object(v, "decide");
        only(o, "decide", Set.of("v", "request"), Set.of());
        version(o);
        return new DecideBody(readRequest(member(o, "request")));
    }

    public static EdgeResult readResult(JsonValue v) {
        JObject o = object(v, "result");
        only(o, "result", Set.of("status", "reference", "message", "restricted", "sessionEnded"), Set.of("challenge", "grant"));
        try {
            Optional<AuthMethod> challenge = o.get("challenge").map(c -> enumValue(AuthMethod.class, c, "challenge"));
            Optional<EdgeGrant> grant = o.get("grant").map(WireFormat::readGrant);
            return new EdgeResult(enumOf(EdgeResult.Status.class, o, "status"), string(o, "reference", MAX_ID),
                    string(o, "message", MAX_MESSAGE), bool(o, "restricted"), challenge, grant, bool(o, "sessionEnded"));
        } catch (IllegalArgumentException e) {
            throw new JsonException("invalid result");
        }
    }

    public static PublicKey readPublicKey(String base64) {
        try {
            byte[] der = Base64.getDecoder().decode(base64);
            PublicKey k = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
            if (!Ed25519.isEd25519(k)) {
                throw new JsonException("session key must be Ed25519");
            }
            return k;
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            throw new JsonException("invalid session key");
        }
    }

    private static EdgeGrant readGrant(JsonValue v) {
        JObject o = object(v, "grant");
        only(o, "grant", Set.of("sessionId", "token", "expiresAt", "reauthDue", "restricted"), Set.of());
        return new EdgeGrant(string(o, "sessionId", MAX_ID), string(o, "token", MAX_ID), instant(o, "expiresAt"),
                instant(o, "reauthDue"), bool(o, "restricted"));
    }

    private static AuthenticationContext readAuthentication(JsonValue v) {
        JObject o = object(v, "authentication");
        only(o, "authentication", Set.of("method", "authenticatedAt"), Set.of("keyThumbprint"));
        Optional<String> thumb = o.get("keyThumbprint").map(t -> stringValue(t, "keyThumbprint", 64));
        return new AuthenticationContext(enumOf(AuthMethod.class, o, "method"), instant(o, "authenticatedAt"), thumb);
    }

    // ---- strict field access ------------------------------------------------------------------------------

    private static JObject object(JsonValue v, String what) {
        if (v instanceof JObject o) {
            return o;
        }
        throw new JsonException(what + " must be an object");
    }

    private static JsonValue member(JObject o, String key) {
        return o.get(key).orElseThrow(() -> new JsonException("missing " + key));
    }

    private static void only(JObject o, String what, Set<String> required, Set<String> optional) {
        Set<String> seen = new HashSet<>(o.keys());
        for (String r : required) {
            if (!seen.remove(r)) {
                throw new JsonException(what + ": missing " + r);
            }
        }
        seen.removeAll(optional);
        if (!seen.isEmpty()) {
            throw new JsonException(what + ": unknown member");
        }
    }

    private static void version(JObject o) {
        if (!(member(o, "v") instanceof JsonValue.JNumber n) || n.asLong() != VERSION) {
            throw new JsonException("unsupported version");
        }
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

    private static boolean bool(JObject o, String key) {
        if (member(o, key) instanceof JsonValue.JBool b) {
            return b.value();
        }
        throw new JsonException(key + " must be true or false");
    }

    private static double dbl(JObject o, String key) {
        if (member(o, key) instanceof JsonValue.JNumber n) {
            return n.asDouble();
        }
        throw new JsonException(key + " must be a number");
    }

    private static Instant instant(JObject o, String key) {
        String s = string(o, key, MAX_TIME);
        try {
            return Instant.parse(s);
        } catch (DateTimeParseException e) {
            throw new JsonException(key + " must be an ISO-8601 instant");
        }
    }

    private static <E extends Enum<E>> E enumOf(Class<E> type, JObject o, String key) {
        return enumValue(type, member(o, key), key);
    }

    private static <E extends Enum<E>> E enumValue(Class<E> type, JsonValue v, String key) {
        String s = stringValue(v, key, 32);
        for (E e : type.getEnumConstants()) {
            if (e.name().equals(s)) {
                return e;
            }
        }
        throw new JsonException(key + " has an unknown value");
    }

    private static JsonValue.JNumber number(double d) {
        if (!Double.isFinite(d)) {
            throw new JsonException("number out of range");
        }
        return new JsonValue.JNumber(Double.toString(d));
    }
}

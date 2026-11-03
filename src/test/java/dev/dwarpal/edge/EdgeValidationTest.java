package dev.dwarpal.edge;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonValue.JObject;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Every validation path of the Part 0 contracts: wrong types, broken invariants, malformed headers. */
class EdgeValidationTest {

    private static final String TOKEN = "A".repeat(43);
    private final EdgeFixtures.World w = EdgeFixtures.world();
    private final KeyPair key = Ed25519.generateKeyPair();

    /** {@code o} with member {@code key} replaced (or removed when {@code v} is null), at any depth along {@code path}. */
    private static JObject with(JObject o, JsonValue v, String... path) {
        JObject.Builder b = JsonValue.object();
        for (String k : o.keys()) {
            JsonValue cur = o.get(k).orElseThrow();
            if (k.equals(path[0])) {
                if (path.length == 1) {
                    if (v != null) {
                        b.put(k, v);
                    }
                } else {
                    b.put(k, with((JObject) cur, v, java.util.Arrays.copyOfRange(path, 1, path.length)));
                }
            } else {
                b.put(k, cur);
            }
        }
        if (path.length == 1 && o.get(path[0]).isEmpty() && v != null) {
            b.put(path[0], v);
        }
        return b.build();
    }

    @Test
    void everyFieldTypeIsChecked() {
        JObject good = WireFormat.request(w.request().mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1), key).build());
        JsonValue s = JsonValue.str("x");
        JsonValue n = JsonValue.num(1);
        JsonValue t = JsonValue.bool(true);
        String[][] stringFields = {{"requestId"}, {"subjectId"}, {"network", "ip"}, {"timestamp"},
                {"evidence", "authentication", "method"}, {"evidence", "authentication", "keyThumbprint"}};
        for (String[] f : stringFields) {
            assertThrows(JsonException.class, () -> WireFormat.readRequest(with(good, n, f)), String.join(".", f));
        }
        assertThrows(JsonException.class, () -> WireFormat.readRequest(with(good, s, "posture", "osPatched")), "boolean");
        assertThrows(JsonException.class, () -> WireFormat.readRequest(with(good, s, "network", "latitude")), "number");
        assertThrows(JsonException.class, () -> WireFormat.readRequest(with(good, JsonValue.num(91), "network", "latitude")),
                "domain range");
        assertThrows(JsonException.class, () -> WireFormat.readRequest(with(good, t, "posture")), "object");
        assertThrows(JsonException.class, () -> WireFormat.readRequest(with(good, s, "timestamp")), "instant");
        assertThrows(JsonException.class, () -> WireFormat.readRequest(with(good, JsonValue.str("x".repeat(129)), "requestId")),
                "too long");
        assertThrows(JsonException.class, () -> WireFormat.readRequest(with(good, JsonValue.str("ab"), "evidence",
                "authentication", "keyThumbprint")), "thumbprint format");
        assertThrows(JsonException.class, () -> WireFormat.readRequest(with(good, JsonValue.str("x"), "evidence", "extra")),
                "unknown evidence member");
        assertThrows(JsonException.class, () -> WireFormat.readRequest(with(good, JsonValue.str("x"), "posture", "assurance")),
                "the client cannot claim an assurance level");
        assertThrows(JsonException.class, () -> WireFormat.readProof(JsonValue.object().put("keyId", "k")
                .put("signedAt", "2026-11-01T00:00:00Z").put("signature", "").build()), "empty signature");
    }

    @Test
    void bodiesAndResultsAreValidated() {
        EdgeRequest r = w.request().build();
        JObject use = WireFormat.use(new WireFormat.UseBody(TOKEN, ClientProofs.sign(key.getPrivate(), "s-1", r, w.clock.now()), r));
        assertThrows(JsonException.class, () -> WireFormat.readUse(with(use, JsonValue.str("short"), "token")));
        assertThrows(JsonException.class, () -> WireFormat.readUse(with(use, JsonValue.str("1"), "v")), "version must be a number");
        JObject open = WireFormat.open(new WireFormat.OpenBody(r, key.getPublic(), Optional.empty()));
        assertTrue(WireFormat.readOpen(open).deviceBinding().isEmpty());
        assertThrows(JsonException.class, () -> WireFormat.readOpen(with(open, null, "sessionKey")));

        EdgeResult step = w.open(key, w.request().resource("vault").build());
        assertEquals(step, WireFormat.readResult(WireFormat.result(step)));
        JObject res = WireFormat.result(step);
        assertThrows(JsonException.class, () -> WireFormat.readResult(with(res, null, "challenge")),
                "STEP_UP without a challenge breaks the invariant");
        assertThrows(JsonException.class, () -> WireFormat.readResult(with(res, JsonValue.str("SMOKE_SIGNAL"), "challenge")));
        JObject opened = WireFormat.result(w.open(key, w.request().build()));
        assertThrows(JsonException.class, () -> WireFormat.readResult(with(opened, JsonValue.str("bad"), "grant", "token")));
        assertThrows(JsonException.class, () -> WireFormat.readResult(with(opened, JsonValue.str("GRANTED"), "status")),
                "a grant with GRANTED breaks the invariant");
    }

    @Test
    void resultInvariantsHold() {
        Instant now = w.clock.now();
        EdgeGrant g = new EdgeGrant("s-1", TOKEN, now, now, false);
        assertThrows(IllegalArgumentException.class, () -> new EdgeResult(EdgeResult.Status.GRANTED, "r", "m", true,
                Optional.empty(), Optional.empty(), false), "restricted GRANTED");
        assertThrows(IllegalArgumentException.class, () -> new EdgeResult(EdgeResult.Status.DENIED, "r", "m", false,
                Optional.of(AuthMethod.WEBAUTHN), Optional.empty(), false), "challenge without STEP_UP");
        assertThrows(IllegalArgumentException.class, () -> new EdgeResult(EdgeResult.Status.DENIED, "r", "m", false,
                Optional.empty(), Optional.of(g), false), "grant without OPENED");
        assertThrows(IllegalArgumentException.class, () -> new EdgeGrant("s-1", "short", now, now, false));
        for (EdgeResult.Status st : EdgeResult.Status.values()) {
            assertFalse(EdgeResult.genericMessage(st, "r-1").isBlank());
        }
        assertTrue(EdgeResult.Status.OPENED.allowed() && EdgeResult.Status.GRANTED_LIMITED.allowed());
        assertFalse(EdgeResult.Status.STEP_UP.allowed() || EdgeResult.Status.REJECTED.allowed());
        assertEquals(g, new EdgeGrant("s-1", TOKEN, now, now, false));
        assertEquals(g.hashCode(), new EdgeGrant("s-1", TOKEN, now, now, false).hashCode());
        assertNotEquals(g, new EdgeGrant("s-2", TOKEN, now, now, false));
        assertFalse(g.toString().contains(TOKEN));
        assertEquals(201, EdgeHttp.status(w.open(key, w.request().build())));
        assertEquals(200, EdgeHttp.status(w.authority.decide(w.request().resource("web:general").build())));
        // R10: P-02 used to grant finance every CONFIDENTIAL+ resource of any kind, including web:malicious.
        assertEquals(403, EdgeHttp.status(w.authority.decide(w.request().resource("web:malicious").build())));
        assertEquals(403, EdgeHttp.status(w.authority.decide(w.request().resource("web:malicious")
                .mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1), key).build())), "not even after MFA");
    }

    @Test
    void malformedTokensAndProofHeadersAreRefused() {
        assertFalse(EdgeHttp.wellFormedToken(null));
        assertFalse(EdgeHttp.wellFormedToken("A".repeat(42) + "+"));
        assertFalse(EdgeHttp.wellFormedToken("A".repeat(42) + "="));
        assertFalse(EdgeHttp.wellFormedToken("A".repeat(42) + (char) 0xE9));
        assertTrue(EdgeHttp.wellFormedToken("z".repeat(21) + "-_" + "9".repeat(20)));
        assertTrue(EdgeHttp.proof("s-1", "a+b/c=", "2026-11-01T09:30:00Z").isPresent());
        assertTrue(EdgeHttp.proof("s-1", "", "2026-11-01T09:30:00Z").isEmpty());
        assertTrue(EdgeHttp.proof("s-1", "a".repeat(257), "2026-11-01T09:30:00Z").isEmpty());
        assertTrue(EdgeHttp.proof(null, "QUJD", "2026-11-01T09:30:00Z").isEmpty());
        assertTrue(EdgeHttp.proof("s-1", null, "2026-11-01T09:30:00Z").isEmpty());
        assertTrue(EdgeHttp.proof("s-1", "QUJD", "2026-11-01T09:30:00Z" + "0".repeat(30)).isEmpty());
        assertFalse(EdgeHttp.safeHeaderValue(null));
        assertFalse(EdgeHttp.safeHeaderValue("a" + (char) 0));
        assertFalse(EdgeHttp.clientOnly(null));
        assertTrue(EdgeHttp.action("PUT", false, false).orElseThrow() == Action.WRITE);
    }

    @Test
    void aSessionUseThatFailsInsideIsADeny() {
        EdgeGrant g = w.open(key, w.request().build()).grant().orElseThrow();
        LocalSessionAuthority noSignals = new LocalSessionAuthority(w.administrator, (req, sig) -> {
            throw new IllegalStateException("down");
        }, w.directory, () -> null, AuthMethod.WEBAUTHN, w.clock);
        EdgeRequest r = w.request().build();
        assertEquals(EdgeResult.Status.DENIED, noSignals.use(g.token(), ClientProofs.sign(key.getPrivate(), g.sessionId(), r,
                w.clock.now()), r).status());
        assertEquals(1, noSignals.internalFailures());
    }

    @Test
    void componentNamesAreValidated() {
        assertEquals("CN=gateway", TlsContexts.component("gateway").getName());
        assertThrows(IllegalArgumentException.class, () -> TlsContexts.component("gateway,O=evil"));
    }
}

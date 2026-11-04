package dev.dwarpal.edge;

import dev.dwarpal.Fixtures;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The contracts every Layer 4 part builds on: wire format, HTTP mapping, and the local authority. */
class EdgeContractTest {

    private final EdgeFixtures.World w = EdgeFixtures.world();
    private final KeyPair key = Ed25519.generateKeyPair();

    private static JsonValue reparse(JsonValue v) {
        return new JsonReader().read(JsonWriter.bytes(v));
    }

    // ---- wire format ----------------------------------------------------------------------------------

    @Test
    void requestsProofsAndBodiesRoundTripExactly() {
        EdgeRequest r = w.request().mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1), key).build();
        assertEquals(r, WireFormat.readRequest(reparse(WireFormat.request(r))));

        WireFormat.OpenBody open = new WireFormat.OpenBody(r, key.getPublic(), r.evidence().postureProof());
        WireFormat.OpenBody back = WireFormat.readOpen(reparse(WireFormat.open(open)));
        assertEquals(open.login(), back.login());
        assertEquals(open.deviceBinding(), back.deviceBinding());
        assertTrue(java.util.Arrays.equals(key.getPublic().getEncoded(), back.sessionKey().getEncoded()));

        SignatureProof p = ClientProofs.sign(key.getPrivate(), "s-1", r, w.clock.now());
        WireFormat.UseBody use = new WireFormat.UseBody("A".repeat(43), p, r);
        assertEquals(use, WireFormat.readUse(reparse(WireFormat.use(use))));
        assertFalse(use.toString().contains("A".repeat(43)), "the token never appears in toString");
        assertEquals(new WireFormat.DecideBody(r), WireFormat.readDecide(reparse(WireFormat.decide(new WireFormat.DecideBody(r)))));
    }

    @Test
    void resultsRoundTripAndHideAnalystDetail() {
        EdgeResult opened = w.open(key, w.request().build());
        assertEquals(EdgeResult.Status.OPENED, opened.status());
        String json = JsonWriter.write(WireFormat.result(opened));
        assertEquals(opened, WireFormat.readResult(new JsonReader().read(json)));
        for (String internal : Set.of("P-01", "policy", "P(attack)", "prior", "risk")) {
            assertFalse(json.contains(internal), "analyst detail must not cross the network: " + internal);
        }
        assertFalse(opened.toString().contains(opened.grant().orElseThrow().token()), "redacted in toString");
    }

    @Test
    void theSchemaIsStrict() {
        EdgeRequest r = w.request().build();
        JsonValue.JObject good = WireFormat.request(r);
        JsonValue.JObject.Builder extra = JsonValue.object();
        for (String k : good.keys()) {
            extra.put(k, good.get(k).orElseThrow());
        }
        extra.put("roles", JsonValue.str("admin"));
        assertThrows(JsonException.class, () -> WireFormat.readRequest(extra.build()),
                "an enforcement point cannot send roles, or anything else unknown");

        JsonValue.JObject.Builder missing = JsonValue.object();
        for (String k : good.keys()) {
            if (!k.equals("action")) {
                missing.put(k, good.get(k).orElseThrow());
            }
        }
        assertThrows(JsonException.class, () -> WireFormat.readRequest(missing.build()));

        JsonValue.JObject.Builder badAction = JsonValue.object();
        for (String k : good.keys()) {
            badAction.put(k, k.equals("action") ? JsonValue.str("read") : good.get(k).orElseThrow());
        }
        assertThrows(JsonException.class, () -> WireFormat.readRequest(badAction.build()), "enum names are exact");

        JsonValue.JObject.Builder badId = JsonValue.object();
        for (String k : good.keys()) {
            badId.put(k, k.equals("subjectId") ? JsonValue.str("alice" + (char) 0x0A + "admin") : good.get(k).orElseThrow());
        }
        JsonException e = assertThrows(JsonException.class, () -> WireFormat.readRequest(badId.build()));
        assertFalse(e.getMessage().contains("alice"), "errors never echo the input");

        assertThrows(JsonException.class, () -> WireFormat.readDecide(JsonValue.object().put("v", JsonValue.num(2))
                .put("request", good).build()), "unknown version");
        assertThrows(JsonException.class, () -> WireFormat.readRequest(JsonValue.str("x")));
    }

    @Test
    void onlyEd25519SessionKeysAreAccepted() throws Exception {
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(256);
        String ecKey = WireFormat.publicKey(ec.generateKeyPair().getPublic());
        assertThrows(JsonException.class, () -> WireFormat.readPublicKey(ecKey));
        assertThrows(JsonException.class, () -> WireFormat.readPublicKey("not base64!"));
        assertThrows(JsonException.class, () -> WireFormat.readPublicKey("AAAA"));
    }

    // ---- HTTP mapping -----------------------------------------------------------------------------------

    @Test
    void httpMappingIsOneTableForEveryEnforcementPoint() {
        assertEquals(Optional.of(Action.READ), EdgeHttp.action("GET", false, false));
        assertEquals(Optional.of(Action.READ), EdgeHttp.action("HEAD", false, false));
        assertEquals(Optional.of(Action.WRITE), EdgeHttp.action("DELETE", false, false));
        assertEquals(Optional.of(Action.DOWNLOAD), EdgeHttp.action("GET", true, false));
        assertEquals(Optional.of(Action.WRITE), EdgeHttp.action("POST", true, false), "uploading to a download route is a write");
        assertEquals(Optional.of(Action.ADMIN), EdgeHttp.action("GET", false, true));
        for (String odd : new String[]{"TRACE", "CONNECT", "OPTIONS", "get", "PROPFIND", null}) {
            assertTrue(EdgeHttp.action(odd, false, false).isEmpty(), "unknown methods have no action: " + odd);
        }
        assertEquals(401, EdgeHttp.status(new EdgeResult(EdgeResult.Status.STEP_UP, "r-1", "m", false,
                Optional.of(AuthMethod.WEBAUTHN), Optional.empty(), false)));
        assertEquals("Dwarpal challenge=" + (char) 0x22 + "WEBAUTHN" + (char) 0x22, EdgeHttp.challengeHeader(AuthMethod.WEBAUTHN));
    }

    @Test
    void headersAreParsedStrictly() {
        // Built from a short repeated pattern: a random-looking literal would (rightly) trip the secret scanner.
        String token = "Ab0-_".repeat(8) + "Ab0";
        assertEquals(Optional.of(token), EdgeHttp.bearerToken("Dwarpal " + token));
        assertTrue(EdgeHttp.bearerToken("Bearer " + token).isEmpty());
        assertTrue(EdgeHttp.bearerToken("Dwarpal  " + token).isEmpty(), "exactly one space");
        assertTrue(EdgeHttp.bearerToken("Dwarpal " + token + "x").isEmpty());
        assertTrue(EdgeHttp.bearerToken(null).isEmpty());

        assertTrue(EdgeHttp.proof("s-1", "QUJD", "2026-11-01T09:30:00Z").isPresent());
        assertTrue(EdgeHttp.proof("s-1", "QUJD", "yesterday").isEmpty());
        assertTrue(EdgeHttp.proof("s-1", "QU JD", "2026-11-01T09:30:00Z").isEmpty());
        assertTrue(EdgeHttp.proof("s 1", "QUJD", "2026-11-01T09:30:00Z").isEmpty());
        assertTrue(EdgeHttp.proof("s-1", "QUJD", null).isEmpty());

        assertFalse(EdgeHttp.safeHeaderValue("ok" + (char) 0x0D + (char) 0x0A + "Set-Cookie: x"), "response splitting");
        assertFalse(EdgeHttp.safeHeaderValue("a".repeat(EdgeHttp.MAX_HEADER_VALUE_LENGTH + 1)));
        assertTrue(EdgeHttp.safeHeaderValue("fine"));
        assertTrue(EdgeHttp.clientOnly("x-dwarpal-subject"), "header names are case-insensitive");
        assertTrue(EdgeHttp.clientOnly("AUTHORIZATION"));
        assertFalse(EdgeHttp.clientOnly("Accept"));
    }

    // ---- the local authority --------------------------------------------------------------------------------

    @Test
    void aSessionWorksEndToEndThroughTheContract() {
        EdgeGrant g = w.open(key, w.request().build()).grant().orElseThrow();
        assertEquals(EdgeResult.Status.GRANTED, w.use(key, g, w.request().build()).status());
        assertEquals(EdgeResult.Status.DENIED, w.use(key, g, w.request().action(Action.ADMIN)
                .mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1), key).build()).status(), "no standing admin");
        EdgeResult stolen = w.authority.use(g.token(), ClientProofs.sign(Ed25519.generateKeyPair().getPrivate(),
                g.sessionId(), w.request().build(), w.clock.now()), w.request().build());
        assertEquals(EdgeResult.Status.REJECTED, stolen.status());
    }

    @Test
    void threatSignalsComeFromTheEngineSideOnly() {
        EdgeGrant g = w.open(key, w.request().build()).grant().orElseThrow();
        w.signals.set(new SignalSnapshot(Set.of(), Set.of(), Set.of("laptop-alice"), Set.of()));
        EdgeResult r = w.use(key, g, w.request().build());
        assertEquals(EdgeResult.Status.DENIED, r.status());
        assertTrue(r.sessionEnded(), "a deny-listed device loses its session on the next request");
    }

    @Test
    void stepUpCarriesTheChallengeAndReadOnlyIsReported() {
        EdgeResult vault = w.open(key, w.request().resource("vault").build());
        assertEquals(EdgeResult.Status.STEP_UP, vault.status());
        assertEquals(Optional.of(AuthMethod.PUSH_NUMBER_MATCH), vault.challenge());

        EdgeResult phone = w.open(key, w.request().device("phone-alice").resource("drive").build());
        assertEquals(EdgeResult.Status.OPENED, phone.status());
        assertTrue(phone.restricted(), "unmanaged device on SaaS data: read-only");
        EdgeGrant g = phone.grant().orElseThrow();
        assertEquals(EdgeResult.Status.GRANTED_LIMITED, w.use(key, g, w.request().device("phone-alice").resource("drive").build()).status());
        assertEquals(EdgeResult.Status.DENIED, w.use(key, g, w.request().device("phone-alice").resource("drive")
                .action(Action.DOWNLOAD).build()).status());
    }

    @Test
    void singleDecisionsAreNotLearnedAndUnknownIdsAreRefused() {
        assertEquals(EdgeResult.Status.GRANTED, w.authority.decide(w.request().resource("web:general").build()).status());
        assertEquals(EdgeResult.Status.DENIED, w.authority.decide(w.request().resource("web:uncategorised").build()).status());
        assertEquals(EdgeResult.Status.DENIED, w.authority.decide(w.request().resource("no-such-thing").build()).status());
        assertEquals(EdgeResult.Status.DENIED, w.authority.decide(w.request().subject("mallory").build()).status());
        assertEquals(0, w.authority.internalFailures());
    }

    @Test
    void r8_singleDecisionsDatedAwayFromTheClockAreRefused() {
        // Red-team finding: the live-clock rule existed only inside sessions; a web decision dated 3 h ago was GRANTED.
        assertEquals(EdgeResult.Status.REJECTED, w.authority.decide(w.request().resource("web:general")
                .at(w.clock.now().minus(Duration.ofHours(3))).build()).status());
        assertEquals(EdgeResult.Status.REJECTED, w.authority.decide(w.request().resource("web:general")
                .at(w.clock.now().plus(Duration.ofMinutes(5))).build()).status());
        assertEquals(EdgeResult.Status.GRANTED, w.authority.decide(w.request().resource("web:general")
                .at(w.clock.now().minus(Duration.ofSeconds(90))).build()).status(), "within the 2 min allowance");
    }

    @Test
    void r9_everyHeaderInTheDwarpalNameSpacesIsStripped() {
        // Red-team finding: only the defined names were stripped, so an invented X-Dwarpal-Roles reached the app.
        for (String h : new String[]{"Dwarpal-Read-Only", "X-Dwarpal-Roles", "x-dwarpal-subject", "X_Dwarpal_Subject",
                "DWARPAL-ANYTHING", " Dwarpal-Session", "Authorization"}) {
            assertTrue(EdgeHttp.clientOnly(h), h);
        }
        for (String h : new String[]{"Accept", "Content-Type", "X-Request-Id", "Dwarpalx", "X-Dwarpalish"}) {
            assertFalse(EdgeHttp.clientOnly(h), h);
        }
        for (String h : EdgeHttp.CLIENT_ONLY_HEADERS) {
            assertTrue(EdgeHttp.clientOnly(h), h);
        }
    }

    @Test
    void internalFailuresAreDeniesNotExceptions() {
        LocalSessionAuthority broken = new LocalSessionAuthority(w.administrator, (req, sig) -> {
            throw new IllegalStateException("engine down");
        }, w.directory, () -> null, AuthMethod.WEBAUTHN, w.clock);
        assertEquals(EdgeResult.Status.DENIED, broken.decide(w.request().resource("web:general").build()).status());
        assertEquals(EdgeResult.Status.DENIED, broken.open(w.request().build(), key.getPublic(), Optional.empty()).status());
        assertEquals(2, broken.internalFailures());
        assertTrue(Fixtures.KEYRING != null);
    }
}

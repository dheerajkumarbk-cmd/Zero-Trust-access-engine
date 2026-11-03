package dev.dwarpal.api;

import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.edge.EdgeFixtures;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The administrative bodies: round trips, and every way a body can be wrong. */
class ApiBodiesTest {

    private static final Instant T = EdgeFixtures.T;
    private static final SignatureProof PROOF = new SignatureProof("k-1", T, "AAAA");
    private static final String THUMB = "a".repeat(64);

    private static JsonValue parse(String s) {
        return new JsonReader().read(s);
    }

    private static <T> T roundTrip(JsonValue written, Function<JsonValue, T> reader) {
        return reader.apply(parse(JsonWriter.write(written)));
    }

    @Test
    void everyBodyRoundTrips() {
        ApiBodies.RevokeBody r = new ApiBodies.RevokeBody(ApiBodies.Scope.DEVICE, "laptop-alice", "lost on a train");
        assertEquals(r, roundTrip(ApiBodies.revoke(r), ApiBodies::readRevoke));
        ApiBodies.ElevationBody e = new ApiBodies.ElevationBody("alice", "laptop-alice", "admin", Duration.ofMinutes(45),
                "INC-1: fix it", new AuthenticationContext(AuthMethod.WEBAUTHN, T, Optional.of(THUMB)), PROOF);
        assertEquals(e, roundTrip(ApiBodies.elevation(e), ApiBodies::readElevation));
        ApiBodies.ElevationBody unbound = new ApiBodies.ElevationBody("alice", "laptop-alice", "admin",
                Duration.ofMinutes(5), "INC-1: fix it", new AuthenticationContext(AuthMethod.TOTP, T), PROOF);
        assertEquals(unbound, roundTrip(ApiBodies.elevation(unbound), ApiBodies::readElevation));
        ApiBodies.ApprovalBody a = new ApiBodies.ApprovalBody("e-1", "bob", PROOF);
        assertEquals(a, roundTrip(ApiBodies.approval(a), ApiBodies::readApproval));
        ApiBodies.BreakGlassBody b = new ApiBodies.BreakGlassBody("bg-admin-1", "admin", "outage", PROOF);
        assertEquals(b, roundTrip(ApiBodies.breakGlass(b), ApiBodies::readBreakGlass));
        ApiBodies.ReviewBody v = new ApiBodies.ReviewBody("g-1", "bob", "misuse", PROOF);
        assertEquals(v, roundTrip(ApiBodies.review(v), ApiBodies::readReview));
        assertEquals("{\"ok\":false}", JsonWriter.write(ApiBodies.pamAnswer(false, Optional.of("leak"))),
                "a refusal never carries an id");
    }

    @Test
    void wrongRevocationsAreRefused() {
        List<String> bad = List.of("[]", "{}", "{\"v\":1,\"scope\":\"session\",\"id\":\"s\"}",
                "{\"v\":1,\"scope\":\"everyone\",\"id\":\"s\",\"reason\":\"r\"}",
                "{\"v\":2,\"scope\":\"session\",\"id\":\"s\",\"reason\":\"r\"}",
                "{\"v\":\"1\",\"scope\":\"session\",\"id\":\"s\",\"reason\":\"r\"}",
                "{\"v\":1,\"scope\":\"session\",\"id\":\"../x\",\"reason\":\"r\"}",
                "{\"v\":1,\"scope\":\"session\",\"id\":\"s\",\"reason\":\" \"}",
                "{\"v\":1,\"scope\":\"session\",\"id\":7,\"reason\":\"r\"}",
                "{\"v\":1,\"scope\":\"session\",\"id\":\"s\",\"reason\":\"" + "r".repeat(201) + "\"}",
                "{\"v\":1,\"scope\":\"session\",\"id\":\"s\",\"reason\":\"r\",\"all\":true}");
        for (String s : bad) {
            assertThrows(JsonException.class, () -> ApiBodies.readRevoke(parse(s)), s);
        }
    }

    @Test
    void wrongPrivilegedAccessBodiesAreRefused() {
        String auth = "{\"method\":\"WEBAUTHN\",\"authenticatedAt\":\"" + T + "\"}";
        String proof = "{\"keyId\":\"k\",\"signedAt\":\"" + T + "\",\"signature\":\"AAAA\"}";
        String good = "{\"v\":1,\"subjectId\":\"alice\",\"deviceId\":\"d\",\"role\":\"admin\",\"minutes\":30,"
                + "\"justification\":\"INC-1: fix it\",\"authentication\":" + auth + ",\"authenticationProof\":" + proof + "}";
        ApiBodies.readElevation(parse(good));
        List<String> bad = List.of(good.replace("30", "0"), good.replace("30", "481"), good.replace("30", "30.5"),
                good.replace("30", "\"30\""), good.replace("WEBAUTHN", "PASSKEY"),
                good.replace("\"" + T + "\"}", "\"yesterday\"}"),
                good.replace("\"authenticatedAt\"", "\"keyThumbprint\":\"xyz\",\"authenticatedAt\""),
                good.replace("\"authenticatedAt\"", "\"extra\":1,\"authenticatedAt\""),
                good.replace(auth, "[]"), good.replace("\"alice\"", "\"al ice\""));
        for (String s : bad) {
            assertThrows(JsonException.class, () -> ApiBodies.readElevation(parse(s)), s);
        }
        assertThrows(JsonException.class, () -> ApiBodies.readApproval(parse("{\"v\":1,\"requestId\":\"e\",\"approverId\":\"b\"}")));
        assertThrows(JsonException.class, () -> ApiBodies.readApproval(parse(
                "{\"v\":1,\"requestId\":\"e\",\"approverId\":\"b b\",\"approval\":" + proof + "}")));
        assertThrows(JsonException.class, () -> ApiBodies.readBreakGlass(parse(
                "{\"v\":1,\"accountId\":\"a\",\"role\":\"admin\",\"justification\":1,\"sealed\":" + proof + "}")));
        assertThrows(JsonException.class, () -> ApiBodies.readReview(parse(
                "{\"v\":1,\"grantId\":\"g\",\"reviewerId\":\"b\",\"verdict\":\"ok\",\"signed\":\"AAAA\"}")));
        assertThrows(JsonException.class, () -> ApiBodies.readReview(parse("1")));
    }

    @Test
    void messagesNeverEchoTheInput() {
        String secret = "s3cr3t-value-123";
        JsonException e = assertThrows(JsonException.class, () -> ApiBodies.readRevoke(parse(
                "{\"v\":1,\"scope\":\"" + secret + "\",\"id\":\"s\",\"reason\":\"r\"}")));
        assertFalse(e.getMessage().contains(secret));
        assertTrue(e.getMessage().contains("scope"));
    }
}

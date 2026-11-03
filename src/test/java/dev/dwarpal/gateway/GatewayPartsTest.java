package dev.dwarpal.gateway;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.edge.EdgeFixtures;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The gateway's building blocks on their own. */
class GatewayPartsTest {

    private static final URI APP = URI.create("http://127.0.0.1:9000");

    @Test
    void pathsHaveExactlyOneReading() {
        for (String ok : new String[]{"/", "/wiki", "/wiki/", "/wiki/pages/home", "/a/b~c/d.e-f_g", "/x/:@!$&'()*+,="}) {
            assertEquals(Optional.of(ok), RequestPath.path(ok), ok);
        }
        for (String bad : new String[]{null, "", "wiki", "/wiki//x", "/./x", "/x/..", "/x/%41", "/x;y", "/x\\y", "/x y",
            "/" + "a".repeat(RequestPath.MAX_PATH)}) {
            assertTrue(RequestPath.path(bad).isEmpty(), String.valueOf(bad));
        }
        assertEquals(Optional.of(""), RequestPath.query(null));
        assertEquals(Optional.of("a=1&b=%20"), RequestPath.query("a=1&b=%20"));
        assertTrue(RequestPath.query("a=%2").isEmpty());
        assertTrue(RequestPath.query("a=" + "x".repeat(RequestPath.MAX_QUERY)).isEmpty());
        assertTrue(RequestPath.under("/wiki/x", "/wiki"));
        assertTrue(RequestPath.under("/wiki", "/wiki"));
        assertFalse(RequestPath.under("/wikis", "/wiki"), "segment boundary");
    }

    @Test
    void routeTablesParseStrictlyAndClassifyActions() {
        RouteTable t = RouteTable.parse("# comment\n\nroute /wiki wiki http://127.0.0.1:9000\n"
                + "download /wiki/download\nadmin /wiki/admin\nroute /vault vault https://127.0.0.1:9443\n");
        assertEquals(2, t.routes().size());
        RouteTable.Route wiki = t.match("/wiki/pages/x").orElseThrow();
        assertEquals("wiki", wiki.resourceId());
        assertEquals(Optional.of(Action.READ), wiki.action("GET", "/wiki/pages/x"));
        assertEquals(Optional.of(Action.WRITE), wiki.action("PATCH", "/wiki/pages/x"));
        assertEquals(Optional.of(Action.DOWNLOAD), wiki.action("GET", "/wiki/download/x"));
        assertEquals(Optional.of(Action.ADMIN), wiki.action("DELETE", "/wiki/admin"));
        assertTrue(wiki.action("OPTIONS", "/wiki").isEmpty());
        assertTrue(t.match("/other").isEmpty());
        assertTrue(t.forResource("vault").isPresent());
        assertTrue(t.forResource("drive").isEmpty());

        for (String bad : new String[]{"", "route /wiki wiki", "download /wiki/x", "route /wiki wiki ftp://h:1",
            "route /wiki wiki http://h:1/path", "route /wiki wiki http://u@h:1", "route /wiki wiki http://h:1?q",
            "route / root http://h:1", "route /.dwarpal/x x http://h:1", "route /wiki/ wiki http://h:1",
            "route /wiki wiki http://h:1\ndownload /other", "frobnicate /x",
            "route /a a http://h:1\nroute /a/b b http://h:1", "route /a a http://h:1\nroute /b a http://h:1",
            "route /a a http:///nohost"}) {
            assertThrows(IllegalArgumentException.class, () -> RouteTable.parse(bad), bad);
        }
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> RouteTable.parse("route /wiki wiki http://h:1\nadmin secret-value"));
        assertFalse(e.getMessage().contains("secret-value"), "errors name the line, never the content");
        assertThrows(IllegalArgumentException.class, () -> RouteTable.parse("x".repeat(70_000)));
    }

    @Test
    void headersAreSortedIntoWhatCrossesAndWhatDoesNot() {
        Set<String> none = Set.of();
        assertTrue(HeaderPolicy.forwardRequest("Accept", none));
        assertTrue(HeaderPolicy.forwardRequest("Cookie", none));
        for (String n : new String[]{"Authorization", "X-Dwarpal-Subject", "x_dwarpal_subject", "Dwarpal-Proof", "Host",
            "Content-Length", "Transfer-Encoding", "Connection", "TE", "X-Forwarded-For", "X_Forwarded_For", "Forwarded",
            "bad name", null}) {
            assertFalse(HeaderPolicy.forwardRequest(n, none), String.valueOf(n));
        }
        assertFalse(HeaderPolicy.forwardRequest("X-Custom", Set.of("x-custom")), "named in Connection");
        assertEquals(Set.of("x-a", "x-b", "close"), HeaderPolicy.connectionListed(Map.of("Connection", List.of("close, X-A", "x_b"))));

        assertTrue(HeaderPolicy.forwardResponse("Content-Type", none));
        assertTrue(HeaderPolicy.forwardResponse("Set-Cookie", none));
        for (String n : new String[]{"Dwarpal-Read-Only", "X-Dwarpal-Subject", "WWW-Authenticate", "Content-Length",
            "Keep-Alive", null}) {
            assertFalse(HeaderPolicy.forwardResponse(n, none), String.valueOf(n));
        }
        assertTrue(HeaderPolicy.overridesMethod(Set.of("Accept", "X-Http-Method-Override")));
        assertFalse(HeaderPolicy.overridesMethod(Set.of("Accept")));
        assertTrue(HeaderPolicy.overridesMethodInQuery("a=1&_method=DELETE"));
        assertTrue(HeaderPolicy.overridesMethodInQuery("%5Fmethod=PUT"));
        assertFalse(HeaderPolicy.overridesMethodInQuery("my_method=1"));
    }

    @Test
    void responseUrlsToTheAppBecomeGatewayRelative() {
        assertEquals(Optional.of("/wiki/x?y=1"), HeaderPolicy.responseValue("Location", "http://127.0.0.1:9000/wiki/x?y=1", APP));
        assertEquals(Optional.of("/w"), HeaderPolicy.responseValue("Location", "http://localhost:9000/w", APP));
        assertEquals(Optional.of("/"), HeaderPolicy.responseValue("Content-Location", "http://127.0.0.1:9000", APP));
        assertEquals(Optional.of("/rel"), HeaderPolicy.responseValue("Location", "/rel", APP));
        assertEquals(Optional.of("https://idp.example/login"),
                HeaderPolicy.responseValue("Location", "https://idp.example/login", APP), "other hosts are left alone");
        assertEquals(Optional.of("http://127.0.0.1:9001/x"), HeaderPolicy.responseValue("Location", "http://127.0.0.1:9001/x", APP));
        assertEquals(Optional.of("/x"), HeaderPolicy.responseValue("Location", "http://127.0.0.1/x", URI.create("http://127.0.0.1")));
        assertEquals(Optional.of("https://127.0.0.1/x"),
                HeaderPolicy.responseValue("Location", "https://127.0.0.1/x", URI.create("http://127.0.0.1")), "other scheme port");
        assertTrue(HeaderPolicy.responseValue("Location", "http://bad host/", APP).isEmpty());
        assertTrue(HeaderPolicy.responseValue("X-A", "a" + (char) 0x0A + "b", APP).isEmpty());
        assertEquals(Optional.of("v"), HeaderPolicy.responseValue("X-A", "v", APP));
    }

    @Test
    void theEvidenceHeaderRoundTripsAndIsStrict() {
        DevicePosture p = new DevicePosture(true, false, true, AssuranceLevel.SELF_REPORTED);
        EdgeFixtures.World w = EdgeFixtures.world();
        Evidence ev = w.request().mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1), Ed25519.generateKeyPair()).build().evidence();
        ClientEvidence.Claims c = ClientEvidence.decode(ClientEvidence.encode(p, ev)).orElseThrow();
        assertEquals(p, c.posture());
        assertEquals(ev, c.evidence());

        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String extra = b64.encodeToString(JsonWriter.bytes(JsonValue.object().put("posture", JsonValue.object().build())
                .put("evidence", JsonValue.object().build()).put("roles", "admin").build()));
        assertTrue(ClientEvidence.decode(extra).isEmpty(), "unknown members");
        String badPosture = b64.encodeToString(JsonWriter.bytes(JsonValue.object().put("posture", JsonValue.object().build())
                .put("evidence", JsonValue.object().build()).build()));
        assertTrue(ClientEvidence.decode(badPosture).isEmpty());
        assertTrue(ClientEvidence.decode(b64.encodeToString("[1]".getBytes(StandardCharsets.UTF_8))).isEmpty());
        assertTrue(ClientEvidence.decode("%%%").isEmpty());
        assertTrue(ClientEvidence.decode(null).isEmpty());
        assertTrue(ClientEvidence.decode("a" + (char) 0x0A).isEmpty());
    }

    @Test
    void configurationRefusesUnsafeValuesAndHidesTheSecret() throws Exception {
        RouteTable t = RouteTable.parse("route /wiki wiki http://127.0.0.1:9000");
        byte[] secret = new byte[32];
        GatewayConfig c = GatewayConfig.builder(t, secret, EdgeFixtures.keyRing()).build();
        assertTrue(c.bindAddress().isLoopbackAddress(), "loopback by default");
        assertFalse(c.toString().contains("AAAA"));
        assertTrue(c.toString().contains("<redacted>"));
        byte[] out = c.upstreamSecret();
        out[0] = 9;
        assertEquals(0, c.upstreamSecret()[0], "a copy");
        assertTrue(c.tls().isEmpty());
        assertFalse(c.requireClientCertificate());
        assertEquals("gateway", c.pepRegion());
        assertEquals(Duration.ofSeconds(2), c.connectTimeout());
        assertThrows(IllegalArgumentException.class, () -> GatewayConfig.builder(t, new byte[31], EdgeFixtures.keyRing()).build());
        assertThrows(IllegalArgumentException.class, () -> GatewayConfig.builder(t, null, EdgeFixtures.keyRing()).build());
        assertThrows(IllegalArgumentException.class, () -> GatewayConfig.builder(t, secret, EdgeFixtures.keyRing()).port(70_000).build());
        assertThrows(IllegalArgumentException.class, () -> GatewayConfig.builder(t, secret, EdgeFixtures.keyRing()).port(-1).build());
        assertThrows(IllegalArgumentException.class, () -> GatewayConfig.builder(t, secret, EdgeFixtures.keyRing()).maxInFlight(0).build());
        assertThrows(IllegalArgumentException.class, () -> GatewayConfig.builder(t, secret, EdgeFixtures.keyRing()).pepRegion("a b").build());
        assertThrows(NullPointerException.class, () -> GatewayConfig.builder(t, secret, null).build());
    }

    @Test
    void networkComesFromATableKeyedByTheRealAddress() throws Exception {
        NetworkContext office = new NetworkContext("10.1.2.3", "AS1", "IN", 12.9, 77.6, 5);
        NetworkResolver r = NetworkResolver.fixed(Map.of("10.1.2.3", office), new NetworkContext("0.0.0.0", "AS0", "ZZ", 0, 0, 20_000));
        assertEquals(office, r.resolve(InetAddress.getByName("10.1.2.3")));
        NetworkContext other = r.resolve(InetAddress.getByName("192.0.2.7"));
        assertEquals("192.0.2.7", other.ip());
        assertEquals("ZZ", other.country());
        assertEquals("fe80:0:0:0:0:0:0:1", NetworkResolver.ip(InetAddress.getByName("fe80::1%1")), "scope id dropped");
        assertEquals("0:0:0:0:0:0:0:1", NetworkResolver.ip(InetAddress.getByName("::1")));
    }

    @Test
    void readBoundedStopsAtTheLimit() throws Exception {
        assertEquals(3, ZtnaGateway.readBounded(new ByteArrayInputStream(new byte[3]), 3).orElseThrow().length);
        assertTrue(ZtnaGateway.readBounded(new ByteArrayInputStream(new byte[20_000]), 10_000).isEmpty());
    }

    @Test
    void theSampleAppListensOnLoopbackOnly() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> SampleApp.start(InetAddress.getByName("0.0.0.0"), 0, new byte[32]));
        assertThrows(IllegalArgumentException.class, () -> SampleApp.start(InetAddress.getLoopbackAddress(), 0, new byte[8]));
    }
}

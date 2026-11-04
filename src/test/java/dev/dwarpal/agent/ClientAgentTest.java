package dev.dwarpal.agent;

import dev.dwarpal.Fixtures;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.devidp.DevIdentityProvider;
import dev.dwarpal.devidp.DevIdpServer;
import dev.dwarpal.devidp.IdentityProvider;
import dev.dwarpal.devidp.SoftwareAuthenticator;
import dev.dwarpal.devidp.UserFile;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.gateway.GatewayWorld;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The client agent against the identity provider over HTTP, and its command line. */
class ClientAgentTest {

    private GatewayWorld g;
    private DevIdpServer idpServer;
    private final HttpClient http = HttpClient.newBuilder().proxy(HttpClient.Builder.NO_PROXY).build();

    @BeforeEach
    void up() throws Exception {
        g = GatewayWorld.start();
        idpServer = DevIdpServer.start(g.idp, InetAddress.getLoopbackAddress(), 0);
    }

    @AfterEach
    void down() {
        idpServer.close();
        g.close();
        http.close();
    }

    private HttpIdentityProvider remoteIdp(URI base) {
        return new HttpIdentityProvider(base, http, Duration.ofSeconds(5));
    }

    private ClientAgent alice(IdentityProvider idp) {
        return ClientAgent.builder().gateway(g.gateway.uri()).routes(g.routes).identityProvider(idp).subject("alice")
                .password(() -> GatewayWorld.password("alice")).authenticator(g.authenticators.get("alice"))
                .device(g.aliceLaptop()).clock(g.w.clock).build();
    }

    @Test
    void theWholeFlowWorksWithTheIdentityProviderOverHttp() throws Exception {
        ClientAgent alice = alice(remoteIdp(idpServer.uri()));
        ClientAgent.Response r = alice.send("GET", "/wiki/pages/home", new byte[0]);
        assertEquals(200, r.status());
        assertTrue(r.result().isEmpty(), "a forwarded response carries no Dwarpal result");
        assertTrue(alice.sessionId("wiki").isPresent());
        assertTrue(r.toString().contains("200"));
        assertEquals(200, alice.send("GET", "/vault/secrets/x", new byte[0]).status());
        g.w.clock.advance(Duration.ofMinutes(16));
        assertEquals(200, alice.send("GET", "/vault/secrets/x", new byte[0]).status(), "step-up over HTTP");
        alice.forget("wiki");
        assertTrue(alice.sessionId("wiki").isEmpty());
        assertEquals(201, alice.login("wiki").status());
    }

    @Test
    void withoutTheIdentityProviderThereIsNoSession() throws Exception {
        ClientAgent alice = alice(remoteIdp(URI.create("http://127.0.0.1:1")));
        ClientAgent.Response r = alice.send("GET", "/wiki/pages/home", new byte[0]);
        assertEquals(401, r.status());
        assertTrue(r.result().isEmpty());
        assertEquals(0, g.gateway.trackedSessions());

        IdentityProvider refusesAssertion = new IdentityProvider() {
            @Override
            public java.util.Optional<dev.dwarpal.devidp.WebAuthn.Challenge> challenge(String s, String d, String t) {
                return java.util.Optional.of(new dev.dwarpal.devidp.WebAuthn.Challenge("ch-1", "A".repeat(43), "evil.example"));
            }

            @Override
            public java.util.Optional<MfaProof> authenticate(Attempt attempt) {
                throw new AssertionError("never reached: the authenticator refuses a foreign relying party");
            }
        };
        assertEquals(401, alice(refusesAssertion).login("wiki").status());
    }

    @Test
    void theAgentRefusesWhatTheGatewayWouldRefuse() {
        ClientAgent alice = alice(g.idp.forClient("127.0.0.1"));
        assertThrows(IllegalArgumentException.class, () -> alice.send("GET", "/wiki/../admin", new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> alice.send("GET", "/elsewhere", new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> alice.send("TRACE", "/wiki/pages/home", new byte[0]));
        assertThrows(NullPointerException.class, () -> ClientAgent.builder().build());
    }

    @Test
    void theIdentityProviderServerIsStrict() throws Exception {
        URI base = idpServer.uri();
        assertEquals(404, post(base.resolve("/v1/other"), "{}").statusCode());
        assertEquals(404, http.send(HttpRequest.newBuilder(base.resolve(DevIdpServer.CHALLENGE_PATH)).build(),
                HttpResponse.BodyHandlers.ofString()).statusCode());
        assertEquals(400, post(base.resolve(DevIdpServer.CHALLENGE_PATH), "{{").statusCode());
        assertEquals(400, post(base.resolve(DevIdpServer.CHALLENGE_PATH), "{\"subjectId\":\"a\"}").statusCode());
        assertEquals(400, post(base.resolve(DevIdpServer.CHALLENGE_PATH),
                "{\"subjectId\":\"a\",\"deviceId\":\"d\",\"keyThumbprint\":\"x\"}").statusCode());
        assertEquals(400, post(base.resolve(DevIdpServer.AUTHENTICATE_PATH), "{}").statusCode());
        assertEquals(413, post(base.resolve(DevIdpServer.AUTHENTICATE_PATH), "x".repeat(20_000)).statusCode());

        HttpIdentityProvider p = remoteIdp(base);
        String thumb = Digests.thumbprint(Ed25519.generateKeyPair().getPublic());
        dev.dwarpal.devidp.WebAuthn.Challenge c = p.challenge("alice", "laptop-alice", thumb).orElseThrow();
        dev.dwarpal.devidp.WebAuthn.Assertion a = g.authenticators.get("alice").assertion(c, true).orElseThrow();
        assertTrue(p.authenticate(new IdentityProvider.Attempt(c.challengeId(), "alice", "wrong", a)).isEmpty());
        HttpResponse<String> failed = post(base.resolve(DevIdpServer.AUTHENTICATE_PATH),
                dev.dwarpal.wire.JsonWriter.write(dev.dwarpal.devidp.IdpWire.attempt(
                        new IdentityProvider.Attempt(c.challengeId(), "alice", "wrong", a))));
        assertEquals(401, failed.statusCode());
        assertEquals("{\"error\":\"authentication failed\"}", failed.body(), "says nothing about which factor");
        assertThrows(IllegalArgumentException.class, () -> DevIdpServer.start(g.idp, InetAddress.getByName("0.0.0.0"), 0));
    }

    private HttpResponse<String> post(URI uri, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(uri).POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void theDeviceAgentSignsOnlyWhenItHasAKey() {
        DeviceAgent phone = DeviceAgent.unmanaged("phone-1", GatewayWorld.healthy());
        assertTrue(phone.evidence(g.w.clock.now()).postureProof().isEmpty());
        assertTrue(phone.bind(g.w.request().build(), Ed25519.generateKeyPair().getPublic(), g.w.clock.now()).isEmpty());
        assertFalse(phone.toString().contains("Private"));
        DeviceAgent laptop = g.aliceLaptop();
        laptop.measured(new DevicePosture(true, false, true, AssuranceLevel.AGENT_SIGNED));
        assertFalse(laptop.posture().diskEncrypted());
        assertEquals(AssuranceLevel.SELF_REPORTED, laptop.posture().assurance(), "the verifier decides assurance");
        assertTrue(laptop.evidence(g.w.clock.now()).postureProof().isPresent());
    }

    @Test
    void aDecryptedDiskLosesTheVault() throws Exception {
        DeviceAgent laptop = g.aliceLaptop();
        ClientAgent alice = ClientAgent.builder().gateway(g.gateway.uri()).routes(g.routes)
                .identityProvider(g.idp.forClient("127.0.0.1")).subject("alice")
                .password(() -> GatewayWorld.password("alice")).authenticator(g.authenticators.get("alice"))
                .device(laptop).clock(g.w.clock).build();
        assertEquals(200, alice.send("GET", "/vault/secrets/x", new byte[0]).status());
        laptop.measured(new DevicePosture(true, false, true, AssuranceLevel.SELF_REPORTED));
        ClientAgent.Response r = alice.send("GET", "/vault/secrets/x", new byte[0]);
        assertEquals(403, r.status(), "posture is re-judged on every request");
        assertEquals(EdgeResult.Status.DENIED, r.result().orElseThrow().status());
    }

    // ---- command line ---------------------------------------------------------------------------------

    private record Run(int code, String out, String err) {
    }

    private Run cli(String stdin, String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = AgentMain.run(args, new BufferedReader(new StringReader(stdin)),
                new PrintStream(out, true, StandardCharsets.UTF_8), new PrintStream(err, true, StandardCharsets.UTF_8),
                g.w.clock);
        return new Run(code, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    @Test
    void theCommandLineEnrolsAndMakesRequests(@TempDir Path dir) throws Exception {
        Path cred = dir.resolve("dave.authenticator");
        Run enrol = cli("dave-password\n", "enrol", "--user", "dave", "--rp-id", GatewayWorld.RP_ID,
                "--authenticator", cred.toString());
        assertEquals(0, enrol.code(), enrol.err());
        String userLine = enrol.out().strip();
        assertTrue(userLine.startsWith("dave " + UserFile.SCHEME + " " + UserFile.DEFAULT_ITERATIONS));
        assertFalse(userLine.contains("dave-password"));
        assertEquals(1, cli("x\n", "enrol", "--user", "dave", "--rp-id", "r", "--authenticator", cred.toString()).code(),
                "never overwrites a key file");

        // Dave's own identity provider (same signing key as the fixtures), served over HTTP.
        List<String> reports = new ArrayList<>();
        DevIdentityProvider daveIdp = new DevIdentityProvider(UserFile.parse(userLine), Fixtures.IDP, Fixtures.IDP_KEY_ID,
                GatewayWorld.RP_ID, g.w.clock, (r, p) -> reports.add(r.subjectId()));
        try (DevIdpServer s = DevIdpServer.start(daveIdp, InetAddress.getLoopbackAddress(), 0)) {
            Path routes = dir.resolve("routes.txt");
            StringBuilder table = new StringBuilder();
            for (var r : g.routes.routes()) {
                table.append("route ").append(r.prefix()).append(' ').append(r.resourceId()).append(' ')
                        .append(r.upstream()).append('\n');
                r.downloads().forEach(d -> table.append("download ").append(d).append('\n'));
                r.admin().forEach(a -> table.append("admin ").append(a).append('\n'));
            }
            Files.writeString(routes, table);
            String[] base = {"request", "--gateway", g.gateway.uri().toString(), "--idp", s.uri().toString(),
                "--routes", routes.toString(), "--user", "dave", "--device", "phone-dave", "--authenticator", cred.toString()};
            g.w.clock.advance(Duration.ofSeconds(2));
            Run unknown = cli("dave-password\n", concat(base, "GET", "/wiki/pages/home"));
            assertEquals(1, unknown.code(), "dave is not in the engine's directory: denied");
            assertTrue(unknown.out().startsWith("403"), unknown.out());

            Path body = dir.resolve("body.txt");
            Files.writeString(body, "x");
            g.w.clock.advance(Duration.ofSeconds(2));
            Run wrongPassword = cli("nope\n", concat(base, "--body", body.toString(), "PUT", "/wiki/pages/x"));
            assertEquals(1, wrongPassword.code());
            assertTrue(wrongPassword.out().startsWith("401"));
            assertEquals(List.of("dave"), reports);

            Path deviceKey = dir.resolve("phone.key");
            Run dk = cli("", "device-key", "--device", "phone-dave", "--key-id", "agent-phone-dave", "--out", deviceKey.toString());
            assertEquals(0, dk.code());
            assertTrue(dev.dwarpal.edge.WireFormat.readPublicKey(dk.out().strip()) != null);
            g.w.clock.advance(Duration.ofSeconds(2));
            Run untrusted = cli("dave-password\n", concat(base, "--device-key", deviceKey.toString(), "GET", "/wiki/pages/home"));
            assertEquals(1, untrusted.code(), "an agent key the engine does not trust cannot bind a session");
            assertTrue(untrusted.out().startsWith("403"), untrusted.out());
            Run mismatch = cli("dave-password\n", "request", "--gateway", "http://x", "--idp", "http://x", "--routes",
                    routes.toString(), "--user", "dave", "--device", "other", "--authenticator", cred.toString(),
                    "--device-key", deviceKey.toString(), "GET", "/wiki/pages/home");
            assertEquals(1, mismatch.code());
            assertTrue(mismatch.err().contains("another device"));
            Run notAuth = cli("p\n", concat(new String[]{"request", "--gateway", "http://x", "--idp", "http://x",
                "--routes", routes.toString(), "--user", "dave", "--device", "d", "--authenticator", deviceKey.toString()},
                    "GET", "/wiki/pages/home"));
            assertEquals(1, notAuth.code());
            assertTrue(notAuth.err().contains("not a authenticator key file"));
        }
    }

    @Test
    void theCommandLineRefusesBadInvocations(@TempDir Path dir) throws Exception {
        assertEquals(2, cli("").code());
        assertEquals(2, cli("", "launch").code());
        assertTrue(cli("", "enrol").err().contains("missing --user"));
        assertEquals(1, cli("", "request", "GET").code());
        Path bad = dir.resolve("bad.authenticator");
        Files.writeString(bad, "type=authenticator\nrpId=r\nid=c\n");
        Path routes = dir.resolve("r.txt");
        Files.writeString(routes, "route /wiki wiki http://127.0.0.1:1\n");
        Run broken = cli("p\n", "request", "--gateway", "http://x", "--idp", "http://x", "--routes", routes.toString(),
                "--user", "u", "--device", "d", "--authenticator", bad.toString(), "GET", "/wiki");
        assertEquals(1, broken.code());
        assertTrue(broken.err().contains("key file is invalid"));
        Files.writeString(bad, "type=authenticator\nrpId=r\nid=c\npublicKey=AAAA\nprivateKey=AAAA\n");
        assertTrue(cli("p\n", "request", "--gateway", "http://x", "--idp", "http://x", "--routes", routes.toString(),
                "--user", "u", "--device", "d", "--authenticator", bad.toString(), "GET", "/wiki").err()
                .contains("key file is invalid"));
        Path big = dir.resolve("big.authenticator");
        Files.writeString(big, "#".repeat(20_000));
        assertTrue(cli("p\n", "request", "--gateway", "http://x", "--idp", "http://x", "--routes", routes.toString(),
                "--user", "u", "--device", "d", "--authenticator", big.toString(), "GET", "/wiki").err().contains("too large"));
        Path cred = dir.resolve("c.authenticator");
        assertEquals(0, cli("pw\n", "enrol", "--user", "u", "--rp-id", "r", "--authenticator", cred.toString()).code());
        assertTrue(cli("", "request", "--gateway", "http://x", "--idp", "http://x", "--routes", routes.toString(),
                "--user", "u", "--device", "d", "--authenticator", cred.toString(), "GET", "/wiki").err()
                .contains("no password"));
        assertTrue(cli("", "enrol", "--user", "u", "--rp-id", "r", "--authenticator", dir.resolve("n.a").toString())
                .err().contains("no password"));
    }

    private static String[] concat(String[] a, String... b) {
        String[] out = new String[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    @Test
    void softwareAuthenticatorsAreScopedToOneRelyingParty() {
        SoftwareAuthenticator a = SoftwareAuthenticator.register("rp.example");
        assertEquals("rp.example", a.rpId());
        assertTrue(a.credentialId().startsWith("cred-"));
    }
}

package dev.dwarpal.integration;

import dev.dwarpal.Fixtures;
import dev.dwarpal.agent.ClientAgent;
import dev.dwarpal.api.RemoteSessionAuthority;
import dev.dwarpal.casb.DataGuard;
import dev.dwarpal.casb.DlpPolicy;
import dev.dwarpal.casb.GuardResult;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.edge.ClientProofs;
import dev.dwarpal.edge.EdgeGrant;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.gateway.GatewayWorld;
import dev.dwarpal.gateway.SampleApp;
import dev.dwarpal.swg.CategoryMap;
import dev.dwarpal.swg.DomainList;
import dev.dwarpal.swg.IdentityResolver;
import dev.dwarpal.swg.WebAccess;
import dev.dwarpal.swg.WebFilter;
import dev.dwarpal.swg.WebGateway;
import dev.dwarpal.swg.WebIdentity;
import dev.dwarpal.swg.WebPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Layer 4 end to end: every enforcement point decides through the API over mutual TLS, never in process.
 * Client agent to ZTNA gateway to API to PA and engine; browser traffic through the web gateway; SaaS
 * uploads through the data guard; the SOC's revocation; and the API going away.
 */
class EndToEndTest {

    private E2eWorld e;

    @BeforeEach
    void up() {
        e = new E2eWorld();
    }

    @AfterEach
    void down() {
        e.close();
    }

    private GatewayWorld ztna() throws IOException {
        return e.keep(GatewayWorld.start(e.w, b -> { }, local -> e.remote("gateway")));
    }

    private long apiCalls(String caller, String endpoint) {
        return e.w.sink.snapshot().stream().filter(r -> r.type().equals("API_CALL")
                && r.payloadJson().contains("\"caller\":\"" + caller + "\"")
                && r.payloadJson().contains("\"endpoint\":\"" + endpoint + "\"")).count();
    }

    @Test
    void aliceUsesTheWikiThroughTheGatewayAndEveryDecisionCrossesTheApi() throws Exception {
        GatewayWorld g = ztna();
        ClientAgent alice = g.alice();
        ClientAgent.Response read = alice.send("GET", "/wiki/pages/home", new byte[0]);
        assertEquals(200, read.status());
        assertEquals("Welcome to the wiki.", read.text());
        assertEquals(200, alice.send("PUT", "/wiki/pages/notes", "hello".getBytes(StandardCharsets.UTF_8)).status());
        assertEquals(Optional.of("hello"), g.app.page("notes"));

        assertEquals(1, apiCalls("gateway", "/v1/sessions"), "the login went over the API");
        assertEquals(2, apiCalls("gateway", "/v1/sessions/use"), "and each request too");
        assertEquals(1, e.w.audited("SESSION_OPENED"), "opened by the PA only after verified MFA");
        for (SampleApp.Seen s : g.app.seen()) {
            assertEquals("alice", s.subject());
            assertTrue(SampleApp.clientOnlyNames(s).isEmpty());
        }
    }

    @Test
    void theSocRevokesAliceOverTheApiAndTheGatewayStopsAtTheNextRequest() throws Exception {
        GatewayWorld g = ztna();
        ClientAgent alice = g.alice();
        assertEquals(200, alice.send("GET", "/wiki/pages/home", new byte[0]).status());

        HttpClient soc = HttpClient.newBuilder().sslContext(E2eWorld.ctx("soc"))
                .sslParameters(TlsContexts.clientParameters(E2eWorld.ctx("soc"))).proxy(HttpClient.Builder.NO_PROXY).build();
        HttpResponse<String> revoked = soc.send(HttpRequest.newBuilder(e.base.resolve("/v1/sessions/revoke"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"v\":1,\"scope\":\"subject\",\"id\":\"alice\",\"reason\":\"SOC ticket 5: phished\"}"))
                .build(), HttpResponse.BodyHandlers.ofString());
        soc.close();
        assertEquals("{\"revoked\":1,\"elevations\":0}", revoked.body());

        assertEquals(403, alice.send("GET", "/wiki/pages/home", new byte[0]).status(), "the next request is refused");
        assertTrue(e.w.sink.snapshot().stream().anyMatch(r -> r.type().equals("SESSION_REVOKED")
                && r.actor().equals("api/soc")));
    }

    @Test
    void whenTheApiIsGoneTheGatewayDenies() throws Exception {
        GatewayWorld g = ztna();
        ClientAgent alice = g.alice();
        assertEquals(200, alice.send("GET", "/wiki/pages/home", new byte[0]).status());
        int before = g.app.seen().size();
        e.api.close();
        assertEquals(403, alice.send("GET", "/wiki/pages/home", new byte[0]).status(), "fail-closed, not fail-open");
        assertEquals(before, g.app.seen().size(), "nothing reached the app");
    }

    @Test
    void browserTunnelsThroughTheWebGatewayAreDecidedOverTheApi() throws Exception {
        try (ServerSocket echo = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            Thread.ofVirtual().start(() -> echoOnce(echo));
            WebPolicy policy = WebPolicy.builder().category("news", "web:general").category("gambling", WebPolicy.MALICIOUS)
                    .tunnelPorts(Set.of(echo.getLocalPort())).allowInternalAddresses(Set.of("127.0.0.1")).build();
            WebFilter filter = new WebFilter(policy, () -> DomainList.parse("evil.example\n"),
                    () -> CategoryMap.parse("news.example news\ngambling.example gambling\n"));
            WebAccess access = new WebAccess(filter, e.remote("swg"), "mumbai", e.w.clock);
            EdgeRequest r = e.w.request().resource("web:general").build();
            WebIdentity alice = new WebIdentity(r.subjectId(), r.deviceId(), r.claimedPosture(), r.evidence(), r.network());
            WebGateway swg = e.keep(new WebGateway(access,
                    IdentityResolver.fixed(Map.of(InetAddress.getLoopbackAddress(), alice)),
                    host -> List.of(InetAddress.getLoopbackAddress()), WebGateway.Settings.defaults()));
            swg.start(new ServerSocket(0, 50, InetAddress.getLoopbackAddress()));

            try (Socket c = new Socket(InetAddress.getLoopbackAddress(), swg.port())) {
                c.setSoTimeout(5000);
                c.getOutputStream().write(("CONNECT news.example:" + echo.getLocalPort() + " HTTP/1.1\r\n\r\nping")
                        .getBytes(StandardCharsets.US_ASCII));
                InputStream in = c.getInputStream();
                String head = head(in);
                assertTrue(head.startsWith("HTTP/1.1 200"), head);
                assertEquals("ping", new String(in.readNBytes(4), StandardCharsets.US_ASCII));
            }
            for (String blocked : List.of("gambling.example", "evil.example", "unknown.example")) {
                try (Socket c = new Socket(InetAddress.getLoopbackAddress(), swg.port())) {
                    c.setSoTimeout(5000);
                    c.getOutputStream().write(("CONNECT " + blocked + ":" + echo.getLocalPort() + " HTTP/1.1\r\n\r\n")
                            .getBytes(StandardCharsets.US_ASCII));
                    String head = head(c.getInputStream());
                    assertTrue(head.startsWith("HTTP/1.1 4"), blocked + " -> " + head);
                }
            }
            assertTrue(apiCalls("swg", "/v1/decisions") >= 3, "the engine decided over the API, blocked hosts included");
        }
    }

    @Test
    void uploadsToSaasDataAreCheckedOverTheApiAndInspected() {
        RemoteSessionAuthority casb = e.remote("casb");
        KeyPair key = dev.dwarpal.crypto.Ed25519.generateKeyPair();
        EdgeRequest login = e.w.request().resource("drive").mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1), key).build();
        EdgeResult opened = casb.open(login, key.getPublic(), Optional.of(ClientProofs.bindDevice(
                Fixtures.DEVICE_AGENT.getPrivate(), Fixtures.DEVICE_KEY_ID, login, key.getPublic(), e.w.clock.now())));
        assertEquals(EdgeResult.Status.OPENED, opened.status());
        EdgeGrant grant = opened.grant().orElseThrow();
        DataGuard guard = new DataGuard(casb, id -> e.w.directory.resource(id).map(Resource::classification),
                DlpPolicy.defaults(), e.w.audit, e.w.clock);

        assertEquals(GuardResult.Verdict.ALLOWED, upload(guard, key, grant, "quarterly notes, nothing sensitive").verdict());
        GuardResult card = upload(guard, key, grant, "paid with 4111 1111 1111 1111, thanks");
        assertEquals(GuardResult.Verdict.REFUSED, card.verdict());
        assertEquals(GuardResult.Reason.SENSITIVE_DATA, card.reason());
        assertEquals(2, apiCalls("casb", "/v1/sessions/use"), "both uploads were decided over the API first");
        assertFalse(e.w.sink.snapshot().stream().anyMatch(r -> r.payloadJson().contains("4111")), "no value in the trail");
    }

    private GuardResult upload(DataGuard guard, KeyPair key, EdgeGrant grant, String text) {
        EdgeRequest r = e.w.request().resource("drive").action(Action.WRITE).build();
        return guard.upload(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), r, e.w.clock.now()), r,
                text.getBytes(StandardCharsets.UTF_8));
    }

    private static void echoOnce(ServerSocket server) {
        try (Socket s = server.accept()) {
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            byte[] buf = new byte[4];
            int n = in.readNBytes(buf, 0, 4);
            out.write(buf, 0, n);
            out.flush();
        } catch (IOException ignored) {
            // the test is over
        }
    }

    private static String head(InputStream in) throws IOException {
        StringBuilder b = new StringBuilder();
        while (!b.toString().endsWith("\r\n\r\n")) {
            int c = in.read();
            if (c < 0) {
                break;
            }
            b.append((char) c);
        }
        return b.toString();
    }
}

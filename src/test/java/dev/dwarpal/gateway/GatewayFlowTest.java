package dev.dwarpal.gateway;

import dev.dwarpal.agent.ClientAgent;
import dev.dwarpal.agent.DeviceAgent;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.edge.EdgeHttp;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The whole path on real sockets: agent, identity provider, gateway, Dwarpal, sample app. */
class GatewayFlowTest {

    private GatewayWorld g;

    @BeforeEach
    void up() throws Exception {
        g = GatewayWorld.start();
    }

    @AfterEach
    void down() {
        g.close();
    }

    private static byte[] text(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void aliceReadsEditsAndDownloadsTheWiki() throws Exception {
        ClientAgent alice = g.alice();
        ClientAgent.Response read = alice.send("GET", "/wiki/pages/home", new byte[0]);
        assertEquals(200, read.status());
        assertEquals("Welcome to the wiki.", read.text());
        assertFalse(read.readOnly());

        assertEquals(200, alice.send("PUT", "/wiki/pages/notes", text("hello")).status());
        assertEquals(Optional.of("hello"), g.app.page("notes"));

        ClientAgent.Response dl = alice.send("GET", "/wiki/download/notes", new byte[0]);
        assertEquals(200, dl.status());
        assertTrue(dl.headers().firstValue("Content-Disposition").orElseThrow().startsWith("attachment"));

        assertEquals(200, alice.send("HEAD", "/wiki/pages/home", new byte[0]).status());
        assertEquals(404, alice.send("GET", "/wiki/pages/nothing-here", new byte[0]).status(), "app answers pass through");
        assertEquals(200, alice.send("DELETE", "/wiki/pages/notes", new byte[0]).status());
        assertEquals(200, alice.send("GET", "/wiki/pages/home?view=raw&x=%20", new byte[0]).status());

        for (SampleApp.Seen s : g.app.seen()) {
            assertEquals("alice", s.subject(), "the subject comes from the session");
            assertTrue(SampleApp.clientOnlyNames(s).isEmpty(), "the app never sees the client's Dwarpal headers");
            assertFalse(s.headerNames().contains("authorization"));
        }
        assertEquals(1, g.gateway.trackedSessions(), "one session for the wiki, reused");
        assertTrue(g.gateway.stats().forwarded() >= 7);
        assertTrue(g.w.audited("SESSION_OPENED") >= 1);
    }

    @Test
    void administrationIsRefusedWithoutJustInTimeElevation() throws Exception {
        ClientAgent alice = g.alice();
        ClientAgent.Response admin = alice.send("POST", "/wiki/admin/settings", text("theme=dark"));
        assertEquals(403, admin.status());
        assertEquals(EdgeResult.Status.DENIED, admin.result().orElseThrow().status());
        assertEquals("theme=light", g.app.settings(), "the app never saw the request");
        assertEquals(200, alice.send("GET", "/wiki/pages/home", new byte[0]).status(), "a refused WRITE-or-ADMIN keeps the session");
    }

    @Test
    void restrictedVaultNeedsFreshStrongAuthenticationAndTheAgentStepsUp() throws Exception {
        ClientAgent alice = g.alice();
        ClientAgent.Response first = alice.send("GET", "/vault/secrets/db", new byte[0]);
        assertEquals(200, first.status(), "WebAuthn at login satisfies the restricted resource");
        assertEquals("secret db for alice", first.text());
        long before = g.idp.succeeded();

        g.w.clock.advance(Duration.ofMinutes(16));
        ClientAgent.Response later = alice.send("GET", "/vault/secrets/db", new byte[0]);
        assertEquals(200, later.status(), "after 15 min the gateway asks for step-up; the agent re-authenticates");
        assertEquals(before + 1, g.idp.succeeded(), "exactly one fresh WebAuthn");
    }

    @Test
    void stepUpIsAnsweredWith401AndAChallenge() throws Exception {
        GatewayWorld.RawSession s = g.rawLogin("alice", "laptop-alice", "vault", true, e -> e);
        assertEquals(201, s.status());
        g.w.clock.advance(Duration.ofMinutes(16));
        HttpResponse<String> r = g.send(g.signed(s, s.key(), "GET", "/vault/secrets/db",
                dev.dwarpal.domain.Action.READ, "vault", g.newId()));
        assertEquals(401, r.statusCode());
        assertEquals(Optional.of(EdgeHttp.challengeHeader(AuthMethod.PUSH_NUMBER_MATCH)),
                r.headers().firstValue(EdgeHttp.CHALLENGE));
        assertFalse(r.body().contains("risk") || r.body().contains("P-0"), "no analyst detail");
    }

    @Test
    void unmanagedDeviceGetsReadOnlySaasAndTheAppIsToldNothingElse() throws Exception {
        ClientAgent carol = g.agent("carol", DeviceAgent.unmanaged("phone-carol", GatewayWorld.healthy()));
        ClientAgent.Response read = carol.send("GET", "/drive/files/report", new byte[0]);
        assertEquals(404, read.status(), "forwarded (the sample app has no drive files)");
        assertTrue(read.readOnly(), "the client is told the session is read-only");
        ClientAgent.Response write = carol.send("PUT", "/drive/files/report", text("x"));
        assertEquals(403, write.status());
        assertEquals(200, carol.send("GET", "/wiki/pages/home", new byte[0]).status());
    }

    @Test
    void aDenyListedDeviceIsCutOffOnTheNextRequest() throws Exception {
        ClientAgent alice = g.alice();
        assertEquals(200, alice.send("GET", "/wiki/pages/home", new byte[0]).status());
        g.w.signals.set(new SignalSnapshot(Set.of(), Set.of(), Set.of("laptop-alice"), Set.of()));
        ClientAgent.Response r = alice.send("GET", "/wiki/pages/home", new byte[0]);
        assertEquals(403, r.status());
        assertTrue(r.result().orElseThrow().sessionEnded());
        assertTrue(alice.sessionId("wiki").isEmpty(), "the agent drops an ended session");
        assertEquals(0, g.gateway.trackedSessions(), "so does the gateway");
    }

    @Test
    void theIdentityProviderReportsFailedLoginsAndNothingOpens() throws Exception {
        ClientAgent wrong = ClientAgent.builder().gateway(g.gateway.uri()).routes(g.routes)
                .identityProvider(g.idp.forClient("127.0.0.1")).subject("alice")
                .password("not-her-password"::toCharArray).authenticator(g.authenticators.get("alice"))
                .device(g.aliceLaptop()).clock(g.w.clock).build();
        ClientAgent.Response r = wrong.send("GET", "/wiki/pages/home", new byte[0]);
        assertEquals(401, r.status());
        assertEquals(1, g.failureReports.size());
        assertEquals("alice", g.failureReports.get(0).subjectId());
        assertEquals(0, g.gateway.trackedSessions());
    }

    @Test
    void theNetworkComesFromTheSocketNotFromHeaders() throws Exception {
        ClientAgent alice = g.alice();
        g.resolved.clear();
        alice.send("GET", "/wiki/pages/home", new byte[0], java.util.Map.of("X-Forwarded-For", "8.8.8.8",
                "Forwarded", "for=8.8.8.8"));
        assertFalse(g.resolved.isEmpty());
        for (java.net.InetAddress a : g.resolved) {
            assertTrue(a.isLoopbackAddress());
        }
        SampleApp.Seen last = g.app.seen().getLast();
        assertTrue(last.headerNames().contains("x-forwarded-for"), "the gateway sets its own");
        assertFalse(last.headerNames().contains("forwarded"));
    }

    @Test
    void manyClientsInParallelAreAllServed() throws Exception {
        List<Integer> statuses = Collections.synchronizedList(new ArrayList<>());
        ClientAgent alice = g.alice();
        alice.send("GET", "/wiki/pages/home", new byte[0]);
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            threads.add(Thread.ofVirtual().start(() -> {
                try {
                    statuses.add(alice.send("GET", "/wiki/pages/home", new byte[0]).status());
                } catch (Exception e) {
                    statuses.add(-1);
                }
            }));
        }
        for (Thread t : threads) {
            t.join();
        }
        assertEquals(40, statuses.size());
        assertTrue(statuses.stream().allMatch(s -> s == 200), statuses.toString());
    }

    @Test
    void theSampleAppTrustsOnlyTheGateway() throws Exception {
        HttpResponse<String> none = g.http.send(HttpRequest.newBuilder(g.app.uri().resolve("/wiki/pages/home"))
                .header(EdgeHttp.UPSTREAM_SUBJECT, "alice").build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(401, none.statusCode(), "no gateway secret");
        HttpResponse<String> wrong = g.http.send(HttpRequest.newBuilder(g.app.uri().resolve("/wiki/pages/home"))
                .header(ZtnaGateway.UPSTREAM_GATEWAY, Base64.getEncoder().encodeToString(new byte[32]))
                .header(EdgeHttp.UPSTREAM_SUBJECT, "alice").build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(401, wrong.statusCode(), "wrong gateway secret");
        HttpResponse<String> noSubject = g.http.send(HttpRequest.newBuilder(g.app.uri().resolve("/wiki/pages/home"))
                .header(ZtnaGateway.UPSTREAM_GATEWAY, Base64.getEncoder().encodeToString(g.secret)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(401, noSubject.statusCode(), "no subject");
        assertTrue(g.app.uri().getHost().startsWith("127."), "loopback only");
    }
}

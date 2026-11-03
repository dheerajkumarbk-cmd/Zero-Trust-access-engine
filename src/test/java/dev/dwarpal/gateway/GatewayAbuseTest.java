package dev.dwarpal.gateway;

import dev.dwarpal.agent.ClientAgent;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.Action;
import dev.dwarpal.edge.EdgeHttp;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.SessionAuthority;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Abuse cases from the plan, each against the running gateway. */
class GatewayAbuseTest {

    private GatewayWorld g;

    @AfterEach
    void down() {
        if (g != null) {
            g.close();
        }
    }

    private GatewayWorld.RawSession aliceWiki() throws Exception {
        GatewayWorld.RawSession s = g.rawLogin("alice", "laptop-alice", "wiki", true, e -> e);
        assertEquals(201, s.status());
        return s;
    }

    private HttpResponse<String> read(GatewayWorld.RawSession s) throws Exception {
        return g.send(g.signed(s, s.key(), "GET", "/wiki/pages/home", Action.READ, "wiki", g.newId()));
    }

    @Test
    void aStolenTokenIsUselessFromAnotherClient() throws Exception {
        g = GatewayWorld.start();
        GatewayWorld.RawSession s = aliceWiki();
        HttpResponse<String> thief = g.send(g.signed(s, Ed25519.generateKeyPair(), "GET", "/wiki/pages/home",
                Action.READ, "wiki", g.newId()));
        assertEquals(403, thief.statusCode());
        assertTrue(thief.body().contains("REJECTED"));
        assertEquals(200, read(s).statusCode(), "the owner's session goes on");
    }

    @Test
    void aReplayedRequestIsRefused() throws Exception {
        g = GatewayWorld.start();
        GatewayWorld.RawSession s = aliceWiki();
        HttpRequest once = g.signed(s, s.key(), "GET", "/wiki/pages/home", Action.READ, "wiki", "replay-1").build();
        assertEquals(200, g.http.send(once, HttpResponse.BodyHandlers.ofString()).statusCode());
        assertEquals(403, g.http.send(once, HttpResponse.BodyHandlers.ofString()).statusCode());
        assertEquals(1, g.app.seen().size(), "the app saw it once");
    }

    @Test
    void aReadProofCannotBeSpentOnAWrite() throws Exception {
        g = GatewayWorld.start();
        GatewayWorld.RawSession s = aliceWiki();
        HttpRequest.Builder b = g.signed(s, s.key(), "PUT", "/wiki/pages/home", Action.READ, "wiki", g.newId());
        assertEquals(403, g.send(b.PUT(HttpRequest.BodyPublishers.ofString("defaced"))).statusCode());
        assertEquals(Optional.of("Welcome to the wiki."), g.app.page("home"));
    }

    @Test
    void injectedIdentityHeadersNeverReachTheApp() throws Exception {
        g = GatewayWorld.start();
        ClientAgent alice = g.alice();
        Map<String, String> evil = Map.of("X-Dwarpal-Subject", "bob", "X_Dwarpal_Subject", "bob",
                "X-Dwarpal-Roles", "admin", "Dwarpal-Anything", "x", "X-Dwarpal-Gateway", "guess",
                "X-Real-IP", "8.8.8.8");
        assertEquals(200, alice.send("GET", "/wiki/pages/home", new byte[0], evil).status());
        SampleApp.Seen seen = g.app.seen().getLast();
        assertEquals("alice", seen.subject());
        assertTrue(SampleApp.clientOnlyNames(seen).isEmpty(), seen.headerNames().toString());
        assertFalse(seen.headerNames().contains("x_dwarpal_subject"));
        assertFalse(seen.headerNames().contains("x-real-ip"));

        GatewayWorld.RawSession s = aliceWiki();
        String crlf = "\r\n";
        StringBuilder head = new StringBuilder("GET /wiki/pages/home HTTP/1.1" + crlf + "Host: x" + crlf);
        g.signed(s, s.key(), "GET", "/wiki/pages/home", Action.READ, "wiki", g.newId()).build().headers().map()
                .forEach((k, v) -> head.append(k).append(": ").append(v.get(0)).append(crlf));
        head.append("Connection: close, X-Secret-Hop").append(crlf).append("X-Secret-Hop: 1").append(crlf)
                .append("Keep-Alive: 5").append(crlf).append(crlf);
        assertTrue(g.rawStatus(head.toString(), new byte[0]).startsWith("HTTP/1.1 200"));
        Set<String> names = g.app.seen().getLast().headerNames();
        assertFalse(names.contains("x-secret-hop"), "headers named in Connection are hop-by-hop: " + names);
        assertFalse(names.contains("keep-alive"));
    }

    @Test
    void pathTricksAreRefusedBeforeAnyDecision() throws Exception {
        g = GatewayWorld.start();
        String[] tricks = {"/wiki/../wiki/admin/settings", "/wiki/%2e%2e/admin/settings", "/wiki/pages%2Fhome",
            "/wiki/pages/%252e%252e/admin", "//wiki/pages/home", "/wiki/./pages/home", "/wiki/pages;x=1/home",
            "/wiki/pages/home%00", "/wiki/pages/%c0%ae%c0%ae", "/wiki/pages/h%6fme", "/wiki/pages/home?a=%zz",
            "/wiki/pages/home?a=<x>", "/wiki/pages/" + "a".repeat(RequestPath.MAX_PATH)};
        for (String t : tricks) {
            String status = g.rawStatus("GET " + t + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", new byte[0]);
            assertTrue(status.startsWith("HTTP/1.1 400"), t + " -> " + status);
        }
        String backslash = g.rawStatus("GET /wiki/pages\\home HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", new byte[0]);
        assertTrue(backslash.startsWith("HTTP/1.1 400"), backslash);
        assertTrue(g.app.seen().isEmpty(), "nothing reached the app");
        assertTrue(g.gateway.stats().invalid() > 0, "some are refused by the JDK server itself, the rest by RequestPath");
    }

    @Test
    void unknownRoutesMethodsAndTheReservedSpaceAreRefused() throws Exception {
        g = GatewayWorld.start();
        assertTrue(g.rawStatus("GET /nowhere HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", new byte[0])
                .startsWith("HTTP/1.1 404"));
        assertTrue(g.rawStatus("GET /.dwarpal/v1/other HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", new byte[0])
                .startsWith("HTTP/1.1 404"));
        assertTrue(g.rawStatus("PROPFIND /wiki/pages/home HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", new byte[0])
                .startsWith("HTTP/1.1 405"));
        assertTrue(g.rawStatus("TRACE /wiki/pages/home HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", new byte[0])
                .startsWith("HTTP/1.1 405"));
        HttpResponse<String> noSession = g.http.send(HttpRequest.newBuilder(g.uri("/wiki/pages/home")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(401, noSession.statusCode());
        assertEquals("{\"error\":\"session required\"}", noSession.body());
        assertEquals(Optional.of("no-store"), noSession.headers().firstValue("Cache-Control"));
    }

    @Test
    void malformedOrRepeatedSessionHeadersAreRefused() throws Exception {
        g = GatewayWorld.start();
        GatewayWorld.RawSession s = aliceWiki();
        HttpRequest.Builder twice = g.signed(s, s.key(), "GET", "/wiki/pages/home", Action.READ, "wiki", g.newId())
                .header(EdgeHttp.AUTHORIZATION, "Dwarpal " + s.grant().token());
        assertEquals(401, g.send(twice).statusCode(), "two Authorization headers");
        HttpRequest.Builder badId = g.signed(s, s.key(), "GET", "/wiki/pages/home", Action.READ, "wiki", g.newId())
                .setHeader(EdgeHttp.REQUEST_ID, "a b");
        assertEquals(401, g.send(badId).statusCode());
        HttpRequest.Builder badEvidence = g.signed(s, s.key(), "GET", "/wiki/pages/home", Action.READ, "wiki", g.newId())
                .header(ClientEvidence.HEADER, "not-json");
        assertEquals(400, g.send(badEvidence).statusCode());
        HttpRequest.Builder otherSession = g.signed(s, s.key(), "GET", "/wiki/pages/home", Action.READ, "wiki", g.newId())
                .setHeader(EdgeHttp.SESSION, "s-unknown");
        assertEquals(403, g.send(otherSession).statusCode(), "the gateway did not open that session");
        assertEquals(200, read(s).statusCode());
    }

    @Test
    void oversizedHeadersAndBodiesAreRefused() throws Exception {
        g = GatewayWorld.start(b -> b.maxRequestBody(1024).maxHeaders(30));
        GatewayWorld.RawSession s = aliceWiki();
        HttpRequest.Builder many = g.signed(s, s.key(), "GET", "/wiki/pages/home", Action.READ, "wiki", g.newId());
        for (int i = 0; i < 40; i++) {
            many.header("X-Pad-" + i, "x");
        }
        assertEquals(431, g.send(many).statusCode());
        HttpRequest.Builder big = g.signed(s, s.key(), "GET", "/wiki/pages/home", Action.READ, "wiki", g.newId())
                .header("X-Big", "a".repeat(40_000));
        assertEquals(431, g.send(big).statusCode());

        ClientAgent alice = g.alice();
        assertEquals(413, alice.send("PUT", "/wiki/pages/big", new byte[2048]).status(), "declared length too large");
        HttpRequest.Builder chunked = g.signed(s, s.key(), "PUT", "/wiki/pages/big", Action.WRITE, "wiki", g.newId())
                .PUT(HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(new byte[4096])));
        assertEquals(413, g.send(chunked).statusCode(), "chunked body too large");
        assertTrue(g.app.page("big").isEmpty());

        assertTrue(g.rawStatus("POST /.dwarpal/v1/sessions HTTP/1.1\r\nHost: x\r\nContent-Length: 999999\r\n"
                + "Connection: close\r\n\r\n", new byte[0]).startsWith("HTTP/1.1 413"));
    }

    @Test
    void oversizedResponsesAndAnUnreachableAppAreBadGateway() throws Exception {
        g = GatewayWorld.start(b -> b.maxResponseBody(10));
        ClientAgent alice = g.alice();
        assertEquals(502, alice.send("GET", "/wiki/pages/home", new byte[0]).status(), "response over the cap");
        g.app.close();
        ClientAgent.Response down = alice.send("GET", "/wiki/pages/home", new byte[0]);
        assertEquals(502, down.status());
        assertEquals("{\"error\":\"bad gateway\"}", down.text(), "no detail about the upstream");
        assertTrue(g.gateway.stats().upstreamFailures() >= 2);
    }

    @Test
    void loginEndpointRefusesJunk() throws Exception {
        g = GatewayWorld.start(b -> b.loginsPerMinutePerAddress(3));
        assertEquals(405, g.http.send(HttpRequest.newBuilder(g.uri(ZtnaGateway.LOGIN_PATH)).build(),
                HttpResponse.BodyHandlers.ofString()).statusCode());
        assertEquals(400, g.postLogin("{\"v\":1}".getBytes(StandardCharsets.UTF_8), null, "alice", "x").status());
        assertEquals(400, g.postLogin("{{{".getBytes(StandardCharsets.UTF_8), null, "alice", "x").status());
        assertEquals(201, aliceLoginStatus());
        assertEquals(429, aliceLoginStatus(), "fourth login in a minute from one address");
        g.w.clock.advance(Duration.ofMinutes(2));
        assertEquals(201, aliceLoginStatus());
    }

    private int aliceLoginStatus() throws Exception {
        return g.rawLogin("alice", "laptop-alice", "wiki", true, e -> e).status();
    }

    @Test
    void fullTablesAndLapsedSessionsFailClosed() throws Exception {
        g = GatewayWorld.start(b -> b.maxSessions(1));
        GatewayWorld.RawSession s = aliceWiki();
        assertEquals(503, g.rawLogin("carol", "phone-carol", "wiki", true, e -> e).status(), "no room");
        g.w.clock.advance(Duration.ofHours(10).plusMinutes(1));
        assertEquals(403, g.send(g.signed(s, s.key(), "GET", "/wiki/pages/home", Action.READ, "wiki", g.newId()))
                .statusCode(), "past its lifetime");
        assertEquals(201, g.rawLogin("carol", "phone-carol", "wiki", true, e -> e).status(), "room again");
    }

    /** An authority that holds the first use until released, to fill the gateway's in-flight slots. */
    private static final class Slow implements SessionAuthority {
        final SessionAuthority inner;
        final CountDownLatch entered = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        volatile boolean explode;

        Slow(SessionAuthority inner) {
            this.inner = inner;
        }

        @Override
        public EdgeResult open(EdgeRequest login, PublicKey key, Optional<SignatureProof> binding) {
            return inner.open(login, key, binding);
        }

        @Override
        public EdgeResult use(String token, SignatureProof proof, EdgeRequest request) {
            if (explode) {
                throw new IllegalStateException("bug");
            }
            entered.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return inner.use(token, proof, request);
        }

        @Override
        public EdgeResult decide(EdgeRequest request) {
            return inner.decide(request);
        }
    }

    @Test
    void overloadIsAnsweredBusyAndABugIsADeny() throws Exception {
        java.util.concurrent.atomic.AtomicReference<Slow> slow = new java.util.concurrent.atomic.AtomicReference<>();
        g = GatewayWorld.start(b -> b.maxInFlight(1), a -> {
            slow.set(new Slow(a));
            return slow.get();
        });
        GatewayWorld.RawSession s = aliceWiki();
        java.util.concurrent.CompletableFuture<HttpResponse<String>> first = g.http.sendAsync(
                g.signed(s, s.key(), "GET", "/wiki/pages/home", Action.READ, "wiki", g.newId()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertTrue(slow.get().entered.await(10, TimeUnit.SECONDS));
        assertEquals(503, read(s).statusCode(), "the one slot is taken");
        assertEquals(1, g.gateway.stats().overloaded());
        slow.get().release.countDown();
        assertEquals(200, first.get(10, TimeUnit.SECONDS).statusCode());

        slow.get().explode = true;
        assertEquals(403, read(s).statusCode(), "an exception inside is a refusal");
        assertEquals(1, g.gateway.stats().internalFailures());
    }
}

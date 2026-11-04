package dev.dwarpal.swg;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static dev.dwarpal.swg.TestServers.exchange;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The forward proxy over real sockets: CONNECT tunnels, plain HTTP, and every way to be refused. */
class WebGatewayTest {

    private final SwgWorld s = new SwgWorld();
    private final List<AutoCloseable> open = new ArrayList<>();
    private TestServers.Server echo;
    private TestServers.Server origin;

    @AfterEach
    void closeAll() throws Exception {
        for (AutoCloseable c : open) {
            c.close();
        }
    }

    private WebGateway gateway(WebPolicy.Builder policy, IdentityResolver who, WebGateway.Settings settings)
            throws IOException {
        echo = TestServers.echo();
        origin = TestServers.origin();
        open.add(echo);
        open.add(origin);
        WebAccess access = s.access(policy.tunnelPorts(Set.of(443, echo.port())).httpPorts(Set.of(80, origin.port()))
                .allowInternalAddresses(Set.of("127.0.0.1")).build());
        WebGateway g = new WebGateway(access, who, SwgWorld.allLoopback(), settings);
        g.start(TestServers.loopbackListener());
        open.add(g);
        return g;
    }

    private WebGateway gateway() throws IOException {
        return gateway(SwgWorld.policy(), s.loopbackIsAlice(), WebGateway.Settings.defaults());
    }

    private static String status(String response) {
        int eol = response.indexOf("\r\n");
        return eol < 0 ? response : response.substring(0, eol);
    }

    @Test
    void allowedTunnelRelaysBytesBothWays() throws IOException {
        WebGateway g = gateway();
        try (Socket c = new Socket(InetAddress.getLoopbackAddress(), g.port())) {
            c.setSoTimeout(5000);
            // the client sends its first bytes right behind the CONNECT head; they must not be lost
            c.getOutputStream().write(("CONNECT news.example:" + echo.port() + " HTTP/1.1\r\nHost: news.example\r\n\r\nping")
                    .getBytes(StandardCharsets.US_ASCII));
            InputStream in = c.getInputStream();
            assertEquals("HTTP/1.1 200 Connection Established", status(TestServers.readHead(in)));
            assertEquals("ping", new String(in.readNBytes(4), StandardCharsets.US_ASCII));
            c.getOutputStream().write("pong".getBytes(StandardCharsets.US_ASCII));
            assertEquals("pong", new String(in.readNBytes(4), StandardCharsets.US_ASCII));
        }
    }

    @Test
    void blockedTunnelsGetAGenericRefusal() throws IOException {
        WebGateway g = gateway();
        for (String target : List.of("evil.example:" + echo.port(), "x.malware.example:" + echo.port(),
                "unknown.example:" + echo.port(), "news.example:22", "192.0.2.1:" + echo.port(), "bad_host:443")) {
            String r = exchange(g.port(), "CONNECT " + target + " HTTP/1.1\r\n\r\n");
            assertTrue(status(r).startsWith("HTTP/1.1 4"), target + " -> " + status(r));
            assertTrue(r.contains("reference: swg-"), r);
            assertTrue(r.contains("Connection: close"));
            assertFalse(r.contains("evil") || r.contains("blocklist") || r.contains("RAW_IP"), "no reason is given");
        }
        assertTrue(origin.requests.isEmpty());
    }

    @Test
    void plainHttpIsForwardedWithoutClientOnlyOrHopByHopHeaders() throws IOException {
        WebGateway g = gateway();
        String r = exchange(g.port(), "GET http://news.example:" + origin.port() + "/page?q=1 HTTP/1.1\r\n"
                + "Host: something-else.example\r\nAccept: text/html\r\nProxy-Authorization: Basic c2VjcmV0\r\n"
                + "X-Dwarpal-Subject: admin\r\nDwarpal_Session: forged\r\nAuthorization: Dwarpal x\r\n"
                + "Connection: keep-alive, X-Secret-Hop\r\nX-Secret-Hop: 1\r\nKeep-Alive: 5\r\nUpgrade: websocket\r\n\r\n");
        assertEquals("HTTP/1.1 200 OK", status(r));
        assertTrue(r.endsWith("hello"));
        String seen = origin.requests.get(0);
        assertTrue(seen.startsWith("GET /page?q=1 HTTP/1.1\r\n"), seen);
        assertTrue(seen.contains("Host: news.example:" + origin.port() + "\r\n"), "Host comes from the decided destination");
        assertTrue(seen.contains("Accept: text/html\r\n"));
        assertTrue(seen.contains("Connection: close\r\n"));
        for (String gone : List.of("something-else", "Proxy-Authorization", "X-Dwarpal", "Dwarpal_Session", "Authorization",
                "X-Secret-Hop", "Keep-Alive", "Upgrade")) {
            assertFalse(seen.contains(gone), gone + " must not reach the origin");
        }
    }

    @Test
    void plainHttpBodiesAreForwardedWithinTheLimit() throws IOException {
        WebGateway g = gateway();
        String r = exchange(g.port(), "POST http://news.example:" + origin.port() + "?x HTTP/1.1\r\nContent-Length: 5\r\n\r\nabcde");
        assertEquals("HTTP/1.1 200 OK", status(r));
        assertTrue(origin.requests.get(0).startsWith("POST /?x HTTP/1.1\r\n"));
        assertTrue(origin.requests.get(0).endsWith("Content-Length: 5\r\nConnection: close\r\n\r\nabcde"));
        String put = exchange(g.port(), "DELETE http://news.example:" + origin.port() + " HTTP/1.1\r\n\r\n");
        assertEquals("HTTP/1.1 200 OK", status(put));
        assertTrue(origin.requests.get(1).contains("Content-Length: 0\r\n"));
    }

    @Test
    void requestsThatCouldBeReadTwoWaysAreRefused() throws IOException {
        WebGateway g = gateway();
        String base = "http://news.example:" + origin.port() + "/";
        Map<String, String> cases = Map.ofEntries(
                Map.entry("GET " + base + " HTTP/1.1\nHost: x\n\n", "400"),
                Map.entry("GET " + base + " HTTP/1.1\r\nHost : x\r\n\r\n", "400"),
                Map.entry("GET " + base + " HTTP/1.1\r\nX: a\r\n folded\r\n\r\n", "400"),
                Map.entry("GET " + base + " HTTP/1.1\r\nX: a\rb\r\n\r\n", "400"),
                Map.entry("GET " + base + " HTTP/2\r\n\r\n", "400"),
                Map.entry("GET  " + base + " HTTP/1.1\r\n\r\n", "400"),
                Map.entry("\r\n\r\n", "400"),
                Map.entry("GET / HTTP/1.1\r\nHost: news.example\r\n\r\n", "400"),
                Map.entry("GET https://news.example/ HTTP/1.1\r\n\r\n", "400"),
                Map.entry("GET http://news.example/#frag HTTP/1.1\r\n\r\n", "400"),
                Map.entry("GET http:// HTTP/1.1\r\n\r\n", "400"),
                Map.entry("TRACE " + base + " HTTP/1.1\r\n\r\n", "405"),
                Map.entry("BREW " + base + " HTTP/1.1\r\n\r\n", "405"),
                Map.entry("POST " + base + " HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "413"),
                Map.entry("POST " + base + " HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nabcde", "413"),
                Map.entry("POST " + base + " HTTP/1.1\r\nContent-Length: -1\r\n\r\n", "413"),
                Map.entry("POST " + base + " HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n", "413"),
                Map.entry("GET " + base + " HTTP/1.1\r\nX: caf\u00e9\r\n\r\n", "400"));
        for (Map.Entry<String, String> e : cases.entrySet()) {
            String r = exchange(g.port(), e.getKey());
            assertTrue(status(r).startsWith("HTTP/1.1 " + e.getValue()), e.getKey().strip() + " -> " + status(r));
        }
        assertTrue(origin.requests.isEmpty(), "nothing ambiguous reaches the origin");
    }

    @Test
    void oversizedHeadsAreRefused() throws IOException {
        WebGateway g = gateway();
        String many = "GET http://news.example/ HTTP/1.1\r\n" + "X-A: 1\r\n".repeat(200) + "\r\n";
        assertTrue(status(exchange(g.port(), many)).startsWith("HTTP/1.1 400"));
        String big = "GET http://news.example/ HTTP/1.1\r\nX-A: " + "a".repeat(40_000) + "\r\n\r\n";
        assertTrue(status(exchange(g.port(), big)).startsWith("HTTP/1.1 400"));
    }

    @Test
    void connectionsWithoutAKnownClientAreRefused() throws IOException {
        WebGateway g = gateway(SwgWorld.policy(), client -> Optional.empty(), WebGateway.Settings.defaults());
        String r = exchange(g.port(), "CONNECT news.example:" + echo.port() + " HTTP/1.1\r\n\r\n");
        assertEquals("HTTP/1.1 403 Forbidden", status(r));
    }

    @Test
    void unreachableDestinationsAreABadGateway() throws IOException {
        WebAccess access = s.access(SwgWorld.policy().tunnelPorts(Set.of(443)).build());
        WebGateway g = new WebGateway(access, s.loopbackIsAlice(), host -> {
            throw new IOException("no such host");
        }, WebGateway.Settings.defaults());
        g.start(TestServers.loopbackListener());
        open.add(g);
        assertEquals("HTTP/1.1 502 Bad Gateway", status(exchange(g.port(), "CONNECT news.example:443 HTTP/1.1\r\n\r\n")));
        assertEquals(1, access.blocked(BlockReason.UPSTREAM_FAILED));
        assertEquals(0, access.allowed());
    }

    @Test
    void tooManyConnectionsGetServiceUnavailable() throws Exception {
        WebGateway.Settings one = new WebGateway.Settings(32 * 1024, 100, 1024, 1024, Duration.ofSeconds(5),
                Duration.ofSeconds(2), Duration.ofSeconds(5), Duration.ofSeconds(30), 1);
        WebGateway g = gateway(SwgWorld.policy(), s.loopbackIsAlice(), one);
        try (Socket holder = new Socket(InetAddress.getLoopbackAddress(), g.port())) {
            holder.getOutputStream().write("GET http://news.example/ HTTP/1.1\r\n".getBytes(StandardCharsets.US_ASCII));
            Thread.sleep(200);
            assertEquals("HTTP/1.1 503 Service Unavailable", status(exchange(g.port(), "CONNECT news.example:443 HTTP/1.1\r\n\r\n")));
        }
    }

    @Test
    void responsesLargerThanTheLimitAreCut() throws IOException {
        WebGateway.Settings tiny = new WebGateway.Settings(32 * 1024, 100, 1024, 10, Duration.ofSeconds(5),
                Duration.ofSeconds(2), Duration.ofSeconds(5), Duration.ofSeconds(30), 8);
        WebGateway g = gateway(SwgWorld.policy(), s.loopbackIsAlice(), tiny);
        String r = exchange(g.port(), "GET http://news.example:" + origin.port() + "/ HTTP/1.1\r\n\r\n");
        assertTrue(r.length() <= 16 * 1024 && !r.endsWith("hello"), "cut after the response limit");
    }

    @Test
    void settingsAreValidated() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> new WebGateway.Settings(10, 100,
                1, 1, Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(1), 1));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> new WebGateway.Settings(1024, 100,
                1, 1, Duration.ZERO, Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(1), 1));
        WebGateway g = new WebGateway(s.access(WebPolicy.defaults()), s.loopbackIsAlice(), HostResolver.system(),
                WebGateway.Settings.defaults());
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class, g::port);
    }
}

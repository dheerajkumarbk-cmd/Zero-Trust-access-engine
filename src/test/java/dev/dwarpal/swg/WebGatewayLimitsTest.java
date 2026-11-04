package dev.dwarpal.swg;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static dev.dwarpal.swg.TestServers.exchange;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Time and size limits of the proxy, and the rarer paths through it. */
class WebGatewayLimitsTest {

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

    private WebGateway gateway(WebGateway.Settings settings) throws IOException {
        echo = TestServers.echo();
        origin = TestServers.origin();
        open.add(echo);
        open.add(origin);
        WebAccess access = s.access(SwgWorld.policy().tunnelPorts(Set.of(echo.port())).httpPorts(Set.of(origin.port()))
                .allowInternalAddresses(Set.of("127.0.0.1")).build());
        WebGateway g = new WebGateway(access, s.loopbackIsAlice(), SwgWorld.allLoopback(), settings);
        g.start(TestServers.loopbackListener());
        open.add(g);
        return g;
    }

    private static WebGateway.Settings settings(Duration read, Duration idle, Duration lifetime) {
        return new WebGateway.Settings(32 * 1024, 100, 1024 * 1024, 1024 * 1024, read, Duration.ofSeconds(2), idle, lifetime, 16);
    }

    @Test
    void aTunnelIsClosedAfterItsLifetimeEvenIfBusy() throws Exception {
        WebGateway g = gateway(settings(Duration.ofSeconds(5), Duration.ofSeconds(30), Duration.ofMillis(600)));
        try (Socket c = new Socket(InetAddress.getLoopbackAddress(), g.port())) {
            c.setSoTimeout(5000);
            c.getOutputStream().write(("CONNECT news.example:" + echo.port() + " HTTP/1.1\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            InputStream in = c.getInputStream();
            assertTrue(TestServers.readHead(in).startsWith("HTTP/1.1 200"));
            long start = System.nanoTime();
            boolean closed = false;
            while (!closed && System.nanoTime() - start < 4_000_000_000L) {
                try {
                    c.getOutputStream().write('x');
                    c.getOutputStream().flush();
                    Thread.sleep(50);
                    if (in.read() < 0) {
                        closed = true;
                    }
                } catch (IOException e) {
                    closed = true;
                }
            }
            long ms = (System.nanoTime() - start) / 1_000_000;
            assertTrue(closed && ms < 3000, "closed after the lifetime, not kept open by traffic: " + ms + " ms");
        }
    }

    @Test
    void anIdleTunnelIsClosed() throws Exception {
        WebGateway g = gateway(settings(Duration.ofSeconds(5), Duration.ofMillis(400), Duration.ofSeconds(60)));
        try (Socket c = new Socket(InetAddress.getLoopbackAddress(), g.port())) {
            c.setSoTimeout(5000);
            c.getOutputStream().write(("CONNECT news.example:" + echo.port() + " HTTP/1.1\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            InputStream in = c.getInputStream();
            assertTrue(TestServers.readHead(in).startsWith("HTTP/1.1 200"));
            long start = System.nanoTime();
            assertEquals(-1, in.read(), "nothing was sent, so the gateway ends the tunnel");
            assertTrue((System.nanoTime() - start) / 1_000_000 < 3000);
        }
    }

    @Test
    void clientsThatLeaveEarlyAreSilentlyDropped() throws Exception {
        WebGateway g = gateway(settings(Duration.ofSeconds(1), Duration.ofSeconds(5), Duration.ofSeconds(30)));
        new Socket(InetAddress.getLoopbackAddress(), g.port()).close();
        try (Socket c = new Socket(InetAddress.getLoopbackAddress(), g.port())) {
            c.getOutputStream().write("GET http://news.example/ HTT".getBytes(StandardCharsets.US_ASCII));
        }
        try (Socket c = new Socket(InetAddress.getLoopbackAddress(), g.port())) {
            c.getOutputStream().write(("POST http://news.example:" + origin.port() + "/ HTTP/1.1\r\nContent-Length: 50\r\n\r\nshort")
                    .getBytes(StandardCharsets.US_ASCII));
        }
        assertEquals(0, origin.accepted.get(), "an incomplete request is never forwarded");
        // still serving afterwards
        assertTrue(exchange(g.port(), "GET http://news.example:" + origin.port() + "/ HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 200"));
    }

    @Test
    void aSlowBodyIsCutOffToo() throws Exception {
        WebGateway g = gateway(settings(Duration.ofMillis(700), Duration.ofSeconds(5), Duration.ofSeconds(30)));
        try (Socket c = new Socket(InetAddress.getLoopbackAddress(), g.port())) {
            c.setSoTimeout(4000);
            c.getOutputStream().write(("POST http://news.example:" + origin.port() + "/ HTTP/1.1\r\nContent-Length: 20\r\n\r\nab")
                    .getBytes(StandardCharsets.US_ASCII));
            c.getOutputStream().flush();
            long start = System.nanoTime();
            byte[] rest = readAll(c);
            assertTrue((System.nanoTime() - start) / 1_000_000 < 3500, "the gateway gave up on the body");
            assertTrue(new String(rest, StandardCharsets.ISO_8859_1).isEmpty() || new String(rest, StandardCharsets.ISO_8859_1).contains("408"));
        }
        assertEquals(0, origin.accepted.get());
    }

    private static byte[] readAll(Socket c) {
        try {
            return c.getInputStream().readAllBytes();
        } catch (IOException e) {
            return new byte[0];
        }
    }

    @Test
    void plainHttpToAnUnreachableOriginIsABadGateway() throws Exception {
        WebAccess access = s.access(SwgWorld.policy().build());
        WebGateway g = new WebGateway(access, s.loopbackIsAlice(), host -> {
            throw new IOException("no such host");
        }, WebGateway.Settings.defaults());
        g.start(TestServers.loopbackListener());
        open.add(g);
        assertTrue(exchange(g.port(), "GET http://news.example/ HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 502"));
        // an origin that refuses the connection: the resolved address works but nothing listens
        TestServers.Server dead = TestServers.echo();
        int deadPort = dead.port();
        dead.close();
        WebAccess access2 = s.access(SwgWorld.policy().httpPorts(Set.of(deadPort)).allowInternalAddresses(Set.of("127.0.0.1")).build());
        WebGateway g2 = new WebGateway(access2, s.loopbackIsAlice(), SwgWorld.allLoopback(), WebGateway.Settings.defaults());
        g2.start(TestServers.loopbackListener());
        open.add(g2);
        assertTrue(exchange(g2.port(), "GET http://news.example:" + deadPort + "/ HTTP/1.1\r\n\r\n").startsWith("HTTP/1.1 502"));
    }

    @Test
    void http10RequestsAndUppercaseSchemesWork() throws Exception {
        WebGateway g = gateway(WebGateway.Settings.defaults());
        String r = exchange(g.port(), "GET HTTP://News.Example:" + origin.port() + "/a HTTP/1.0\r\n\r\n");
        assertTrue(r.startsWith("HTTP/1.1 200"), r.split("\r\n")[0]);
        assertTrue(origin.requests.get(0).contains("Host: news.example:" + origin.port()));
        String head = exchange(g.port(), "HEAD http://news.example:" + origin.port() + "/ HTTP/1.1\r\n\r\n");
        assertTrue(head.startsWith("HTTP/1.1 200"));
    }

    @Test
    void settingsRejectNonsense() {
        Duration ok = Duration.ofSeconds(1);
        assertThrows(IllegalArgumentException.class, () -> new WebGateway.Settings(1024, 0, 1, 1, ok, ok, ok, ok, 1));
        assertThrows(IllegalArgumentException.class, () -> new WebGateway.Settings(1024, 1, -1, 1, ok, ok, ok, ok, 1));
        assertThrows(IllegalArgumentException.class, () -> new WebGateway.Settings(1024, 1, 1, 0, ok, ok, ok, ok, 1));
        assertThrows(IllegalArgumentException.class, () -> new WebGateway.Settings(1024, 1, 1, 1, ok, ok, ok, ok, 0));
        assertThrows(IllegalArgumentException.class, () -> new WebGateway.Settings(1024, 1, 1, 1, ok, Duration.ofSeconds(-1), ok, ok, 1));
        assertThrows(IllegalArgumentException.class, () -> new WebGateway.Settings(1024, 1, 1, 1, ok, ok, Duration.ofDays(60), ok, 1));
        assertThrows(IllegalArgumentException.class, () -> new WebGateway.Settings(1024, 1, 1, 1, ok, ok, ok, Duration.ZERO, 1));
    }
}

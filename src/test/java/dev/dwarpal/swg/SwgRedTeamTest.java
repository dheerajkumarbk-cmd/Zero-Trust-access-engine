package dev.dwarpal.swg;

import dev.dwarpal.domain.Action;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static dev.dwarpal.swg.TestServers.exchange;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Red-team pass on the web gateway. Each r-test is a probe that was first run against the unfixed code
 * and failed (the breach worked); the fix then made it pass, and it stays as a regression test. The
 * "held" tests are attacks that never worked.
 */
class SwgRedTeamTest {

    private final SwgWorld s = new SwgWorld();
    private final List<AutoCloseable> open = new ArrayList<>();

    @AfterEach
    void closeAll() throws Exception {
        for (AutoCloseable c : open) {
            c.close();
        }
    }

    /** A policy that lets every unlisted host through, so only the filter itself can stop a bypass. */
    private WebAccess lenient() {
        return s.access(SwgWorld.policy().uncategorised("web:general").build());
    }

    private Optional<BlockReason> check(WebAccess a, String authority) {
        return a.check(s.alice(), authority, true, Action.READ).reason();
    }

    private WebGateway gatewayTo(WebAccess access, WebGateway.Settings settings) throws IOException {
        WebGateway g = new WebGateway(access, s.loopbackIsAlice(), SwgWorld.allLoopback(), settings);
        g.start(TestServers.loopbackListener());
        open.add(g);
        return g;
    }

    // R1 ----------------------------------------------------------------------------------------

    @Test
    void r1_numericSpellingsOfAnIpAddressAreNotHostNames() {
        WebAccess a = lenient();
        for (String sneaky : List.of("2130706433", "0x7f000001", "0x7f.0.0.1", "127.1", "0177.0.0.1", "017700000001",
                "3232235777", "4294967295", "1.1", "10.1", "0300.0250.0.1", "1.2.3.0x4")) {
            WebVerdict v = a.check(s.alice(), sneaky, true, Action.READ);
            assertFalse(v.allowed(), sneaky + " must not pass as a host name");
            assertEquals(Optional.of(BlockReason.BAD_HOST), v.reason(), sneaky);
        }
        // the dotted form is an IP literal and meets the raw-IP rule
        assertEquals(Optional.of(BlockReason.RAW_IP), check(a, "127.0.0.1"));
        assertEquals(Optional.of(BlockReason.RAW_IP), check(a, "127.0.0.1."));
    }

    // R2 ----------------------------------------------------------------------------------------

    @Test
    void r2_aNameThatResolvesToAnInternalAddressIsNeverConnectedTo() throws Exception {
        TestServers.Server internal = TestServers.echo();
        open.add(internal);
        WebAccess access = s.access(SwgWorld.policy().tunnelPorts(Set.of(internal.port())).build());
        WebGateway g = gatewayTo(access, WebGateway.Settings.defaults());
        String r = exchange(g.port(), "CONNECT news.example:" + internal.port() + " HTTP/1.1\r\n\r\n");
        assertTrue(r.startsWith("HTTP/1.1 403"), "an allowed name pointing at 127.0.0.1 is an SSRF: " + r.split("\r\n")[0]);
        assertEquals(0, internal.accepted.get(), "the internal server must not even see a connection");
        assertEquals(1, access.blocked(BlockReason.INTERNAL_ADDRESS));
        assertEquals(0, access.allowed());
    }

    // R3 ----------------------------------------------------------------------------------------

    @Test
    void r3_namesMixingWritingSystemsAreLookalikes() {
        WebAccess a = lenient();
        for (String fake : List.of("\u0430pple.example", "g\u043e\u043egle.example", "pay\u0440al.example",
                "www.p\u0430ypal.example", "online\u03bf.example", "bank.\u0430pple.example")) {
            WebVerdict v = a.check(s.alice(), fake, true, Action.READ);
            assertEquals(Optional.of(BlockReason.LOOKALIKE), v.reason(), fake);
            assertEquals(WebPolicy.MALICIOUS, v.destination().orElseThrow().resourceId());
        }
        // single-script international names are fine
        assertTrue(a.check(s.alice(), "k\u00e4se.example", true, Action.READ).allowed());
        assertTrue(a.check(s.alice(), "\u043f\u0440\u0438\u043c\u0435\u0440.example", true, Action.READ).allowed());
        assertTrue(a.check(s.alice(), "xn--bcher-kva.example.net", true, Action.READ).allowed());
        assertTrue(a.check(s.alice(), "news.example", true, Action.READ).allowed());
    }

    // R4 ----------------------------------------------------------------------------------------

    @Test
    void r4_aSlowTrickleCannotHoldAConnectionOpen() throws Exception {
        WebGateway.Settings oneSecond = new WebGateway.Settings(32 * 1024, 100, 1024, 1024, Duration.ofSeconds(1),
                Duration.ofSeconds(2), Duration.ofSeconds(5), Duration.ofSeconds(30), 8);
        WebGateway g = gatewayTo(s.access(SwgWorld.policy().build()), oneSecond);
        long start = System.nanoTime();
        try (Socket c = new Socket(InetAddress.getLoopbackAddress(), g.port())) {
            c.setSoTimeout(500);
            OutputStream out = c.getOutputStream();
            byte[] head = "GET http://news.example/ HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .getBytes(StandardCharsets.US_ASCII);
            // one byte every 250 ms: each read is well inside the 1 s read timeout, the whole request is not
            boolean cut = false;
            for (int i = 0; i < head.length && !cut; i++) {
                try {
                    out.write(head[i]);
                    out.flush();
                    Thread.sleep(250);
                    if (c.getInputStream().available() > 0) {
                        break;
                    }
                } catch (IOException e) {
                    cut = true;
                }
            }
            String answer;
            try {
                answer = new String(c.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
            } catch (IOException e) {
                answer = "";
            }
            long ms = (System.nanoTime() - start) / 1_000_000;
            assertTrue(answer.startsWith("HTTP/1.1 408") || cut,
                    "the gateway must give up on a request that takes too long: '" + answer + "'");
            assertTrue(ms < 4000, "cut after about the time limit, not after the trickle ended: " + ms + " ms");
        }
    }

    // held: attacks that did not work -----------------------------------------------------------

    @Test
    void held_userInfoAndBackslashTricksInTheTarget() throws IOException {
        TestServers.Server origin = TestServers.origin();
        open.add(origin);
        WebAccess access = s.access(SwgWorld.policy().httpPorts(Set.of(origin.port()))
                .allowInternalAddresses(Set.of("127.0.0.1")).build());
        WebGateway g = gatewayTo(access, WebGateway.Settings.defaults());
        for (String target : List.of("http://news.example@evil.example/", "http://evil.example\\@news.example/",
                "http://news.example%2f@evil.example/", "http://news.example:80@evil.example/",
                "http://evil.example#@news.example/", "http://news.example%00.evil.example/")) {
            String r = exchange(g.port(), "GET " + target + " HTTP/1.1\r\n\r\n");
            assertTrue(r.startsWith("HTTP/1.1 400"), target + " -> " + r.split("\r\n")[0]);
        }
        assertTrue(origin.requests.isEmpty());
    }

    @Test
    void held_ipv6AndMappedFormsOfABlocklistedAddress() {
        WebAccess a = lenient();
        for (String ip : List.of("198.51.100.66", "[::ffff:198.51.100.66]", "[::ffff:c633:6442]",
                "[0:0:0:0:0:ffff:198.51.100.66]")) {
            assertEquals(Optional.of(BlockReason.BLOCKLISTED), check(a, ip), ip);
        }
    }

    @Test
    void held_theHostHeaderCannotChangeTheDestination() throws IOException {
        TestServers.Server origin = TestServers.origin();
        open.add(origin);
        WebAccess access = s.access(SwgWorld.policy().httpPorts(Set.of(origin.port()))
                .allowInternalAddresses(Set.of("127.0.0.1")).build());
        WebGateway g = gatewayTo(access, WebGateway.Settings.defaults());
        String r = exchange(g.port(), "GET http://evil.example:" + origin.port() + "/ HTTP/1.1\r\nHost: news.example\r\n\r\n");
        assertTrue(r.startsWith("HTTP/1.1 403"), "the absolute target decides, not the Host header");
        assertEquals(0, origin.accepted.get());
        r = exchange(g.port(), "GET http://news.example:" + origin.port() + "/ HTTP/1.1\r\nHost: evil.example\r\n\r\n");
        assertTrue(r.startsWith("HTTP/1.1 200"));
        assertTrue(origin.requests.get(0).contains("Host: news.example:" + origin.port()));
    }
}

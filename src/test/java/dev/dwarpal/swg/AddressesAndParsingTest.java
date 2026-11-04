package dev.dwarpal.swg;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Which addresses count as inside, how request heads are parsed, and the small helpers around them. */
class AddressesAndParsingTest {

    private static boolean internal(String literal) {
        return Addresses.internal(InetAddress.ofLiteral(literal));
    }

    @Test
    void everyNonPublicRangeIsInternal() {
        for (String ip : List.of("0.0.0.0", "0.1.2.3", "10.0.0.1", "10.255.255.255", "100.64.0.1", "100.127.255.255",
                "127.0.0.1", "127.255.255.254", "169.254.169.254", "172.16.0.1", "172.31.255.255", "192.0.0.1",
                "192.168.0.1", "198.18.0.1", "198.19.255.255", "224.0.0.1", "239.255.255.255", "240.0.0.1",
                "255.255.255.255", "::", "::1", "fe80::1", "fc00::1", "fd12:3456::1", "fec0::1", "ff02::1",
                "::127.0.0.1", "::10.0.0.1", "::ffff:10.0.0.1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "64:ff9b::a00:1",
                "2002:7f00:1::1", "2002:a9fe:a9fe::1", "2001:db8::1")) {
            assertTrue(internal(ip), ip + " is not on the public internet");
        }
    }

    @Test
    void publicAddressesAreNotInternal() {
        for (String ip : List.of("8.8.8.8", "1.1.1.1", "9.255.255.255", "11.0.0.1", "100.63.255.255", "100.128.0.1",
                "126.255.255.255", "128.0.0.1", "169.253.255.255", "169.255.0.1", "172.15.255.255", "172.32.0.1",
                "192.0.1.1", "192.167.255.255", "192.169.0.1", "198.17.255.255", "198.20.0.1", "223.255.255.255",
                "2606:4700:4700::1111", "2a00:1450:4009:81f::200e", "64:ff9b::808:808", "2002:808:808::1",
                "::ffff:8.8.8.8", "2001:4860:4860::8888")) {
            assertFalse(internal(ip), ip + " is a public address");
        }
    }

    @Test
    void theSystemResolverTurnsLiteralsIntoAddressesWithoutALookup() throws IOException {
        HostResolver system = HostResolver.system();
        assertEquals(List.of(InetAddress.ofLiteral("192.0.2.1")), system.resolve(HostName.parse("192.0.2.1").orElseThrow()));
        assertEquals(List.of(InetAddress.ofLiteral("2001:db8::1")), system.resolve(HostName.parse("[2001:db8::1]").orElseThrow()));
        assertTrue(system.resolve(HostName.parse("localhost").orElseThrow()).stream().allMatch(InetAddress::isLoopbackAddress));
    }

    @Test
    void identitiesAreLookedUpByClientAddress() {
        IdentityResolver r = IdentityResolver.fixed(Map.of());
        assertEquals(Optional.empty(), r.resolve(null));
        assertEquals(Optional.empty(), r.resolve(InetAddress.getLoopbackAddress()));
    }

    // ---- request heads -----------------------------------------------------------------------------

    private static Optional<HttpHead> head(String raw) throws IOException, HttpHead.Malformed {
        return HttpHead.read(new ByteArrayInputStream(raw.getBytes(StandardCharsets.ISO_8859_1)), 4096, 10);
    }

    private static void malformed(String raw) {
        assertThrows(HttpHead.Malformed.class, () -> head(raw), raw.replace("\r", "\\r").replace("\n", "\\n"));
    }

    @Test
    void aWellFormedHeadIsParsed() throws Exception {
        HttpHead h = head("GET http://a.example/x HTTP/1.1\r\nHost: a.example\r\nAccept: a\r\nAccept: b\r\nX-Tab:\tv \r\n\r\n").orElseThrow();
        assertEquals("GET", h.method);
        assertEquals("http://a.example/x", h.target);
        assertEquals("HTTP/1.1", h.version);
        assertEquals(List.of("a", "b"), h.values("accept"));
        assertEquals(Optional.of("v"), h.single("X-TAB"));
        assertEquals(Optional.empty(), h.single("absent"));
        assertThrows(HttpHead.Malformed.class, () -> h.single("Accept"));
        assertEquals(Optional.empty(), head(""));
        assertTrue(head("GET / HTTP/1.0\r\n\r\n").isPresent());
    }

    @Test
    void everyAmbiguousOrBrokenHeadIsRejected() {
        malformed("GET / HTTP/1.1\r\n");                     // closed inside the head
        malformed("GET / HTTP/1.1\nHost: a\n\n");            // bare LF
        malformed("GET / HTTP/1.1\r\rHost: a\r\n\r\n");      // bare CR
        malformed("GET / HTTP/1.1\r\nHost: a\r\r\n\r\n");
        malformed("\r\n");                                   // empty request line
        malformed("GET / HTTP/1.1 extra\r\n\r\n");
        malformed("GET /\r\n\r\n");
        malformed("G@T / HTTP/1.1\r\n\r\n");
        malformed("GET / HTTP/3\r\n\r\n");
        malformed("GET /\u007f HTTP/1.1\r\n\r\n");
        malformed("GET / HTTP/1.1\r\n: nameless\r\n\r\n");
        malformed("GET / HTTP/1.1\r\nBad Name: v\r\n\r\n");
        malformed("GET / HTTP/1.1\r\nNo colon here\r\n\r\n");
        malformed("GET / HTTP/1.1\r\nA: b\r\n\tfolded\r\n\r\n");
        malformed("GET / HTTP/1.1\r\nA: \u0001\r\n\r\n");
        malformed("GET / HTTP/1.1\r\nA: caf\u00e9\r\n\r\n");
        malformed("GET / HTTP/1.1\r\n" + "A: b\r\n".repeat(11) + "\r\n");
        malformed("GET /" + "a".repeat(5000) + " HTTP/1.1\r\n\r\n");
    }

    @Test
    void tokensFollowTheHttpGrammar() {
        assertTrue(HttpHead.token("X-Custom_Header.1~"));
        assertFalse(HttpHead.token(""));
        assertFalse(HttpHead.token("a b"));
        assertFalse(HttpHead.token("a:b"));
        assertArrayEquals(new byte[] {'a', 'b'}, HttpHead.ascii("ab"));
    }

    @Test
    void absoluteTargetsAreSplitIntoAuthorityAndPath() {
        assertEquals(List.of("a.example", "/"), List.of(WebGateway.absoluteHttp("http://a.example").orElseThrow()));
        assertEquals(List.of("a.example:8080", "/p/q?x=1"), List.of(WebGateway.absoluteHttp("HTTP://a.example:8080/p/q?x=1").orElseThrow()));
        assertEquals(List.of("a.example", "/?x"), List.of(WebGateway.absoluteHttp("http://a.example?x").orElseThrow()));
        for (String bad : List.of("https://a.example/", "/relative", "http://", "http:///path", "http://a.example/p#frag", "ftp://a.example/",
                "http:/a.example")) {
            assertEquals(Optional.empty(), WebGateway.absoluteHttp(bad), bad);
        }
    }

    @Test
    void cappedStreamsStopAtTheirLimit() throws IOException {
        InputStream ok = ListFiles.capped(new ByteArrayInputStream(new byte[10]), 10);
        assertEquals(10, ok.readAllBytes().length);
        InputStream over = ListFiles.capped(new ByteArrayInputStream(new byte[11]), 10);
        assertThrows(IOException.class, over::readAllBytes);
        InputStream single = ListFiles.capped(new ByteArrayInputStream(new byte[] {7, 8}), 1);
        assertEquals(7, single.read());
        assertThrows(IOException.class, single::read);
        assertEquals(0, ListFiles.capped(new ByteArrayInputStream(new byte[1]), 1).read(new byte[4], 0, 0));
        // a final line without a newline is still a line
        List<String> lines = new java.util.ArrayList<>();
        ListFiles.lines(new java.io.StringReader("a\r\nb"), new ListFiles.LineSink() {
            @Override
            public void line(String line) {
                lines.add(line);
            }

            @Override
            public void rejected() {
                lines.add("<rejected>");
            }
        });
        assertEquals(List.of("a", "b"), lines);
    }

    @Test
    void hostNameEdgeCases() {
        assertEquals(Optional.empty(), HostName.parse("[1:2:3:4:5:6:7:8:9]"));
        assertEquals(Optional.empty(), HostName.parse("[" + "1".repeat(50) + "]"));
        assertEquals(Optional.empty(), HostName.parse("[::1]x"));
        assertEquals(Optional.empty(), HostName.parse("256.1.1.1"));
        assertEquals(Optional.empty(), HostName.parse("1.2.3.4.5"));
        assertEquals(Optional.empty(), HostName.parse("1.2.3.04"));
        assertEquals(Optional.empty(), HostName.parse("xn--"));
        assertEquals(Optional.empty(), HostName.parse("a.0x"));
        assertTrue(HostName.parse("a.0xfg").isPresent(), "not hexadecimal, so an ordinary (odd) name");
        assertFalse(HostName.parse("plain.example").orElseThrow().mixedScript());
        assertFalse(HostName.parse("192.0.2.1").orElseThrow().mixedScript());
        assertFalse(HostName.parse("xn--invalid-.example").map(HostName::mixedScript).orElse(false));
        assertTrue(HostName.parse("\u65e5\u672c\u8a9e\u30c6\u30b9\u30c8.example").isPresent());
        assertFalse(HostName.parse("\u65e5\u672c\u8a9e\u30c6\u30b9\u30c8.example").orElseThrow().mixedScript(),
                "Han with Katakana is ordinary Japanese");
        assertFalse(HostName.parse("\ud55c\uae00\u6f22\u5b57.example").orElseThrow().mixedScript(), "Han with Hangul is Korean");
        assertTrue(HostName.parse("a\u65e5.example").orElseThrow().mixedScript(), "Latin with Han is not on the list");
        assertEquals("[0:0:0:0:0:0:0:1]", HostName.parse("[::1]").orElseThrow().toString());
        assertEquals(HostName.Kind.IPV6, HostName.parse("[::1]").orElseThrow().kind());
    }

    @Test
    void domainListEdgeCases() {
        DomainList l = DomainList.of("127.0.0.1 localhost", "0.0.0.0 0.0.0.0", "::1 ip6-localhost", "fe80::1%lo0 x.example", "1.2.3.4",
                "||e.example^ extra tokens", "*.", "||", "# only a comment");
        assertEquals(1, l.size(), "only 1.2.3.4 is a real entry");
        assertTrue(l.matches(HostName.parse("1.2.3.4").orElseThrow()));
        assertTrue(l.rejectedLines() >= 3);
    }
}

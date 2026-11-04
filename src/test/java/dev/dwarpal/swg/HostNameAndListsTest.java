package dev.dwarpal.swg;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Host normalisation, blocklists and category files. */
class HostNameAndListsTest {

    private static String host(String raw) {
        return HostName.parse(raw).map(HostName::value).orElse("<invalid>");
    }

    @Test
    void namesAreNormalisedToOneCanonicalForm() {
        assertEquals("news.example", host("NEWS.Example"));
        assertEquals("news.example", host("news.example."));
        assertEquals("xn--bcher-kva.example", host("b\u00fccher.example"));
        assertEquals("xn--bcher-kva.example", host("B\u00dcCHER.example"));
        // full-width letters and the ideographic full stop are the same name after IDNA mapping
        assertEquals("news.example", host("\uff4e\uff45\uff57\uff53\u3002example"));
        assertEquals(HostName.Kind.NAME, HostName.parse("intranet").orElseThrow().kind());
    }

    @Test
    void anythingThatIsNotClearlyAHostIsRefused() {
        for (String bad : List.of("", "a..b", ".a", "..", "-a.example", "a-.example", "a b.example", "evil.example%2f",
                "evil.example/x", "evil\\example", "user@evil.example", "evil.example:80", "a\u0000b", "a\tb",
                "x".repeat(64) + ".example", ("a".repeat(60) + ".").repeat(5) + "example", "a_b.example",
                "[::1", "[fe80::1%eth0]", "[]", "[zz::1]", "x".repeat(2000), "a,b.example")) {
            assertEquals(Optional.empty(), HostName.parse(bad), bad);
        }
        assertEquals(Optional.empty(), HostName.parse(null));
    }

    @Test
    void ipLiteralsAreRecognisedAndCanonical() {
        HostName v4 = HostName.parse("192.0.2.1").orElseThrow();
        assertEquals(HostName.Kind.IPV4, v4.kind());
        assertTrue(v4.ipLiteral());
        assertEquals(List.of("192.0.2.1"), v4.suffixes());
        HostName v6 = HostName.parse("[2001:DB8::1]").orElseThrow();
        assertEquals(HostName.Kind.IPV6, v6.kind());
        assertEquals("[2001:db8:0:0:0:0:0:1]", v6.toString());
        assertEquals("192.0.2.1", host("[::ffff:192.0.2.1]"));
        assertEquals(HostName.Kind.IPV4, HostName.parse("[::ffff:192.0.2.1]").orElseThrow().kind());
        assertEquals("192.0.2.1", HostName.parse("192.0.2.1").orElseThrow().toString());
    }

    @Test
    void suffixesGoFromMostToLeastSpecific() {
        assertEquals(List.of("a.b.evil.example", "b.evil.example", "evil.example", "example"),
                HostName.parse("a.b.evil.example").orElseThrow().suffixes());
    }

    @Test
    void blocklistCoversSubdomainsButNotLookalikeSuffixes() {
        DomainList list = SwgWorld.sampleBlocklist();
        for (String blocked : List.of("evil.example", "a.b.evil.example", "EVIL.example.", "tracker.example",
                "ads.tracker.example", "phish.example", "x.malware.example", "malware.example", "ransom.example",
                "198.51.100.66", "b\u00fccher.example", "www.xn--bcher-kva.example")) {
            assertTrue(list.matches(HostName.parse(blocked).orElseThrow()), blocked);
        }
        for (String fine : List.of("notevil.example", "evil.example.org", "example", "localhost", "198.51.100.67",
                "news.example")) {
            assertFalse(list.matches(HostName.parse(fine).orElseThrow()), fine);
        }
        assertEquals(Optional.of("evil.example"), list.match(HostName.parse("deep.evil.example").orElseThrow()));
        assertEquals(1, list.rejectedLines());
        assertEquals(8, list.size());
        assertTrue(list.toString().contains("8 entries"));
    }

    @Test
    void blocklistFormatsAndJunk() {
        DomainList list = DomainList.of("! adblock comment", "# comment", "", "   ", "0.0.0.0 a.example b.example",
                ":: v6.example", "not/a/host", "1.2.3.4 bad/host", "999.1.1.1 x.example", "||c.example^", "*.d.example");
        assertEquals(5, list.size());
        assertEquals(3, list.rejectedLines());
        assertTrue(list.matches(HostName.parse("v6.example").orElseThrow()));
        assertTrue(list.matches(HostName.parse("z.d.example").orElseThrow()));
        assertEquals(0, DomainList.empty().size());
    }

    @Test
    void listFilesAreReadStrictly(@TempDir Path dir) throws IOException {
        Path good = dir.resolve("block.txt");
        Files.writeString(good, "evil.example\r\nphish.example\r\n" + "x".repeat(ListFiles.MAX_LINE_CHARS + 5) + "\n",
                StandardCharsets.UTF_8);
        DomainList list = DomainList.load(good);
        assertEquals(2, list.size());
        assertEquals(1, list.rejectedLines());

        Path latin1 = dir.resolve("latin1.txt");
        Files.write(latin1, new byte[] {'a', '.', 'e', 'x', (byte) 0xE9, '\n'});
        assertThrows(IOException.class, () -> DomainList.load(latin1));
        assertThrows(IOException.class, () -> DomainList.load(dir));
        assertThrows(IOException.class, () -> DomainList.load(dir.resolve("missing.txt")));

        Path cats = dir.resolve("cats.txt");
        Files.writeString(cats, "news.example news\n", StandardCharsets.UTF_8);
        assertEquals(1, CategoryMap.load(cats).size());

        Path link = dir.resolve("link.txt");
        try {
            Files.createSymbolicLink(link, good);
        } catch (IOException | UnsupportedOperationException e) {
            return; // creating links needs a privilege on some systems; nothing to test there
        }
        assertThrows(IOException.class, () -> DomainList.load(link));
    }

    @Test
    void categoriesMostSpecificWinsAndConflictsAreRejected() {
        CategoryMap m = CategoryMap.parse("example news\nshop.example shopping\nshop.example shopping\n"
                + "shop.example gambling\nbad line here\n!!! news\nok.example BAD*CAT\n198.51.100.7 hosting # an IP\n");
        assertEquals(Optional.of("shopping"), m.category(HostName.parse("a.shop.example").orElseThrow()));
        assertEquals(Optional.of("news"), m.category(HostName.parse("other.example").orElseThrow()));
        assertEquals(Optional.of("hosting"), m.category(HostName.parse("198.51.100.7").orElseThrow()));
        assertEquals(Optional.empty(), m.category(HostName.parse("example.org").orElseThrow()));
        assertEquals(4, m.rejectedLines());
        assertEquals(3, m.size());
        assertTrue(m.toString().contains("3 entries"));
        assertEquals(0, CategoryMap.empty().size());
    }

    @Test
    void policyValidatesItsSettings() {
        assertThrows(IllegalArgumentException.class, () -> WebPolicy.builder().tunnelPorts(Set.of(0)).build());
        assertThrows(IllegalArgumentException.class, () -> WebPolicy.builder().allowRawIps(Set.of("host")).build());
        assertThrows(IllegalArgumentException.class, () -> WebPolicy.builder().category("x", "bad id!").build());
        WebPolicy p = WebPolicy.builder().allowRawIps(Set.of("2001:db8::1", "192.0.2.1"))
                .allowInternalAddresses(Set.of("127.0.0.1")).uncategorised("web:general").malicious("web:malicious")
                .httpPorts(Set.of(80, 8080)).build();
        assertTrue(p.rawIpAllowed("2001:db8:0:0:0:0:0:1"));
        assertTrue(p.internalAddressAllowed("127.0.0.1"));
        assertTrue(p.httpPortAllowed(8080));
        assertFalse(p.tunnelPortAllowed(8080));
        assertEquals("web:general", p.resourceFor(Optional.empty()));
        assertEquals(WebPolicy.UNCATEGORISED, WebPolicy.defaults().resourceFor(Optional.of("nothing")));
    }
}

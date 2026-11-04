package dev.dwarpal.swg;

import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.SessionAuthority;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Decisions on web destinations: the local filter and the engine (through SessionAuthority) together. */
class WebAccessTest {

    private final SwgWorld s = new SwgWorld();
    private final WebAccess access = s.access(SwgWorld.policy().build());

    private Optional<BlockReason> tunnel(String authority) {
        return access.check(s.alice(), authority, true, Action.READ).reason();
    }

    @Test
    void generalWebIsAllowedThroughTheEngine() {
        long before = s.decisions();
        WebVerdict v = access.check(s.alice(), "news.example:443", true, Action.READ);
        assertTrue(v.allowed(), v.toString());
        assertEquals("web:general", v.destination().orElseThrow().resourceId());
        assertEquals(Optional.of("news"), v.destination().orElseThrow().category());
        assertEquals("news.example:443", v.destination().orElseThrow().authority());
        assertEquals(before + 1, s.decisions(), "every destination is decided (and audited) by the engine");
        assertTrue(access.check(s.alice(), "a.search.example", false, Action.READ).allowed());
        assertTrue(access.check(s.alice(), "NEWS.EXAMPLE.:443", true, Action.READ).allowed());
        assertEquals(3, access.allowed());
    }

    @Test
    void uncategorisedWebIsDeniedByThePolicy() {
        // web:uncategorised is INTERNAL; the reference policy permits only PUBLIC web destinations (P-10)
        assertEquals(Optional.of(BlockReason.DENIED), tunnel("unknown.example"));
        assertEquals(Optional.of(BlockReason.DENIED), tunnel("mail.example"));
        assertEquals(2, access.blocked(BlockReason.DENIED));
    }

    @Test
    void blockedCategoryIsRefused() {
        assertEquals(Optional.of(BlockReason.DENIED), tunnel("gambling.example"));
        assertEquals(Optional.of(BlockReason.DENIED), tunnel("www.gambling.example"));
    }

    @Test
    void blocklistedDomainsAndSubdomainsAreRefusedButStillDecided() {
        for (String host : List.of("evil.example", "a.b.evil.example", "EVIL.Example.", "x.malware.example:443",
                "ads.tracker.example", "b\u00fccher.example", "xn--bcher-kva.example")) {
            long before = s.decisions();
            WebVerdict v = access.check(s.alice(), host, true, Action.READ);
            assertEquals(Optional.of(BlockReason.BLOCKLISTED), v.reason(), host);
            assertEquals(WebPolicy.MALICIOUS, v.destination().orElseThrow().resourceId());
            assertEquals(before + 1, s.decisions(), "the engine's audit trail sees blocked destinations too");
            assertTrue(v.userMessage().contains(v.reference()));
            assertFalse(v.userMessage().toLowerCase(java.util.Locale.ROOT).contains("block"),
                    "the user is not told why");
        }
    }

    @Test
    void blocklistWinsEvenIfTheEngineWouldAllow() {
        // a misconfigured policy permitting everything must not open a blocklisted host
        WebAccess lenient = s.access(SwgWorld.policy().malicious("web:general").build());
        assertEquals(Optional.of(BlockReason.BLOCKLISTED),
                lenient.check(s.alice(), "evil.example", true, Action.READ).reason());
    }

    @Test
    void rawIpDestinationsAreRefusedUnlessAllowed() {
        assertEquals(Optional.of(BlockReason.RAW_IP), tunnel("192.0.2.10:443"));
        assertEquals(Optional.of(BlockReason.RAW_IP), tunnel("[2001:db8::10]:443"));
        assertEquals(Optional.of(BlockReason.BLOCKLISTED), tunnel("198.51.100.66"));
        s.categories.set(CategoryMap.parse("192.0.2.10 news\n"));
        WebAccess allowing = s.access(SwgWorld.policy().allowRawIps(Set.of("192.0.2.10")).build());
        assertTrue(allowing.check(s.alice(), "192.0.2.10:443", true, Action.READ).allowed());
        assertEquals(Optional.of(BlockReason.RAW_IP), allowing.check(s.alice(), "192.0.2.11", true, Action.READ).reason());
    }

    @Test
    void portsAreRestrictedPerKindOfRequest() {
        long before = s.decisions();
        assertEquals(Optional.of(BlockReason.PORT_NOT_ALLOWED), tunnel("news.example:22"));
        assertEquals(Optional.of(BlockReason.PORT_NOT_ALLOWED), tunnel("news.example:80"));
        assertEquals(Optional.of(BlockReason.PORT_NOT_ALLOWED),
                access.check(s.alice(), "news.example:443", false, Action.READ).reason());
        assertEquals(before, s.decisions(), "nothing to ask the engine about");
        for (String bad : List.of("news.example:", "news.example:0", "news.example:65536", "news.example:+443",
                "news.example:44a", "news.example:123456", "[::1", "[::1]x", "", "user@news.example:443",
                "news.example:443:443")) {
            assertEquals(Optional.of(BlockReason.BAD_HOST), tunnel(bad), bad);
        }
        assertTrue(access.check(s.alice(), "news.example", false, Action.READ).allowed());
    }

    @Test
    void engineSideSignalsApplyToWebTraffic() {
        s.world.signals.set(new SignalSnapshot(Set.of(), Set.of("alice"), Set.of(), Set.of()));
        assertEquals(Optional.of(BlockReason.DENIED), tunnel("news.example"));
    }

    @Test
    void unknownPeopleAndDevicesAreJudgedByTheEngine() {
        assertEquals(Optional.of(BlockReason.DENIED),
                access.check(s.identity("mallory", "laptop-alice"), "news.example", true, Action.READ).reason());
        // carol's unmanaged phone may still read public web pages: P-10 has no device condition
        assertTrue(access.check(s.identity("carol", "phone-carol"), "news.example", true, Action.READ).allowed());
    }

    /** An authority that answers with a fixed status, to test how the gateway maps each one. */
    private static SessionAuthority answering(EdgeResult.Status status, boolean restricted) {
        return new SessionAuthority() {
            @Override
            public EdgeResult open(EdgeRequest login, PublicKey key, Optional<SignatureProof> binding) {
                throw new UnsupportedOperationException();
            }

            @Override
            public EdgeResult use(String token, SignatureProof proof, EdgeRequest request) {
                throw new UnsupportedOperationException();
            }

            @Override
            public EdgeResult decide(EdgeRequest r) {
                return new EdgeResult(status, r.requestId(), EdgeResult.genericMessage(status, r.requestId()), restricted,
                        status == EdgeResult.Status.STEP_UP ? Optional.of(AuthMethod.WEBAUTHN) : Optional.empty(),
                        Optional.empty(), false);
            }
        };
    }

    @Test
    void readOnlyAnswersAllowOnlyPlainReads() {
        WebAccess limited = s.access(SwgWorld.policy().build(), answering(EdgeResult.Status.GRANTED_LIMITED, true));
        assertTrue(limited.check(s.alice(), "news.example", false, Action.READ).allowed());
        assertEquals(Optional.of(BlockReason.READ_ONLY), limited.check(s.alice(), "news.example", false, Action.WRITE).reason());
        assertEquals(Optional.of(BlockReason.READ_ONLY), limited.check(s.alice(), "news.example", true, Action.READ).reason(),
                "a tunnel could carry an upload; read-only cannot be enforced inside it");
    }

    @Test
    void everyOtherEngineAnswerIsARefusal() {
        WebAccess stepUp = s.access(SwgWorld.policy().build(), answering(EdgeResult.Status.STEP_UP, false));
        WebVerdict v = stepUp.check(s.alice(), "news.example", true, Action.READ);
        assertEquals(Optional.of(BlockReason.STEP_UP_REQUIRED), v.reason());
        assertTrue(v.userMessage().startsWith("Additional verification"));
        for (EdgeResult.Status st : List.of(EdgeResult.Status.DENIED, EdgeResult.Status.REJECTED)) {
            assertEquals(Optional.of(BlockReason.DENIED),
                    s.access(SwgWorld.policy().build(), answering(st, false)).check(s.alice(), "news.example", true,
                            Action.READ).reason());
        }
    }

    @Test
    void aFailingOrSilentAuthorityIsADeny() {
        List<SessionAuthority> broken = new ArrayList<>();
        broken.add(new SessionAuthority() {
            @Override
            public EdgeResult open(EdgeRequest login, PublicKey key, Optional<SignatureProof> binding) {
                return null;
            }

            @Override
            public EdgeResult use(String token, SignatureProof proof, EdgeRequest request) {
                return null;
            }

            @Override
            public EdgeResult decide(EdgeRequest r) {
                throw new IllegalStateException("engine unreachable");
            }
        });
        broken.add(new SessionAuthority() {
            @Override
            public EdgeResult open(EdgeRequest login, PublicKey key, Optional<SignatureProof> binding) {
                return null;
            }

            @Override
            public EdgeResult use(String token, SignatureProof proof, EdgeRequest request) {
                return null;
            }

            @Override
            public EdgeResult decide(EdgeRequest r) {
                return null;
            }
        });
        for (SessionAuthority a : broken) {
            assertEquals(Optional.of(BlockReason.DENIED),
                    s.access(SwgWorld.policy().build(), a).check(s.alice(), "news.example", true, Action.READ).reason());
        }
    }

    @Test
    void verdictsAreConsistent() {
        assertThrows(IllegalArgumentException.class,
                () -> new WebVerdict(true, Optional.of(BlockReason.DENIED), Optional.empty(), "r-1", "m"));
        assertThrows(IllegalArgumentException.class, () -> new WebVerdict(true, Optional.empty(), Optional.empty(), "r-1", "m"));
        assertThrows(IllegalArgumentException.class, () -> new Destination(HostName.parse("a.example").orElseThrow(), 0,
                "web:general", Optional.empty(), Optional.empty()));
        assertEquals(Optional.of(BlockReason.UNKNOWN_CLIENT), access.refuse(BlockReason.UNKNOWN_CLIENT).reason());
        assertThrows(IllegalArgumentException.class, () -> new WebAccess(s.filter(WebPolicy.defaults()), s.world.authority,
                "bad region!", s.world.clock));
    }
}

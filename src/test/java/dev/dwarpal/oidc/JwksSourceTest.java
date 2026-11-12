package dev.dwarpal.oidc;

import dev.dwarpal.oidc.OidcException.Reason;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwksSourceTest {

    private FakeIdp idp;
    private FakeIdp.TestClock clock;
    private OidcDiscovery discovery;
    private JwksSource source;

    @BeforeEach
    void start() throws IOException {
        clock = new FakeIdp.TestClock(TestTokens.NOW);
        idp = new FakeIdp(clock);
        discovery = OidcDiscovery.fetch(idp.issuer(), OidcHttp.forLoopbackTests());
        source = new JwksSource(discovery, OidcHttp.forLoopbackTests(), clock);
    }

    @AfterEach
    void stop() {
        idp.close();
    }

    private static void unavailable(Runnable call) {
        OidcException e = assertThrows(OidcException.class, call::run);
        assertEquals(Reason.KEYS_UNAVAILABLE, e.reason());
        assertEquals(Reason.KEYS_UNAVAILABLE.message(), e.getMessage());
    }

    @Test
    void nothingIsFetchedUntilKeysAreNeededThenTheyAreCachedForTenMinutes() {
        assertEquals(0, idp.jwksRequests());
        JwkSet first = source.current();
        assertEquals(3, first.size());
        assertSame(first, source.current());
        clock.advance(Duration.ofMinutes(9).plusSeconds(59));
        assertSame(first, source.current());
        assertEquals(1, idp.jwksRequests());
        clock.advance(Duration.ofSeconds(1));
        JwkSet second = source.current();
        assertNotSame(first, second);
        assertEquals(2, idp.jwksRequests());
        assertEquals(1, idp.discoveryRequests());
    }

    @Test
    void refreshForAnUnknownKeyIsLimitedToOneRequestPerThirtySeconds() {
        JwkSet first = source.current();
        idp.rotate();
        assertSame(first, source.refreshForUnknownKey());
        assertEquals(1, idp.jwksRequests());
        clock.advance(Duration.ofSeconds(29));
        assertSame(first, source.refreshForUnknownKey());
        assertEquals(1, idp.jwksRequests());
        clock.advance(Duration.ofSeconds(1));
        JwkSet second = source.refreshForUnknownKey();
        assertNotSame(first, second);
        assertTrue(second.find("rsa-2").isPresent());
        assertTrue(second.find("rsa-1").isEmpty());
        assertEquals(2, idp.jwksRequests());
        assertSame(second, source.refreshForUnknownKey());
        assertEquals(2, idp.jwksRequests());
    }

    @Test
    void aFloodOfRefreshCallsCausesAtMostOneRequestPerThirtySeconds() {
        source.current();
        int seconds = 0;
        for (int step = 0; step < 100; step++) {
            for (int i = 0; i < 50; i++) {
                source.refreshForUnknownKey();
            }
            clock.advance(Duration.ofSeconds(3));
            seconds += 3;
        }
        // 297 simulated seconds: the first fetch (t=0) and one at each of t=30, 60 ... 270
        assertEquals(10, idp.jwksRequests());
        assertTrue(idp.jwksRequests() <= 1 + seconds / 30);
    }

    @Test
    void manyThreadsAtOnceCauseASingleRequest() throws Exception {
        int threads = 24;
        CountDownLatch go = new CountDownLatch(1);
        List<Future<JwkSet>> results = new ArrayList<>();
        try (ExecutorService pool = Executors.newFixedThreadPool(threads)) {
            for (int i = 0; i < threads; i++) {
                boolean viaCurrent = i % 2 == 0;
                results.add(pool.submit(() -> {
                    go.await();
                    return viaCurrent ? source.current() : source.refreshForUnknownKey();
                }));
            }
            go.countDown();
            JwkSet first = results.get(0).get();
            for (Future<JwkSet> f : results) {
                assertSame(first, f.get());
            }
        }
        assertEquals(1, idp.jwksRequests());
    }

    @Test
    void anOutageKeepsTheOldKeysForUnderAnHourThenFailsClosed() {
        JwkSet good = source.current();
        idp.jwksStatus(503);
        clock.advance(Duration.ofMinutes(11));
        assertSame(good, source.current());
        assertEquals(2, idp.jwksRequests());
        clock.advance(Duration.ofMinutes(48).plusSeconds(58));       // 59 min 58 s since the good fetch
        assertSame(good, source.current());
        clock.advance(Duration.ofSeconds(1));
        assertSame(good, source.current());                           // 59 min 59 s
        clock.advance(Duration.ofSeconds(1));                         // 60 min
        unavailable(source::current);
        unavailable(source::refreshForUnknownKey);
        // when the provider returns, the next allowed attempt recovers
        idp.jwksStatus(200);
        clock.advance(Duration.ofSeconds(30));
        assertEquals(3, source.current().size());
    }

    @Test
    void aFirstFetchThatFailsGivesNoKeysAndIsRetriedOnlyAfterThirtySeconds() {
        idp.jwksStatus(500);
        unavailable(source::current);
        unavailable(source::current);
        unavailable(source::refreshForUnknownKey);
        assertEquals(1, idp.jwksRequests());
        idp.jwksStatus(200);
        clock.advance(Duration.ofSeconds(30));
        assertEquals(3, source.current().size());
        assertEquals(2, idp.jwksRequests());
    }

    @Test
    void anInvalidNewKeySetNeverReplacesAGoodOne() {
        JwkSet good = source.current();
        String dup = TestTokens.jwks(List.of(TestTokens.RSA_1.jwk(), TestTokens.RSA_1.jwk()));
        String weak = TestTokens.jwks(List.of(TestTokens.Signer.rsa("weak", 1024).jwk()));
        Map<String, String> offCurve = TestTokens.EC_1.jwk();
        offCurve.put("y", TestTokens.q(TestTokens.b64(new byte[32])));
        String[] poisoned = {"not json", "{}", "{\"keys\":5}", "{\"keys\":[5]}", dup, weak,
            TestTokens.jwks(offCurve), "{\"keys\":[]}", "{\"keys\":[{\"kty\":\"oct\",\"k\":\"AAAA\"}]}",
            "[" + "[".repeat(100)};
        int requests = 1;
        for (String text : poisoned) {
            idp.jwksBody(text);
            clock.advance(Duration.ofSeconds(30));
            assertSame(good, source.refreshForUnknownKey(), text);
            assertEquals(++requests, idp.jwksRequests());
        }
        // a good set afterwards is taken
        idp.jwksBody(null);
        clock.advance(Duration.ofSeconds(30));
        assertNotSame(good, source.refreshForUnknownKey());
    }

    @Test
    void aRedirectAnOversizedBodyOrTheWrongMediaTypeNeverReplaceAGoodSet() {
        JwkSet good = source.current();
        int requests = 1;
        idp.jwksRedirect(true);
        clock.advance(Duration.ofMinutes(11));
        assertSame(good, source.current());
        idp.jwksRedirect(false);
        idp.jwksOversized(true);
        clock.advance(Duration.ofMinutes(11));
        assertSame(good, source.current());
        idp.chunked(true);
        clock.advance(Duration.ofMinutes(11));
        assertSame(good, source.current());
        idp.chunked(false);
        idp.jwksOversized(false);
        idp.jwksContentType("text/html");
        clock.advance(Duration.ofMinutes(11));
        assertSame(good, source.current());
        assertEquals(requests + 4, idp.jwksRequests());
    }

    @Test
    void aRedirectIsNotFollowedEvenForTheFirstFetch() {
        idp.jwksRedirect(true);
        unavailable(source::current);
        assertEquals(1, idp.jwksRequests());
    }

    @Test
    void anEmptyKeySetIsNotAGoodSet() {
        idp.jwksBody("{\"keys\":[]}");
        unavailable(source::current);
    }

    @Test
    void theJwkSetMediaTypeIsAccepted() {
        idp.jwksContentType("application/jwk-set+json");
        assertEquals(3, source.current().size());
        clock.advance(Duration.ofMinutes(11));
        idp.jwksContentType("application/octet-stream");
        source.current();
        assertEquals(2, idp.jwksRequests());
    }

    @Test
    void onlyTheDiscoveredKeyAddressIsEverContacted() {
        source.current();
        clock.advance(Duration.ofMinutes(11));
        source.current();
        source.refreshForUnknownKey();
        assertEquals(1, idp.discoveryRequests());          // only the fetch made in setUp
        assertEquals(2, idp.jwksRequests());
        assertEquals(discovery.jwksUri(), java.net.URI.create(idp.issuer() + "/jwks"));
    }

    @Test
    void aSlowServerIsRefusedWithinTheTimeout() {
        // headers at once, then one byte every 200 ms: the whole answer cannot arrive in time
        idp.jwksDrip(200);
        JwksSource slow = new JwksSource(discovery, OidcHttp.forLoopbackTests(), clock);
        long start = System.nanoTime();
        unavailable(slow::current);
        long millis = (System.nanoTime() - start) / 1_000_000;
        assertTrue(millis < 8_000, "took " + millis + " ms");
        assertTrue(millis >= 4_000, "gave up too early: " + millis + " ms");
    }

    @Test
    void aServerThatNeverAnswersIsRefusedAtTheRequestLimit() {
        idp.jwksDelay(30_000);
        OidcHttp shortLimit = new OidcHttp(true, Duration.ofSeconds(1));
        JwksSource slow = new JwksSource(discovery, shortLimit, clock);
        long start = System.nanoTime();
        unavailable(slow::current);
        long millis = (System.nanoTime() - start) / 1_000_000;
        assertTrue(millis < 4_000, "took " + millis + " ms");
    }
}

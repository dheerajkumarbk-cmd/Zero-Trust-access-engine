package dev.dwarpal.api;

import dev.dwarpal.Fixtures;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.edge.ClientProofs;
import dev.dwarpal.edge.EdgeFixtures;
import dev.dwarpal.edge.EdgeGrant;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The drill: the engine API goes away and comes back. Every call is DENIED while it is gone, the alarm fires
 * once on each edge, and readiness tells the operator which part is failing without leaking any text.
 */
class FailClosedDrillTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(2);

    /** Counts the edges. */
    private static final class Recorder implements EngineAlarm {
        final AtomicInteger downs = new AtomicInteger();
        final AtomicInteger backs = new AtomicInteger();
        final AtomicLong failuresAtDown = new AtomicLong();
        final EngineAlarm also;

        Recorder(EngineAlarm also) {
            this.also = also;
        }

        @Override
        public void engineDown(long consecutiveFailures, Instant at) {
            downs.incrementAndGet();
            failuresAtDown.set(consecutiveFailures);
            also.engineDown(consecutiveFailures, at);
        }

        @Override
        public void engineBack(Instant at) {
            backs.incrementAndGet();
            also.engineBack(at);
        }
    }

    private static ApiServer server(EdgeFixtures.World w, int port, List<Readiness> checks) throws Exception {
        return ApiServer.builder(w.audit, w.pam).tls(ApiKit.ctx("api")).authority(w.authority)
                .administrator(w.administrator).clock(w.clock).callers(ApiKit.CALLERS)
                .address(new InetSocketAddress(InetAddress.getLoopbackAddress(), port)).readiness(checks)
                .build().start();
    }

    private static ApiKit.Raw raw(ApiServer s, String leaf) {
        return new ApiKit.Raw(URI.create("https://localhost:" + s.port()), ApiKit.ctx(leaf));
    }

    /** As the device agent does it: a login carrying signed posture is bound to the session key. */
    private static EdgeResult open(EdgeFixtures.World w, RemoteSessionAuthority pep, KeyPair key) {
        EdgeRequest login = w.request().build();
        Optional<SignatureProof> binding = login.evidence().postureProof().isPresent()
                ? Optional.of(ClientProofs.bindDevice(Fixtures.DEVICE_AGENT.getPrivate(), Fixtures.DEVICE_KEY_ID,
                login, key.getPublic(), w.clock.now()))
                : Optional.empty();
        return pep.open(login, key.getPublic(), binding);
    }

    private static EdgeResult timed(Supplier<EdgeResult> call) {
        long t0 = System.nanoTime();
        EdgeResult r = call.get();
        long ms = (System.nanoTime() - t0) / 1_000_000;
        assertTrue(ms < TIMEOUT.toMillis() + 1000, "answered after " + ms + " ms");
        return r;
    }

    @Test
    void engineGoesDownEverythingIsDeniedOnceAlarmedAndComesBack(@TempDir Path dir) throws Exception {
        EdgeFixtures.World w = EdgeFixtures.world();
        Path alarmFile = dir.resolve("engine-alarm.log");
        Recorder rec = new Recorder(new FileEngineAlarm(alarmFile));
        ApiServer up = server(w, 0, List.of(Readiness.of("policy", () -> true)));
        int port = up.port();
        URI base = URI.create("https://localhost:" + port);
        KeyPair key = Ed25519.generateKeyPair();
        try (RemoteSessionAuthority pep = RemoteSessionAuthority.create(base, ApiKit.ctx("gateway"), TIMEOUT, rec, 5);
             ApiKit.Raw raw = new ApiKit.Raw(base, ApiKit.ctx("gateway"))) {
            // engine up: answers normally, ready
            assertEquals(200, raw.get("/v1/ready").status());
            EdgeResult opened = open(w, pep, key);
            assertEquals(EdgeResult.Status.OPENED, opened.status());
            EdgeGrant grant = opened.grant().orElseThrow();
            assertEquals(EdgeResult.Status.GRANTED, pep.decide(w.request().resource("web:general").build()).status());
            assertEquals(0, rec.downs.get());

            // engine stopped: open, use and decide are all DENIED within timeout + 1 s
            up.close();
            for (int i = 0; i < 2; i++) {
                assertEquals(EdgeResult.Status.DENIED, timed(() -> open(w, pep, key)).status());
                EdgeRequest use = w.request().build();
                assertEquals(EdgeResult.Status.DENIED, timed(() -> pep.use(grant.token(),
                        ClientProofs.sign(key.getPrivate(), grant.sessionId(), use, w.clock.now()), use)).status());
                assertEquals(EdgeResult.Status.DENIED, timed(() ->
                        pep.decide(w.request().resource("web:general").build())).status());
            }
            // six failures: the alarm fired exactly once, at the threshold
            assertEquals(1, rec.downs.get());
            assertEquals(5, rec.failuresAtDown.get());
            assertEquals(0, rec.backs.get());
            assertEquals(6, pep.failures());
            String lines = Files.readString(alarmFile);
            assertEquals(1, lines.lines().count(), lines);
            assertTrue(lines.startsWith("{\"event\":\"engine-down\",\"at\":\""), lines);
            assertTrue(lines.contains("\"failures\":5}"), lines);

            // a new server on the same address: the next call answers normally, engineBack fires once
            try (ApiServer again = server(w, port, List.of())) {
                assertEquals(port, again.port());
                assertEquals(EdgeResult.Status.GRANTED, pep.decide(w.request().resource("web:general").build()).status());
                assertEquals(EdgeResult.Status.GRANTED, pep.decide(w.request().resource("web:general").build()).status());
                assertEquals(1, rec.backs.get());
                assertEquals(1, rec.downs.get());
            }
            List<String> all = Files.readAllLines(alarmFile);
            assertEquals(2, all.size());
            assertTrue(all.get(1).contains("\"event\":\"engine-back\""));
        }
    }

    @Test
    void anAlarmThatThrowsDoesNotChangeTheAnswer() throws Exception {
        EdgeFixtures.World w = EdgeFixtures.world();
        ApiServer up = server(w, 0, List.of());
        URI base = URI.create("https://localhost:" + up.port());
        up.close();
        EngineAlarm bad = new EngineAlarm() {
            @Override
            public void engineDown(long n, Instant at) {
                throw new IllegalStateException("alarm broke");
            }

            @Override
            public void engineBack(Instant at) {
                throw new IllegalStateException("alarm broke");
            }
        };
        try (RemoteSessionAuthority pep = RemoteSessionAuthority.create(base, ApiKit.ctx("gateway"), TIMEOUT, bad, 2)) {
            for (int i = 0; i < 4; i++) {
                assertEquals(EdgeResult.Status.DENIED, pep.decide(w.request().build()).status());
            }
            assertEquals(1, pep.alarmFailures(), "edge-triggered: one call, which threw");
            assertEquals(4, pep.failures());
        }
    }

    @Test
    void aFileAlarmStopsAtItsCapAndCounts(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("a.log");
        FileEngineAlarm a = new FileEngineAlarm(f, 100);
        for (int i = 0; i < 10; i++) {
            a.engineDown(5, Instant.parse("2026-01-01T00:00:00Z"));
        }
        assertTrue(Files.size(f) <= 100);
        assertTrue(a.dropped() > 0);
    }

    @Test
    void readinessNamesOnlyTheFailingChecksAndNeverLeaksText() throws Exception {
        EdgeFixtures.World w = EdgeFixtures.world();
        List<Readiness> checks = List.of(
                Readiness.of("policy", () -> true),
                Readiness.of("audit", () -> false),
                Readiness.of("store", () -> {
                    throw new IllegalStateException("secret-detail jdbc-url password");
                }));
        try (ApiServer s = server(w, 0, checks); ApiKit.Raw pep = raw(s, "gateway");
             ApiKit.Raw stranger = raw(s, "stranger")) {
            ApiKit.Reply r = pep.get("/v1/ready");
            assertEquals(503, r.status());
            assertEquals("{\"status\":\"not ready\",\"failing\":[\"audit\",\"store\"]}", r.body());
            assertFalse(r.body().contains("secret") || r.body().contains("Exception"));
            assertEquals(403, stranger.get("/v1/ready").status(), "behind mutual TLS and the caller list");
            assertEquals(405, pep.post("/v1/ready", "{}").status());
            assertEquals(200, pep.get("/v1/health").status(), "liveness is unchanged");
        }
        try (ApiServer s = server(w, 0, List.of(Readiness.of("policy", () -> true))); ApiKit.Raw pep = raw(s, "gateway")) {
            ApiKit.Reply r = pep.get("/v1/ready");
            assertEquals(200, r.status());
            assertEquals("{\"status\":\"ready\"}", r.body());
        }
        try (ApiServer s = server(w, 0, List.of()); ApiKit.Raw pep = raw(s, "gateway")) {
            assertEquals(200, pep.get("/v1/ready").status(), "no checks registered: ready");
        }
    }

    @Test
    void readinessNamesAreFixedIdentifiers() {
        for (String bad : new String[]{"", "Policy", "a b", "x".repeat(33), "a1", "a\"b", null}) {
            assertThrows(IllegalArgumentException.class, () -> Readiness.of(bad, () -> true), String.valueOf(bad));
        }
        Readiness.of("audit-trail", () -> true);
    }
}

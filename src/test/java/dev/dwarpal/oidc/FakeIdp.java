package dev.dwarpal.oidc;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Test-only identity provider on a loopback port. It serves {@code /.well-known/openid-configuration}
 * and {@code /jwks}, holds an RS256, an ES256 and an Ed25519 key, mints tokens, rotates its keys,
 * counts key-set requests, and can misbehave on demand (wrong issuer, other host, oversized, redirect,
 * wrong media type, slow, failing, garbage key set).
 */
final class FakeIdp implements AutoCloseable {

    /** A clock the test moves by hand, so no test has to sleep. */
    static final class TestClock extends Clock {
        private final AtomicReference<Instant> now;

        TestClock(Instant start) {
            this.now = new AtomicReference<>(start);
        }

        void advance(java.time.Duration d) {
            now.updateAndGet(i -> i.plus(d));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }

    private final Clock clock;
    private final HttpServer server;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final String issuer;
    private final AtomicInteger jwksRequests = new AtomicInteger();
    private final AtomicInteger discoveryRequests = new AtomicInteger();
    private final AtomicInteger rotations = new AtomicInteger();

    private volatile List<TestTokens.Signer> active = List.of(TestTokens.RSA_1, TestTokens.EC_1, TestTokens.ED_1);
    private volatile List<TestTokens.Signer> retired = List.of();

    // misbehaviour switches
    private volatile String documentIssuer;
    private volatile String jwksUriOverride;
    private volatile boolean discoveryRedirect;
    private volatile boolean jwksRedirect;
    private volatile boolean discoveryOversized;
    private volatile boolean jwksOversized;
    private volatile String discoveryContentType = "application/json";
    private volatile String jwksContentType = "application/json";
    private volatile int jwksStatus = 200;
    private volatile String jwksBodyOverride;
    private volatile long jwksDelayMillis;
    private volatile long jwksDripMillis;
    private volatile boolean chunked;
    private volatile String discoveryBodyOverride;
    private volatile int discoveryStatus = 200;

    FakeIdp(Clock clock) throws IOException {
        this.clock = clock;
        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        this.server.createContext("/", this::handle);
        this.server.setExecutor(executor);
        this.server.start();
        this.issuer = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /** The issuer this provider calls itself (and the base of every URL it serves). */
    String issuer() {
        return issuer;
    }

    OidcPolicy policy() {
        return OidcPolicy.of(issuer, TestTokens.CLIENT);
    }

    int jwksRequests() {
        return jwksRequests.get();
    }

    int discoveryRequests() {
        return discoveryRequests.get();
    }

    // keys and tokens

    /** The current key for the algorithm (RS256, ES256 or EdDSA). */
    TestTokens.Signer signer(String alg) {
        return pick(active, alg);
    }

    /** The key that {@link #rotate()} dropped, for the algorithm. */
    TestTokens.Signer retiredSigner(String alg) {
        return pick(retired, alg);
    }

    private static TestTokens.Signer pick(List<TestTokens.Signer> from, String alg) {
        return from.stream().filter(s -> s.alg().equals(alg)).findFirst().orElseThrow();
    }

    /** Adds a new key of each type and drops the old ones: the next JWKS lists only the new keys. */
    void rotate() {
        List<TestTokens.Signer> next;
        if (rotations.incrementAndGet() == 1) {
            next = List.of(TestTokens.RSA_2, TestTokens.EC_2, TestTokens.ED_2);
        } else {
            String n = Integer.toString(rotations.get());
            next = List.of(TestTokens.Signer.rsa("rsa-r" + n, 2048), TestTokens.Signer.ec("ec-r" + n),
                    TestTokens.Signer.ed("ed-r" + n));
        }
        retired = active;
        active = next;
    }

    /** A valid token for the given algorithm, with the clock's current time. */
    String mint(String alg, String nonce) {
        return mint(signer(alg), nonce);
    }

    String mint(TestTokens.Signer signer, String nonce) {
        Map<String, String> c = new LinkedHashMap<>();
        long now = clock.instant().getEpochSecond();
        c.put("iss", TestTokens.q(issuer));
        c.put("aud", TestTokens.q(TestTokens.CLIENT));
        c.put("sub", TestTokens.q(TestTokens.SUBJECT));
        c.put("nonce", TestTokens.q(nonce));
        c.put("iat", Long.toString(now - 30));
        c.put("exp", Long.toString(now + 300));
        return TestTokens.mint(signer, TestTokens.header(signer), c);
    }

    /** A token carrying a key id the provider never published. */
    String mintWithUnknownKid(String alg, String nonce, String kid) {
        TestTokens.Signer real = signer(alg);
        TestTokens.Signer renamed = new TestTokens.Signer(kid, real.alg(), real.priv(), real.pub());
        return mint(renamed, nonce);
    }

    // switches

    void documentIssuer(String value) {
        this.documentIssuer = value;
    }

    void jwksUri(String value) {
        this.jwksUriOverride = value;
    }

    void discoveryRedirect(boolean on) {
        this.discoveryRedirect = on;
    }

    void jwksRedirect(boolean on) {
        this.jwksRedirect = on;
    }

    void discoveryOversized(boolean on) {
        this.discoveryOversized = on;
    }

    void jwksOversized(boolean on) {
        this.jwksOversized = on;
    }

    void discoveryContentType(String value) {
        this.discoveryContentType = value;
    }

    void jwksContentType(String value) {
        this.jwksContentType = value;
    }

    /** Answer the key-set request with this status instead of 200 (an outage). */
    void jwksStatus(int status) {
        this.jwksStatus = status;
    }

    /** Serve this text as the key set (for a broken or hostile set); null goes back to the real keys. */
    void jwksBody(String text) {
        this.jwksBodyOverride = text;
    }

    /** Wait this long before answering the key-set request at all. */
    void jwksDelay(long millis) {
        this.jwksDelayMillis = millis;
    }

    /** Send the key-set headers at once, then the body one byte per this many milliseconds. */
    void jwksDrip(long millis) {
        this.jwksDripMillis = millis;
    }

    /** Serve this text as the discovery document; null goes back to the real one. */
    void discoveryBody(String text) {
        this.discoveryBodyOverride = text;
    }

    /** Answer the discovery request with this status instead of 200. */
    void discoveryStatus(int status) {
        this.discoveryStatus = status;
    }

    /** Send bodies without a declared length (chunked), so only the streaming cap can stop an oversized one. */
    void chunked(boolean on) {
        this.chunked = on;
    }

    // server

    private String jwksText() {
        String override = jwksBodyOverride;
        if (override != null) {
            return override;
        }
        List<Map<String, String>> keys = new ArrayList<>();
        for (TestTokens.Signer s : active) {
            keys.add(s.jwk());
        }
        return TestTokens.jwks(keys);
    }

    private String discoveryText() {
        String override = discoveryBodyOverride;
        if (override != null) {
            return override;
        }
        String iss = documentIssuer != null ? documentIssuer : issuer;
        String jwks = jwksUriOverride != null ? jwksUriOverride : issuer + "/jwks";
        return "{\"issuer\":" + TestTokens.q(iss)
                + ",\"jwks_uri\":" + TestTokens.q(jwks)
                + ",\"authorization_endpoint\":" + TestTokens.q(issuer + "/authorize")
                + ",\"token_endpoint\":" + TestTokens.q(issuer + "/token")
                + ",\"authorization_response_iss_parameter_supported\":true"
                + ",\"id_token_signing_alg_values_supported\":[\"RS256\",\"ES256\",\"EdDSA\"]}";
    }

    private void handle(HttpExchange ex) {
        try (ex) {
            String path = ex.getRequestURI().getRawPath();
            if (!"GET".equals(ex.getRequestMethod())) {
                reply(ex, 405, "text/plain", "no");
            } else if ("/.well-known/openid-configuration".equals(path)) {
                discoveryRequests.incrementAndGet();
                serve(ex, discoveryRedirect, discoveryOversized, discoveryContentType, discoveryStatus, discoveryText(), 0, 0);
            } else if ("/jwks".equals(path)) {
                jwksRequests.incrementAndGet();
                serve(ex, jwksRedirect, jwksOversized, jwksContentType, jwksStatus, jwksText(), jwksDelayMillis,
                        jwksDripMillis);
            } else if ("/redirected".equals(path)) {
                reply(ex, 200, "application/json", jwksText());
            } else {
                reply(ex, 404, "text/plain", "no");
            }
        } catch (IOException | RuntimeException e) {
            // the client gave up (timeouts and caps do that on purpose); nothing to do
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void serve(HttpExchange ex, boolean redirect, boolean oversized, String type, int status, String text,
                       long delayMillis, long dripMillis) throws IOException, InterruptedException {
        if (delayMillis > 0) {
            Thread.sleep(delayMillis);
        }
        if (redirect) {
            ex.getResponseHeaders().add("Location", issuer + "/redirected");
            ex.sendResponseHeaders(302, -1);
            return;
        }
        String body = text;
        if (oversized) {
            body = text + " ".repeat(JwkSet.MAX_BYTES + 1024);
        }
        if (dripMillis > 0) {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", type);
            ex.sendResponseHeaders(status, 0);
            OutputStream out = ex.getResponseBody();
            for (byte b : bytes) {
                out.write(b);
                out.flush();
                Thread.sleep(dripMillis);
            }
            return;
        }
        if (chunked) {
            ex.getResponseHeaders().add("Content-Type", type);
            ex.sendResponseHeaders(status, 0);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(body.getBytes(StandardCharsets.UTF_8));
            }
            return;
        }
        reply(ex, status, type, body);
    }

    private static void reply(HttpExchange ex, int status, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", type);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }
}

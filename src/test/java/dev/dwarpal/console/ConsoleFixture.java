package dev.dwarpal.console;

import dev.dwarpal.edge.DevPki;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.lab.LabConfig;
import dev.dwarpal.lab.LabRunner;
import dev.dwarpal.lab.LabWorld;
import dev.dwarpal.soar.Analyst;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * The real thing for the tests: a real lab world (built once, it is the slow part), the real console server on a free
 * loopback port with TLS 1.3, and a real HTTPS client that trusts only the lab CA. Nothing of the security parts is
 * mocked. Each test class starts its own server (cheap) so that throttles and session tables do not leak between them.
 */
final class ConsoleFixture implements AutoCloseable {

    /** A clock the tests move; sessions, throttles and step-up use it, scenario time does not. */
    static final class TestClock extends Clock {
        private volatile Instant now = Instant.parse("2026-11-05T09:00:00Z");

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    record Sess(String cookie, String csrf, String user) {
    }

    record Resp(int status, String body, HttpHeaders headers) {
        JsonValue json() {
            return new JsonReader().read(body);
        }

        String field(String name) {
            return ((JsonValue.JString) ((JsonValue.JObject) json()).get(name).orElseThrow()).value();
        }

        String header(String name) {
            return headers.firstValue(name).orElse(null);
        }
    }

    static final String UA = "ConsoleTest/1";
    private static LabWorld shared;

    final LabWorld world;
    final TestClock clock = new TestClock();
    final List<ConsoleAuth.Enrolment> people = DemoPeople.fresh();
    final ConsoleServer server;
    final String base;
    final String origin;
    final HttpClient http;
    final DevPki pki;

    /** The one lab world of the test run: 30 users, the whole script played, so that there are P1s to decide. */
    static synchronized LabWorld world() throws Exception {
        if (shared == null) {
            shared = LabWorld.create(LabConfig.defaults(Files.createTempDirectory("dwarpal-console-test")).withPort(0)
                    .withUsers(30));
            shared.advanceTo(shared.scriptEnd);
            LabWorld w = shared;
            Runtime.getRuntime().addShutdownHook(new Thread(w::close));
        }
        return shared;
    }

    static ConsoleFixture start() throws Exception {
        return start(b -> {
        }, ConsoleSettings.defaults().fastHashing());
    }

    static ConsoleFixture start(Consumer<ConsoleServer.Builder> tweak, ConsoleSettings settings) throws Exception {
        return new ConsoleFixture(tweak, settings);
    }

    private ConsoleFixture(Consumer<ConsoleServer.Builder> tweak, ConsoleSettings settings) throws Exception {
        world = world();
        pki = world.pki;
        SSLContext serverTls = TlsContexts.create(pki.keyStore("console"), pki.password(), pki.trustStore(), pki.password());
        Set<String> analysts = LabWorld.ANALYSTS.stream().map(Analyst::id).collect(Collectors.toSet());
        LabHandle lab = LabHandle.of(world, new LabRunner(world, 60));
        SocChannel channel = new DelegatedSocChannel(pki, () -> lab.world().socApiUrl(), () -> lab.world().delegationIssuer(),
                analysts, Duration.ofSeconds(10));
        ConsoleAuth auth = new ConsoleAuth(people, clock, settings.passwordIterations(), settings.pinIterations());
        ConsoleServer.Builder b = ConsoleServer.builder(lab, channel, new LabVerdictSigner(lab), auth, serverTls)
                .settings(settings).wallClock(clock).staticRoot("consolefixture");
        b.address(new java.net.InetSocketAddress(java.net.InetAddress.getLoopbackAddress(), 0));
        tweak.accept(b);
        server = b.build().start();
        base = "https://localhost:" + server.port();
        origin = base;
        http = HttpClient.newBuilder().sslContext(trustOnlyTheLabCa(pki)).version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();
    }

    static SSLContext trustOnlyTheLabCa(DevPki pki) throws Exception {
        KeyStore ts = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(pki.trustStore())) {
            ts.load(in, pki.password());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(ts);
        SSLContext c = SSLContext.getInstance("TLSv1.3");
        c.init(null, tmf.getTrustManagers(), null);
        return c;
    }

    ConsoleAuth.Enrolment person(String id) {
        return people.stream().filter(e -> e.person().id().equals(id)).findFirst().orElseThrow();
    }

    // ---- requests -----------------------------------------------------------------------------------------

    Resp raw(String method, String path, Map<String, String> headers, String body) throws IOException, InterruptedException {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).timeout(Duration.ofSeconds(15));
        headers.forEach(b::header);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return new Resp(r.statusCode(), r.body(), r.headers());
    }

    Resp get(String path, Sess s) throws IOException, InterruptedException {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("User-Agent", UA);
        if (s != null) {
            h.put("Cookie", ConsoleServer.COOKIE + "=" + s.cookie());
        }
        return raw("GET", path, h, null);
    }

    /** What an open page sends when it refreshes itself, as opposed to something the person did. */
    Resp backgroundGet(String path, Sess s) throws IOException, InterruptedException {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("User-Agent", UA);
        h.put("Cookie", ConsoleServer.COOKIE + "=" + s.cookie());
        h.put(ConsoleServer.BACKGROUND_HEADER, "1");
        return raw("GET", path, h, null);
    }

    /** A well-formed write: cookie, anti-forgery token, own Origin, JSON. */
    Resp post(String path, Sess s, String body) throws IOException, InterruptedException {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("User-Agent", UA);
        h.put("Origin", origin);
        h.put("Content-Type", "application/json");
        if (s != null) {
            h.put("Cookie", ConsoleServer.COOKIE + "=" + s.cookie());
            h.put(ConsoleServer.CSRF_HEADER, s.csrf());
        }
        return raw("POST", path, h, body);
    }

    Resp login(String user, String password, String pin) throws IOException, InterruptedException {
        Resp first = post("/console/api/session/login", null, "{\"user\":\"" + user + "\",\"password\":\"" + password + "\"}");
        if (first.status() != 200) {
            return first;
        }
        return post("/console/api/session/verify", null, "{\"loginId\":\"" + first.field("loginId") + "\",\"pin\":\"" + pin
                + "\"}");
    }

    Sess login(String id) throws IOException, InterruptedException {
        ConsoleAuth.Enrolment e = person(id);
        Resp r = login(id, e.password(), e.pin());
        if (r.status() != 200) {
            throw new IllegalStateException("login of " + id + " failed: " + r.status() + " " + r.body());
        }
        return new Sess(cookieValue(r), r.field("csrf"), id);
    }

    static String cookieValue(Resp r) {
        for (String c : r.headers().allValues("Set-Cookie")) {
            if (c.startsWith(ConsoleServer.COOKIE + "=")) {
                String v = c.substring(ConsoleServer.COOKIE.length() + 1, c.indexOf(';'));
                return v;
            }
        }
        throw new IllegalStateException("no session cookie in the answer");
    }

    Sess stepUp(Sess s) throws IOException, InterruptedException {
        ConsoleAuth.Enrolment e = person(s.user());
        Resp r = post("/console/api/session/stepup", s, "{\"password\":\"" + e.password() + "\",\"pin\":\"" + e.pin() + "\"}");
        if (r.status() != 200) {
            throw new IllegalStateException("step-up failed: " + r.status() + " " + r.body());
        }
        return new Sess(cookieValue(r), r.field("csrf"), s.user());
    }

    @Override
    public void close() {
        server.close();
    }
}

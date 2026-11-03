package dev.dwarpal.api;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.edge.ClientProofs;
import dev.dwarpal.edge.DevPki;
import dev.dwarpal.edge.EdgeFixtures;
import dev.dwarpal.edge.EdgeGrant;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.SessionAuthority;
import dev.dwarpal.edge.TlsContexts;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * Test kit for the engine API: one development PKI for the whole test run (keytool is slow), a
 * running API in front of the shared {@link EdgeFixtures} world, and raw HTTPS helpers for abuse tests.
 */
final class ApiKit {

    static final List<Caller> CALLERS = List.of(
            Caller.component("gateway", CallerRole.PEP),
            Caller.component("swg", CallerRole.PEP),
            Caller.component("console", CallerRole.ADMIN_CONSOLE),
            Caller.component("soc", CallerRole.SOC));

    private static DevPki pki;
    private static DevPki rogue;

    private ApiKit() {
    }

    /** The Dwarpal development CA; {@code stranger} has a valid certificate but is not a configured caller. */
    static synchronized DevPki pki() {
        if (pki == null) {
            try {
                Path dir = Files.createTempDirectory("dwarpal-api-pki");
                pki = DevPki.create(dir.resolve("dwarpal"), "Dwarpal Dev CA", List.of(DevPki.Leaf.valid("api"),
                        DevPki.Leaf.valid("gateway"), DevPki.Leaf.valid("swg"), DevPki.Leaf.valid("console"),
                        DevPki.Leaf.valid("soc"), DevPki.Leaf.valid("stranger"),
                        DevPki.Leaf.expired("old-gateway")));
                rogue = DevPki.create(dir.resolve("rogue"), "Some Other CA", List.of(DevPki.Leaf.valid("gateway")));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
        return pki;
    }

    /** Another CA that also issued a certificate named {@code gateway}. */
    static synchronized DevPki rogue() {
        pki();
        return rogue;
    }

    static RemoteSessionAuthority pinned(URI base, String leaf) {
        try {
            return RemoteSessionAuthority.connect(base, pki().keyStore(leaf), pki().password(), pki().trustStore(),
                    pki().password(), TlsContexts.component("api"), Duration.ofSeconds(5));
        } catch (IOException | java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static SSLContext ctx(String leaf) {
        return ctx(pki(), leaf);
    }

    static SSLContext ctx(DevPki from, String leaf) {
        try {
            return TlsContexts.create(from.keyStore(leaf), from.password(), pki().trustStore(), pki().password());
        } catch (IOException | java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The shared world behind a running API. */
    static final class Harness implements AutoCloseable {
        final EdgeFixtures.World world;
        final ApiServer server;
        final URI base;

        Harness(ApiSettings settings) {
            this(EdgeFixtures.world(), settings, null, null);
        }

        Harness(EdgeFixtures.World world, ApiSettings settings, SessionAuthority authority, AuditLog audit) {
            this.world = world;
            try {
                server = ApiServer.builder(audit == null ? world.audit : audit, world.pam).tls(ctx("api"))
                        .authority(authority == null ? world.authority : authority)
                        .administrator(world.administrator).clock(world.clock)
                        .callers(CALLERS).settings(settings).build().start();
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            base = URI.create("https://localhost:" + server.port());
        }

        /** The client as an enforcement point runs it: its certificate, the CA, and the API pinned. */
        RemoteSessionAuthority client(String leaf) {
            return pinned(base, leaf);
        }

        /** Logs in over the API, with the device agent's binding when the login carries signed posture. */
        EdgeResult open(SessionAuthority via, KeyPair sessionKey, EdgeRequest login) {
            Optional<SignatureProof> binding = login.evidence().postureProof().isPresent()
                    ? Optional.of(ClientProofs.bindDevice(Fixtures.DEVICE_AGENT.getPrivate(), Fixtures.DEVICE_KEY_ID,
                    login, sessionKey.getPublic(), world.clock.now()))
                    : Optional.empty();
            return via.open(login, sessionKey.getPublic(), binding);
        }

        EdgeResult use(SessionAuthority via, KeyPair sessionKey, EdgeGrant grant, EdgeRequest request) {
            return via.use(grant.token(),
                    ClientProofs.sign(sessionKey.getPrivate(), grant.sessionId(), request, world.clock.now()), request);
        }

        Raw raw(String leaf) {
            return new Raw(base, ctx(leaf));
        }

        @Override
        public void close() {
            server.close();
        }
    }

    record Reply(int status, String body) {
    }

    /** A plain HTTPS client with a chosen certificate, for requests the real client would never send. */
    static final class Raw implements AutoCloseable {
        private final URI base;
        private final HttpClient http;

        Raw(URI base, SSLContext ctx) {
            this.base = base;
            this.http = HttpClient.newBuilder().sslContext(ctx).sslParameters(TlsContexts.clientParameters(ctx))
                    .version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(5)).build();
        }

        Reply post(String path, String json) throws IOException, InterruptedException {
            return send(HttpRequest.newBuilder(base.resolve(path)).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8)));
        }

        Reply post(String path, String contentType, byte[] body) throws IOException, InterruptedException {
            return send(HttpRequest.newBuilder(base.resolve(path)).header("Content-Type", contentType)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body)));
        }

        /** Sent chunked: no Content-Length, so the server has to count. */
        Reply postChunked(String path, byte[] body) throws IOException, InterruptedException {
            return send(HttpRequest.newBuilder(base.resolve(path)).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofInputStream(() -> new java.io.ByteArrayInputStream(body))));
        }

        Reply get(String path) throws IOException, InterruptedException {
            return send(HttpRequest.newBuilder(base.resolve(path)).GET());
        }

        Reply method(String method, String path) throws IOException, InterruptedException {
            return send(HttpRequest.newBuilder(base.resolve(path)).header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString("{}")));
        }

        private Reply send(HttpRequest.Builder b) throws IOException, InterruptedException {
            HttpResponse<String> r = http.send(b.timeout(Duration.ofSeconds(10)).build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return new Reply(r.statusCode(), r.body());
        }

        @Override
        public void close() {
            http.close();
        }
    }

    /** A TLS socket to the API with a chosen certificate, for byte-level abuse (slow bodies). */
    static SSLSocket socket(URI base, String leaf) throws IOException {
        SSLContext c = ctx(leaf);
        SSLSocket s = (SSLSocket) c.getSocketFactory().createSocket("localhost", base.getPort());
        s.setSSLParameters(TlsContexts.clientParameters(c));
        s.setSoTimeout(15_000);
        s.startHandshake();
        return s;
    }

    /** A server that speaks TLS with the Dwarpal CA but answers whatever {@code handler} says. */
    static HttpsServer fakeApi(String leaf, HttpHandler handler) throws IOException {
        SSLContext c = ctx(leaf);
        HttpsServer s = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 16);
        s.setHttpsConfigurator(new HttpsConfigurator(c) {
            @Override
            public void configure(HttpsParameters p) {
                p.setSSLParameters(TlsContexts.serverParameters(c));
            }
        });
        s.createContext("/", handler);
        s.start();
        return s;
    }

    static URI base(HttpsServer s) {
        return URI.create("https://localhost:" + s.getAddress().getPort());
    }
}

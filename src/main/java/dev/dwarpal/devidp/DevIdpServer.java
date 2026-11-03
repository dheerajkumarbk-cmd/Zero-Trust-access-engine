package dev.dwarpal.devidp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The development identity provider over HTTP (JDK server, loopback only), for the client agent's
 * command line and the demo. Bodies are at most 16 KiB of strict JSON ({@link IdpWire}); every failure
 * answers the same generic body. The client address passed to the provider is the socket's, never a
 * header.
 */
public final class DevIdpServer implements AutoCloseable {

    public static final String CHALLENGE_PATH = "/v1/challenge";
    public static final String AUTHENTICATE_PATH = "/v1/authenticate";
    static final int MAX_BODY = 16 * 1024;

    private final DevIdentityProvider idp;
    private final HttpServer server;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    private DevIdpServer(DevIdentityProvider idp, HttpServer server) {
        this.idp = idp;
        this.server = server;
    }

    public static DevIdpServer start(DevIdentityProvider idp, InetAddress loopback, int port) throws IOException {
        Objects.requireNonNull(idp, "idp");
        if (!loopback.isLoopbackAddress()) {
            throw new IllegalArgumentException("the development identity provider listens on loopback only");
        }
        DevIdpServer s = new DevIdpServer(idp, HttpServer.create(new InetSocketAddress(loopback, port), 0));
        s.server.createContext("/", s::handle);
        s.server.setExecutor(s.executor);
        s.server.start();
        return s;
    }

    public URI uri() {
        InetSocketAddress a = server.getAddress();
        return URI.create("http://" + a.getAddress().getHostAddress() + ":" + a.getPort());
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    private void handle(HttpExchange ex) {
        try (ex) {
            String path = ex.getRequestURI().getRawPath();
            if (!"POST".equals(ex.getRequestMethod())
                    || !CHALLENGE_PATH.equals(path) && !AUTHENTICATE_PATH.equals(path)) {
                reply(ex, 404, error("not found"));
                return;
            }
            Optional<byte[]> body = read(ex.getRequestBody());
            if (body.isEmpty()) {
                reply(ex, 413, error("request too large"));
                return;
            }
            String host = ex.getRemoteAddress().getAddress().getHostAddress();
            String ip = host.indexOf('%') >= 0 ? host.substring(0, host.indexOf('%')) : host;
            JsonValue in;
            try {
                in = new JsonReader().read(body.get());
            } catch (JsonException e) {
                reply(ex, 400, error("invalid request"));
                return;
            }
            if (CHALLENGE_PATH.equals(path)) {
                challenge(ex, in, ip);
            } else {
                authenticate(ex, in, ip);
            }
        } catch (IOException | RuntimeException e) {
            // Connection gone or a bug: the client gets no proof, which is the safe outcome.
        }
    }

    private void challenge(HttpExchange ex, JsonValue in, String ip) throws IOException {
        IdpWire.ChallengeRequest r;
        try {
            r = IdpWire.readChallengeRequest(in);
        } catch (JsonException e) {
            reply(ex, 400, error("invalid request"));
            return;
        }
        Optional<WebAuthn.Challenge> c = idp.challenge(r.subjectId(), r.deviceId(), r.keyThumbprint(), ip);
        if (c.isEmpty()) {
            reply(ex, 400, error("invalid request"));
            return;
        }
        reply(ex, 200, IdpWire.challenge(c.get()));
    }

    private void authenticate(HttpExchange ex, JsonValue in, String ip) throws IOException {
        IdentityProvider.Attempt a;
        try {
            a = IdpWire.readAttempt(in);
        } catch (JsonException e) {
            reply(ex, 400, error("invalid request"));
            return;
        }
        Optional<IdentityProvider.MfaProof> proof = idp.authenticate(a, ip);
        if (proof.isEmpty()) {
            reply(ex, 401, error("authentication failed"));
            return;
        }
        reply(ex, 200, IdpWire.mfa(proof.get()));
    }

    private static Optional<byte[]> read(InputStream in) throws IOException {
        try (in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) != -1) {
                if (out.size() + n > MAX_BODY) {
                    return Optional.empty();
                }
                out.write(buf, 0, n);
            }
            return Optional.of(out.toByteArray());
        }
    }

    private static JsonValue error(String message) {
        return JsonValue.object().put("error", message).build();
    }

    private static void reply(HttpExchange ex, int status, JsonValue body) throws IOException {
        byte[] b = JsonWriter.bytes(body);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }
}

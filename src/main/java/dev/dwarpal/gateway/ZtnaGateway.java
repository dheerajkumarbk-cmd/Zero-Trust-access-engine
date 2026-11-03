package dev.dwarpal.gateway;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.edge.EdgeHttp;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.SessionAuthority;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.edge.WireFormat;
import dev.dwarpal.guard.RateLimiter;
import dev.dwarpal.session.SessionLimits;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The ZTNA gateway: a reverse proxy that lets a request reach an internal application only when
 * Dwarpal says so, for that subject, device, resource and action, right now.
 *
 * <pre>
 *   POST /.dwarpal/v1/sessions        login: WireFormat open body; answers the result (201 with the grant)
 *   any  /&lt;route prefix&gt;/...            on a session: token + proof headers, see {@link EdgeHttp}
 * </pre>
 *
 * <p>Per request: the path must have one reading ({@link RequestPath}); the route gives the resource, the
 * method and route give the action; the subject and device come from the session this gateway opened,
 * the network from the real socket address; {@link SessionAuthority#use} decides. Only GRANTED and
 * GRANTED_LIMITED are forwarded. Every client-only header is removed, the gateway adds the subject, the
 * session and its own secret for the application, and sizes, time and concurrency are bounded. Any
 * failure is a refusal.
 */
public final class ZtnaGateway implements AutoCloseable {

    /** The gateway's own name space; no route may use it. */
    public static final String RESERVED_PREFIX = "/.dwarpal";
    public static final String LOGIN_PATH = RESERVED_PREFIX + "/v1/sessions";
    /** The gateway's identity for the application (shared secret, base64). */
    public static final String UPSTREAM_GATEWAY = "X-Dwarpal-Gateway";
    public static final String FORWARDED_FOR = "X-Forwarded-For";

    /** Counters for monitoring; no identifiers, no secrets. */
    public record Stats(long forwarded, long refused, long invalid, long upstreamFailures, long overloaded,
                        long internalFailures) {
    }

    private final GatewayConfig config;
    private final SessionAuthority authority;
    private final HttpServer server;
    private final ExecutorService executor;
    private final HttpClient upstream;
    private final GatewaySessions sessions;
    private final Semaphore inFlight;
    private final RateLimiter logins;
    private final LoginGuard loginGuard;
    private final String secret;
    private final AtomicLong forwarded = new AtomicLong();
    private final AtomicLong refused = new AtomicLong();
    private final AtomicLong invalid = new AtomicLong();
    private final AtomicLong upstreamFailures = new AtomicLong();
    private final AtomicLong overloaded = new AtomicLong();
    private final AtomicLong internalFailures = new AtomicLong();

    private ZtnaGateway(GatewayConfig config, SessionAuthority authority, HttpServer server) {
        this.config = config;
        this.authority = authority;
        this.server = server;
        this.executor = Executors.newVirtualThreadPerTaskExecutor();
        this.upstream = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .proxy(HttpClient.Builder.NO_PROXY)
                .connectTimeout(config.connectTimeout())
                .version(HttpClient.Version.HTTP_1_1)
                .build();
        this.sessions = new GatewaySessions(config.maxSessions(), SessionLimits.defaults().maxSessionsPerSubject());
        this.inFlight = new Semaphore(config.maxInFlight());
        this.logins = new RateLimiter(config.loginsPerMinutePerAddress(), Duration.ofMinutes(1), 100_000);
        this.loginGuard = new LoginGuard(config.identityProviders(), config.maxLoginAuthenticationAge(),
                Math.max(1_000, 2 * config.maxSessions()));
        this.secret = Base64.getEncoder().encodeToString(config.upstreamSecret());
    }

    /** Starts listening on the configured address (loopback by default). */
    public static ZtnaGateway start(GatewayConfig config, SessionAuthority authority) throws IOException {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(authority, "authority");
        InetSocketAddress at = new InetSocketAddress(config.bindAddress(), config.port());
        HttpServer server;
        if (config.tls().isPresent()) {
            SSLContext ctx = config.tls().get();
            HttpsServer https = HttpsServer.create(at, 0);
            boolean needCert = config.requireClientCertificate();
            https.setHttpsConfigurator(new HttpsConfigurator(ctx) {
                @Override
                public void configure(HttpsParameters params) {
                    SSLParameters p = TlsContexts.serverParameters(ctx);
                    p.setNeedClientAuth(needCert);
                    params.setSSLParameters(p);
                }
            });
            server = https;
        } else {
            server = HttpServer.create(at, 0);
        }
        ZtnaGateway g = new ZtnaGateway(config, authority, server);
        server.createContext("/", g::handle);
        server.setExecutor(g.executor);
        server.start();
        return g;
    }

    /** Where clients reach the gateway. */
    public URI uri() {
        InetSocketAddress a = server.getAddress();
        String scheme = config.tls().isPresent() ? "https" : "http";
        String host = a.getAddress().getHostAddress();
        return URI.create(scheme + "://" + (host.contains(":") ? "[" + host + "]" : host) + ":" + a.getPort());
    }

    public Stats stats() {
        return new Stats(forwarded.get(), refused.get(), invalid.get(), upstreamFailures.get(), overloaded.get(),
                internalFailures.get());
    }

    /** Sessions this gateway is tracking. */
    public int trackedSessions() {
        return sessions.size();
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
        upstream.close();
    }

    // ---- request handling ------------------------------------------------------------------------------

    private void handle(HttpExchange ex) {
        Reply reply = new Reply(ex);
        if (!inFlight.tryAcquire()) {
            overloaded.incrementAndGet();
            reply.error(503, "busy");
            ex.close();
            return;
        }
        try {
            dispatch(ex, reply);
        } catch (IOException e) {
            // The client or the connection went away; there is nobody left to answer.
            refused.incrementAndGet();
        } catch (RuntimeException e) {
            internalFailures.incrementAndGet();
            reply.error(403, "access denied");
        } finally {
            inFlight.release();
            ex.close();
        }
    }

    private void dispatch(HttpExchange ex, Reply reply) throws IOException {
        if (!headersWithinLimits(ex.getRequestHeaders())) {
            invalid.incrementAndGet();
            reply.error(431, "request headers too large");
            return;
        }
        URI uri = ex.getRequestURI();
        Optional<String> path = RequestPath.path(uri.getRawPath());
        Optional<String> query = RequestPath.query(uri.getRawQuery());
        if (path.isEmpty() || query.isEmpty()) {
            invalid.incrementAndGet();
            reply.error(400, "invalid request");
            return;
        }
        if (path.get().equals(LOGIN_PATH)) {
            login(ex, reply);
            return;
        }
        Optional<RouteTable.Route> route = RequestPath.under(path.get(), RESERVED_PREFIX)
                ? Optional.empty() : config.routes().match(path.get());
        if (route.isEmpty()) {
            invalid.incrementAndGet();
            reply.error(404, "not found");
            return;
        }
        Optional<Action> action = route.get().action(ex.getRequestMethod(), path.get());
        if (action.isEmpty()) {
            invalid.incrementAndGet();
            reply.error(405, "method not allowed");
            return;
        }
        proxy(ex, reply, route.get(), action.get(), path.get(), query.get());
    }

    private void login(HttpExchange ex, Reply reply) throws IOException {
        Instant now = config.clock().instant();
        InetAddress client = ex.getRemoteAddress().getAddress();
        if (!"POST".equals(ex.getRequestMethod())) {
            invalid.incrementAndGet();
            reply.error(405, "method not allowed");
            return;
        }
        if (!logins.tryAcquire(NetworkResolver.ip(client), now)) {
            refused.incrementAndGet();
            reply.error(429, "too many requests");
            return;
        }
        Optional<byte[]> body = body(ex, JsonLimits.defaults().maxBytes());
        if (body.isEmpty()) {
            invalid.incrementAndGet();
            reply.error(413, "request too large");
            return;
        }
        WireFormat.OpenBody open;
        EdgeRequest login;
        try {
            open = WireFormat.readOpen(new JsonReader().read(body.get()));
            EdgeRequest l = open.login();
            // The gateway states the time, the network and itself; the action of a login is READ.
            login = new EdgeRequest(l.requestId(), now, l.subjectId(), l.deviceId(), l.claimedPosture(), l.resourceId(),
                    Action.READ, config.network().resolve(client), config.pepRegion(), l.evidence());
        } catch (JsonException | IllegalArgumentException e) {
            invalid.incrementAndGet();
            reply.error(400, "invalid request");
            return;
        }
        // B2: only for resources this gateway fronts. B1, B7: only with fresh, signed, key-bound, unused MFA.
        if (config.routes().forResource(login.resourceId()).isEmpty()
                || loginGuard.check(login, open.sessionKey(), now).isPresent()) {
            refused.incrementAndGet();
            reply.error(403, "access denied");
            return;
        }
        if (!sessions.hasRoom(now)) {
            overloaded.incrementAndGet();
            reply.error(503, "busy");
            return;
        }
        EdgeResult r = authority.open(login, open.sessionKey(), open.deviceBinding());
        if (r.status() == EdgeResult.Status.OPENED && !sessions.remember(r.grant().orElseThrow(), login, now)) {
            overloaded.incrementAndGet();
            reply.error(503, "busy");
            return;
        }
        if (!r.status().allowed()) {
            refused.incrementAndGet();
        }
        reply.result(r);
    }

    private void proxy(HttpExchange ex, Reply reply, RouteTable.Route route, Action action, String path, String query)
            throws IOException {
        Instant now = config.clock().instant();
        Headers h = ex.getRequestHeaders();
        Optional<String> token = single(h, EdgeHttp.AUTHORIZATION).flatMap(EdgeHttp::bearerToken);
        Optional<String> sessionId = single(h, EdgeHttp.SESSION);
        Optional<SignatureProof> proof = EdgeHttp.proof(sessionId.orElse(null), single(h, EdgeHttp.PROOF).orElse(null),
                single(h, EdgeHttp.PROOF_TIME).orElse(null));
        Optional<String> requestId = single(h, EdgeHttp.REQUEST_ID).filter(ZtnaGateway::validId);
        if (HeaderPolicy.overridesMethod(h.keySet()) || HeaderPolicy.overridesMethodInQuery(query)) {
            // B4: the application would run another method than the one Dwarpal decided.
            invalid.incrementAndGet();
            reply.error(400, "invalid request");
            return;
        }
        if (token.isEmpty() || proof.isEmpty() || requestId.isEmpty()) {
            refused.incrementAndGet();
            reply.error(401, "session required");
            return;
        }
        Optional<GatewaySessions.Entry> found = sessions.find(sessionId.get(), token.get(), now);
        if (found.isEmpty() || !found.get().resourceId().equals(route.resourceId())) {
            refused.incrementAndGet();
            reply.error(403, "access denied");
            return;
        }
        GatewaySessions.Entry s = found.get();
        DevicePosture posture = s.loginPosture();
        Evidence evidence = Evidence.none();
        List<String> ev = h.get(ClientEvidence.HEADER);
        if (ev != null) {
            Optional<ClientEvidence.Claims> claims = ev.size() == 1 ? ClientEvidence.decode(ev.get(0)) : Optional.empty();
            if (claims.isEmpty()) {
                invalid.incrementAndGet();
                reply.error(400, "invalid request");
                return;
            }
            posture = claims.get().posture();
            evidence = claims.get().evidence();
        }
        long declared = declaredLength(h);
        if (declared > config.maxRequestBody()) {
            invalid.incrementAndGet();
            reply.error(413, "request too large");
            return;
        }
        InetAddress client = ex.getRemoteAddress().getAddress();
        NetworkContext network = config.network().resolve(client);
        EdgeRequest request = new EdgeRequest(requestId.get(), now, s.subjectId(), s.deviceId(), posture,
                route.resourceId(), action, network, config.pepRegion(), evidence);

        EdgeResult r = authority.use(token.get(), proof.get(), request);
        if (r.sessionEnded()) {
            sessions.forget(s.sessionId());
        }
        if (!r.status().allowed()) {
            refused.incrementAndGet();
            reply.result(r);
            return;
        }
        Optional<byte[]> body = body(ex, config.maxRequestBody());
        if (body.isEmpty()) {
            invalid.incrementAndGet();
            reply.error(413, "request too large");
            return;
        }
        forward(ex, reply, route, path, query, s, network, body.get(), r.status() == EdgeResult.Status.GRANTED_LIMITED);
    }

    private void forward(HttpExchange ex, Reply reply, RouteTable.Route route, String path, String query,
                         GatewaySessions.Entry s, NetworkContext network, byte[] body, boolean readOnly)
            throws IOException {
        URI target = URI.create(route.upstream().toString() + path + (query.isEmpty() ? "" : "?" + query));
        HttpRequest.Builder b = HttpRequest.newBuilder(target).timeout(config.upstreamTimeout());
        Headers in = ex.getRequestHeaders();
        Set<String> listed = HeaderPolicy.connectionListed(in);
        for (Map.Entry<String, List<String>> e : in.entrySet()) {
            if (HeaderPolicy.forwardRequest(e.getKey(), listed)) {
                for (String v : e.getValue()) {
                    if (EdgeHttp.safeHeaderValue(v)) {
                        b.header(e.getKey(), v);
                    }
                }
            }
        }
        b.header(EdgeHttp.UPSTREAM_SUBJECT, s.subjectId())
                .header(EdgeHttp.UPSTREAM_SESSION, s.sessionId())
                .header(UPSTREAM_GATEWAY, secret)
                .header(FORWARDED_FOR, network.ip());
        b.method(ex.getRequestMethod(), body.length == 0 ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(body));

        HttpResponse<InputStream> resp;
        byte[] content;
        try {
            resp = upstream.send(b.build(), HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream rb = resp.body()) {
                Optional<byte[]> bounded = readBounded(rb, config.maxResponseBody());
                if (bounded.isEmpty()) {
                    upstreamFailures.incrementAndGet();
                    reply.error(502, "bad gateway");
                    return;
                }
                content = bounded.get();
            }
        } catch (IOException e) {
            upstreamFailures.incrementAndGet();
            reply.error(502, "bad gateway");
            return;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            upstreamFailures.incrementAndGet();
            reply.error(502, "bad gateway");
            return;
        }

        Headers out = ex.getResponseHeaders();
        Set<String> respListed = HeaderPolicy.connectionListed(resp.headers().map());
        for (Map.Entry<String, List<String>> e : resp.headers().map().entrySet()) {
            if (HeaderPolicy.forwardResponse(e.getKey(), respListed)) {
                for (String v : e.getValue()) {
                    Optional<String> safe = HeaderPolicy.responseValue(e.getKey(), v, route.upstream());
                    safe.ifPresent(x -> out.add(e.getKey(), x));
                }
            }
        }
        if (readOnly) {
            out.set(EdgeHttp.READ_ONLY, "true");
        }
        forwarded.incrementAndGet();
        int status = resp.statusCode();
        boolean noBody = "HEAD".equals(ex.getRequestMethod()) || status == 204 || status == 304 || content.length == 0;
        reply.sent = true;
        ex.sendResponseHeaders(status, noBody ? -1 : content.length);
        if (!noBody) {
            try (OutputStream os = ex.getResponseBody()) {
                os.write(content);
            }
        }
    }

    // ---- helpers ---------------------------------------------------------------------------------------

    private boolean headersWithinLimits(Headers h) {
        int count = 0;
        long bytes = 0;
        for (Map.Entry<String, List<String>> e : h.entrySet()) {
            for (String v : e.getValue()) {
                count++;
                bytes += e.getKey().length() + (v == null ? 0 : v.length()) + 4;
            }
        }
        return count <= config.maxHeaders() && bytes <= config.maxHeaderBytes();
    }

    /** The value of a header sent exactly once; a repeated or missing one is no value at all. */
    private static Optional<String> single(Headers h, String name) {
        List<String> v = h.get(name);
        return v != null && v.size() == 1 ? Optional.ofNullable(v.get(0)) : Optional.empty();
    }

    private static boolean validId(String s) {
        try {
            Validate.id(s, "requestId");
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** Declared Content-Length, or 0 when absent; an unreadable value counts as too large. */
    private static long declaredLength(Headers h) {
        List<String> v = h.get("Content-Length");
        if (v == null) {
            return 0;
        }
        try {
            return v.size() == 1 ? Long.parseLong(v.get(0).strip()) : Long.MAX_VALUE;
        } catch (NumberFormatException e) {
            return Long.MAX_VALUE;
        }
    }

    private static Optional<byte[]> body(HttpExchange ex, int max) throws IOException {
        if (declaredLength(ex.getRequestHeaders()) > max) {
            return Optional.empty();
        }
        try (InputStream in = ex.getRequestBody()) {
            return readBounded(in, max);
        }
    }

    /** At most {@code max} bytes; empty if there are more. */
    static Optional<byte[]> readBounded(InputStream in, int max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(max, 8192));
        byte[] buf = new byte[8192];
        int total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > max) {
                return Optional.empty();
            }
            out.write(buf, 0, n);
        }
        return Optional.of(out.toByteArray());
    }

    /** Answers the client at most once. */
    private static final class Reply {
        private final HttpExchange ex;
        private boolean sent;

        Reply(HttpExchange ex) {
            this.ex = ex;
        }

        void error(int status, String message) {
            send(status, JsonValue.object().put("error", message).build(), Optional.empty());
        }

        void result(EdgeResult r) {
            Optional<String> challenge = r.challenge().map(EdgeHttp::challengeHeader);
            send(EdgeHttp.status(r), WireFormat.result(r), challenge);
        }

        private void send(int status, JsonValue body, Optional<String> challenge) {
            if (sent) {
                return;
            }
            sent = true;
            byte[] bytes = JsonWriter.bytes(body);
            Headers out = ex.getResponseHeaders();
            out.set("Content-Type", "application/json; charset=utf-8");
            out.set("Cache-Control", "no-store");
            out.set("X-Content-Type-Options", "nosniff");
            challenge.ifPresent(c -> out.set(EdgeHttp.CHALLENGE, c));
            try {
                ex.sendResponseHeaders(status, bytes.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(bytes);
                }
            } catch (IOException e) {
                // Connection gone; nothing more can be done for this client.
            }
        }
    }
}

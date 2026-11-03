package dev.dwarpal.agent;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.devidp.IdentityProvider;
import dev.dwarpal.devidp.SoftwareAuthenticator;
import dev.dwarpal.devidp.WebAuthn;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.edge.ClientProofs;
import dev.dwarpal.edge.EdgeGrant;
import dev.dwarpal.edge.EdgeHttp;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.WireFormat;
import dev.dwarpal.gateway.ClientEvidence;
import dev.dwarpal.gateway.RequestPath;
import dev.dwarpal.gateway.RouteTable;
import dev.dwarpal.gateway.ZtnaGateway;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonWriter;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * The client agent: everything a user's device does to reach an application through the gateway.
 *
 * <ol>
 *   <li>Per resource, generate a fresh Ed25519 session key (never leaves this object).</li>
 *   <li>Log in at the identity provider with the password and the WebAuthn authenticator; the MFA proof
 *       comes back bound to the session key's thumbprint.</li>
 *   <li>Have the device agent bind the session key to this device for this login, and open the session
 *       at the gateway.</li>
 *   <li>Sign every request with the session key (fresh request id, {@link ClientProofs#sign}), with the
 *       device's signed posture and the latest MFA proof in {@code Dwarpal-Evidence}.</li>
 *   <li>On 401 (step-up) authenticate again with WebAuthn, bound to the same key, and retry once.</li>
 * </ol>
 *
 * The agent computes the action from the same {@link RouteTable} as the gateway, because the action is
 * part of what it signs.
 */
public final class ClientAgent {

    /** What came back for one call. */
    public static final class Response {
        private final int status;
        private final byte[] body;
        private final HttpHeaders headers;
        private final Optional<EdgeResult> result;

        Response(int status, byte[] body, HttpHeaders headers, Optional<EdgeResult> result) {
            this.status = status;
            this.body = body.clone();
            this.headers = headers;
            this.result = result;
        }

        public int status() {
            return status;
        }

        public byte[] body() {
            return body.clone();
        }

        public String text() {
            return new String(body, StandardCharsets.UTF_8);
        }

        public HttpHeaders headers() {
            return headers;
        }

        /** Dwarpal's answer, when the gateway refused, challenged or opened (absent for forwarded responses). */
        public Optional<EdgeResult> result() {
            return result;
        }

        public boolean readOnly() {
            return headers.firstValue(EdgeHttp.READ_ONLY).map("true"::equals).orElse(false);
        }

        @Override
        public String toString() {
            return "Response[status=" + status + ", bytes=" + body.length + ", result=" + result.map(EdgeResult::status) + "]";
        }
    }

    private static final class Session {
        final String sessionId;
        final String token;
        final KeyPair key;
        volatile IdentityProvider.MfaProof mfa;

        Session(EdgeGrant g, KeyPair key, IdentityProvider.MfaProof mfa) {
            this.sessionId = g.sessionId();
            this.token = g.token();
            this.key = key;
            this.mfa = mfa;
        }
    }

    /** The agent does not know its network; the gateway states it from the socket. */
    private static final NetworkContext UNKNOWN_NETWORK = new NetworkContext("0.0.0.0", "AS0", "ZZ", 0, 0, 0);
    private static final String REGION = "client";
    private static final int MAX_RESPONSE = 8 << 20;
    private static final Duration HIDE_MFA_AFTER = Duration.ofMinutes(15);

    private final URI gateway;
    private final RouteTable routes;
    private final IdentityProvider idp;
    private final String subjectId;
    private final Supplier<char[]> password;
    private final SoftwareAuthenticator authenticator;
    private final DeviceAgent device;
    private final Clock clock;
    private final HttpClient http;
    private final Duration timeout;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    private ClientAgent(Builder b) {
        this.gateway = Objects.requireNonNull(b.gateway, "gateway");
        this.routes = Objects.requireNonNull(b.routes, "routes");
        this.idp = Objects.requireNonNull(b.idp, "idp");
        this.subjectId = Validate.id(b.subjectId, "subjectId");
        this.password = Objects.requireNonNull(b.password, "password");
        this.authenticator = Objects.requireNonNull(b.authenticator, "authenticator");
        this.device = Objects.requireNonNull(b.device, "device");
        this.clock = Objects.requireNonNull(b.clock, "clock");
        this.http = b.http != null ? b.http : HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
                .proxy(HttpClient.Builder.NO_PROXY).connectTimeout(Duration.ofSeconds(5)).build();
        this.timeout = Objects.requireNonNull(b.timeout, "timeout");
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Opens a session for {@code resourceId} (normally done on the first request to it). */
    public Response login(String resourceId) throws IOException, InterruptedException {
        Validate.id(resourceId, "resourceId");
        KeyPair key = Ed25519.generateKeyPair();
        Optional<IdentityProvider.MfaProof> mfa = authenticate(key);
        if (mfa.isEmpty()) {
            return new Response(401, new byte[0], HttpHeaders.of(Map.of(), (a, b) -> true), Optional.empty());
        }
        Instant at = clock.instant();
        Evidence evidence = mfa.get().addTo(device.evidence(at));
        EdgeRequest login = new EdgeRequest(newId(), at, subjectId, device.deviceId(), device.posture(), resourceId,
                Action.READ, UNKNOWN_NETWORK, REGION, evidence);
        Optional<SignatureProof> binding = device.bind(login, key.getPublic(), at);
        byte[] body = JsonWriter.bytes(WireFormat.open(new WireFormat.OpenBody(login, key.getPublic(), binding)));
        HttpRequest req = HttpRequest.newBuilder(gateway.resolve(ZtnaGateway.LOGIN_PATH)).timeout(timeout)
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
        Response r = exchange(req);
        r.result().flatMap(EdgeResult::grant).ifPresent(g -> sessions.put(resourceId, new Session(g, key, mfa.get())));
        return r;
    }

    /**
     * Sends one request through the gateway, logging in first if there is no session for its resource.
     *
     * @param pathAndQuery for example {@code /wiki/pages/home} or {@code /wiki/pages?q=x}
     */
    public Response send(String method, String pathAndQuery, byte[] body) throws IOException, InterruptedException {
        return send(method, pathAndQuery, body, Map.of());
    }

    /** As {@link #send(String, String, byte[])}, with extra headers (the gateway decides what reaches the app). */
    public Response send(String method, String pathAndQuery, byte[] body, Map<String, String> extraHeaders)
            throws IOException, InterruptedException {
        int q = pathAndQuery.indexOf('?');
        String path = q < 0 ? pathAndQuery : pathAndQuery.substring(0, q);
        if (RequestPath.path(path).isEmpty()) {
            throw new IllegalArgumentException("path has more than one reading; the gateway would refuse it");
        }
        RouteTable.Route route = routes.match(path)
                .orElseThrow(() -> new IllegalArgumentException("no route for this path"));
        Action action = route.action(method, path)
                .orElseThrow(() -> new IllegalArgumentException("method has no action"));
        Session s = sessions.get(route.resourceId());
        if (s == null) {
            Response opened = login(route.resourceId());
            s = sessions.get(route.resourceId());
            if (s == null) {
                return opened;
            }
        }
        Response r = signed(s, route.resourceId(), action, method, pathAndQuery, body, extraHeaders);
        if (r.result().map(x -> x.status() == EdgeResult.Status.STEP_UP).orElse(false)) {
            Optional<IdentityProvider.MfaProof> fresh = authenticate(s.key);
            if (fresh.isPresent()) {
                s.mfa = fresh.get();
                r = signed(s, route.resourceId(), action, method, pathAndQuery, body, extraHeaders);
            }
        }
        if (r.result().map(EdgeResult::sessionEnded).orElse(false)) {
            sessions.remove(route.resourceId(), s);
        }
        return r;
    }

    /** Forgets the session of a resource (the next request logs in again). */
    public void forget(String resourceId) {
        sessions.remove(resourceId);
    }

    /** The session id for a resource, if the agent holds one. */
    public Optional<String> sessionId(String resourceId) {
        return Optional.ofNullable(sessions.get(resourceId)).map(s -> s.sessionId);
    }

    private Response signed(Session s, String resourceId, Action action, String method, String pathAndQuery,
                            byte[] body, Map<String, String> extraHeaders) throws IOException, InterruptedException {
        Instant at = clock.instant();
        Evidence evidence = device.evidence(at);
        IdentityProvider.MfaProof mfa = s.mfa;
        if (mfa != null && Duration.between(mfa.authentication().authenticatedAt(), at).compareTo(HIDE_MFA_AFTER) < 0) {
            evidence = mfa.addTo(evidence);
        }
        EdgeRequest r = new EdgeRequest(newId(), at, subjectId, device.deviceId(), device.posture(), resourceId, action,
                UNKNOWN_NETWORK, REGION, evidence);
        SignatureProof proof = ClientProofs.sign(s.key.getPrivate(), s.sessionId, r, at);
        HttpRequest.Builder b = HttpRequest.newBuilder(gateway.resolve(pathAndQuery)).timeout(timeout);
        extraHeaders.forEach(b::header);
        b.header(EdgeHttp.AUTHORIZATION, EdgeHttp.SCHEME + " " + s.token)
                .header(EdgeHttp.SESSION, s.sessionId)
                .header(EdgeHttp.REQUEST_ID, r.requestId())
                .header(EdgeHttp.PROOF_TIME, proof.signedAt().toString())
                .header(EdgeHttp.PROOF, proof.signature())
                .header(ClientEvidence.HEADER, ClientEvidence.encode(r.claimedPosture(), evidence))
                .method(method, body.length == 0 ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofByteArray(body));
        return exchange(b.build());
    }

    /** WebAuthn plus password at the identity provider, bound to {@code key}. */
    private Optional<IdentityProvider.MfaProof> authenticate(KeyPair key) {
        String thumbprint = Digests.thumbprint(key.getPublic());
        Optional<WebAuthn.Challenge> c = idp.challenge(subjectId, device.deviceId(), thumbprint);
        if (c.isEmpty()) {
            return Optional.empty();
        }
        Optional<WebAuthn.Assertion> a = authenticator.assertion(c.get(), true);
        if (a.isEmpty()) {
            return Optional.empty();
        }
        char[] pw = password.get();
        try {
            return idp.authenticate(new IdentityProvider.Attempt(c.get().challengeId(), subjectId, new String(pw), a.get()))
                    .filter(m -> m.authentication().boundTo(thumbprint));
        } finally {
            Arrays.fill(pw, (char) 0);
        }
    }

    private Response exchange(HttpRequest req) throws IOException, InterruptedException {
        HttpResponse<byte[]> resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        byte[] body = resp.body();
        if (body.length > MAX_RESPONSE) {
            throw new IOException("response too large");
        }
        Optional<EdgeResult> result = Optional.empty();
        boolean fromGateway = resp.headers().firstValue("Content-Type").map(t -> t.startsWith("application/json"))
                .orElse(false) && (resp.statusCode() == 201 || resp.statusCode() == 401 || resp.statusCode() == 403);
        if (fromGateway) {
            try {
                result = Optional.of(WireFormat.readResult(new JsonReader().read(body)));
            } catch (JsonException e) {
                result = Optional.empty();
            }
        }
        return new Response(resp.statusCode(), body, resp.headers(), result);
    }

    private String newId() {
        byte[] b = new byte[16];
        random.nextBytes(b);
        return "rq-" + HexFormat.of().formatHex(b);
    }

    public static final class Builder {
        private URI gateway;
        private RouteTable routes;
        private IdentityProvider idp;
        private String subjectId;
        private Supplier<char[]> password;
        private SoftwareAuthenticator authenticator;
        private DeviceAgent device;
        private Clock clock = Clock.systemUTC();
        private HttpClient http;
        private Duration timeout = Duration.ofSeconds(15);

        private Builder() {
        }

        public Builder gateway(URI v) { gateway = v; return this; }
        public Builder routes(RouteTable v) { routes = v; return this; }
        public Builder identityProvider(IdentityProvider v) { idp = v; return this; }
        public Builder subject(String v) { subjectId = v; return this; }
        /** Asked each time the user must authenticate; the returned array is wiped after use. */
        public Builder password(Supplier<char[]> v) { password = v; return this; }
        public Builder authenticator(SoftwareAuthenticator v) { authenticator = v; return this; }
        public Builder device(DeviceAgent v) { device = v; return this; }
        public Builder clock(Clock v) { clock = v; return this; }
        public Builder http(HttpClient v) { http = v; return this; }
        public Builder timeout(Duration v) { timeout = v; return this; }

        public ClientAgent build() {
            return new ClientAgent(this);
        }
    }
}

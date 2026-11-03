package dev.dwarpal.gateway;

import dev.dwarpal.Fixtures;
import dev.dwarpal.agent.ClientAgent;
import dev.dwarpal.agent.DeviceAgent;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.devidp.DevIdentityProvider;
import dev.dwarpal.devidp.IdentityProvider;
import dev.dwarpal.devidp.SoftwareAuthenticator;
import dev.dwarpal.devidp.UserFile;
import dev.dwarpal.devidp.WebAuthn;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.edge.ClientProofs;
import dev.dwarpal.edge.EdgeFixtures;
import dev.dwarpal.edge.EdgeGrant;
import dev.dwarpal.edge.EdgeHttp;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.SessionAuthority;
import dev.dwarpal.edge.WireFormat;
import dev.dwarpal.session.FailureReportReceiver;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonWriter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;

/**
 * Part B's test world on real sockets: the shared {@link EdgeFixtures} engine behind a
 * {@link LocalSessionAuthority}, the development identity provider, the sample app and the gateway.
 *
 * <pre>
 * users      alice, bob, carol: password "pw-&lt;name&gt;-correct-horse", one software authenticator each
 * routes     /wiki -> wiki (download /wiki/download, admin /wiki/admin), /vault -> vault, /drive -> drive
 * devices    laptop-alice (managed, agent key from the fixtures), anything else unmanaged
 * </pre>
 */
public final class GatewayWorld implements AutoCloseable {

    public static final String RP_ID = "dwarpal.localhost";
    public static final int ITERATIONS = UserFile.MIN_ITERATIONS;
    public static final NetworkContext MUMBAI = new NetworkContext("127.0.0.1", "AS64500", "IN", 19.07, 72.88, 25);

    public final EdgeFixtures.World w = EdgeFixtures.world();
    public final byte[] secret = new byte[32];
    public final Map<String, SoftwareAuthenticator> authenticators = new LinkedHashMap<>();
    public final List<FailureReportReceiver.FailureReport> failureReports = Collections.synchronizedList(new ArrayList<>());
    public final List<InetAddress> resolved = Collections.synchronizedList(new ArrayList<>());
    public final DevIdentityProvider idp;
    public final SampleApp app;
    public final RouteTable routes;
    public final ZtnaGateway gateway;
    public final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
            .proxy(HttpClient.Builder.NO_PROXY).build();
    private final AtomicInteger ids = new AtomicInteger();

    private GatewayWorld(Consumer<GatewayConfig.Builder> tweak, UnaryOperator<SessionAuthority> wrap) throws IOException {
        new SecureRandom().nextBytes(secret);
        StringBuilder file = new StringBuilder("# test users\n");
        for (String u : List.of("alice", "bob", "carol")) {
            SoftwareAuthenticator a = SoftwareAuthenticator.register(RP_ID);
            authenticators.put(u, a);
            file.append(UserFile.line(u, password(u), ITERATIONS, a.credentialId(), a.publicKey())).append('\n');
        }
        idp = new DevIdentityProvider(UserFile.parse(file.toString()), Fixtures.IDP, Fixtures.IDP_KEY_ID, RP_ID,
                w.clock, (report, proof) -> failureReports.add(report));
        InetAddress lo = InetAddress.getLoopbackAddress();
        app = SampleApp.start(lo, 0, secret);
        routes = RouteTable.parse("route /wiki wiki " + app.uri() + "\n"
                + "download /wiki/download\nadmin /wiki/admin\n"
                + "route /vault vault " + app.uri() + "\n"
                + "route /drive drive " + app.uri() + "\n");
        GatewayConfig.Builder b = GatewayConfig.builder(routes, secret, EdgeFixtures.keyRing()).clock(w.clock)
                .pepRegion("mumbai").network(ip -> {
                    resolved.add(ip);
                    return MUMBAI;
                });
        tweak.accept(b);
        gateway = ZtnaGateway.start(b.build(), wrap.apply(w.authority));
    }

    public static GatewayWorld start() throws IOException {
        return new GatewayWorld(b -> { }, a -> a);
    }

    public static GatewayWorld start(Consumer<GatewayConfig.Builder> tweak) throws IOException {
        return new GatewayWorld(tweak, a -> a);
    }

    /** A world whose gateway asks {@code wrap(local authority)}. */
    public static GatewayWorld start(Consumer<GatewayConfig.Builder> tweak, UnaryOperator<SessionAuthority> wrap)
            throws IOException {
        return new GatewayWorld(tweak, wrap);
    }

    public static char[] password(String user) {
        return ("pw-" + user + "-correct-horse").toCharArray();
    }

    public static DevicePosture healthy() {
        return new DevicePosture(true, true, true, AssuranceLevel.SELF_REPORTED);
    }

    public DeviceAgent aliceLaptop() {
        return DeviceAgent.managed("laptop-alice", Fixtures.DEVICE_KEY_ID, Fixtures.DEVICE_AGENT, healthy());
    }

    public ClientAgent agent(String user, DeviceAgent device) {
        return ClientAgent.builder().gateway(gateway.uri()).routes(routes).identityProvider(idp.forClient("127.0.0.1"))
                .subject(user).password(() -> password(user)).authenticator(authenticators.get(user)).device(device)
                .clock(w.clock).build();
    }

    public ClientAgent alice() {
        return agent("alice", aliceLaptop());
    }

    // ---- raw access, for attacks the agent would never make ------------------------------------------

    /** A session opened by hand: everything an attacker who did the login himself would hold. */
    public record RawSession(int status, Optional<EdgeResult> result, KeyPair key, byte[] loginBody, String user,
                             String device) {
        public EdgeGrant grant() {
            return result.orElseThrow().grant().orElseThrow();
        }
    }

    public String newId() {
        return "raw-" + ids.incrementAndGet();
    }

    /** Key-bound WebAuthn MFA for {@code key}, straight from the identity provider. */
    public IdentityProvider.MfaProof mfa(String user, String device, KeyPair key) {
        IdentityProvider p = idp.forClient("127.0.0.1");
        WebAuthn.Challenge c = p.challenge(user, device, Digests.thumbprint(key.getPublic())).orElseThrow();
        WebAuthn.Assertion a = authenticators.get(user).assertion(c, true).orElseThrow();
        return p.authenticate(new IdentityProvider.Attempt(c.challengeId(), user, new String(password(user)), a))
                .orElseThrow();
    }

    /** Builds a login exactly as the agent would, then lets the caller change the evidence before sending. */
    public RawSession rawLogin(String user, String device, String resource, boolean withMfa,
                               java.util.function.UnaryOperator<Evidence> tamper) throws Exception {
        KeyPair key = Ed25519.generateKeyPair();
        boolean managed = device.equals("laptop-alice");
        DeviceAgent d = managed ? aliceLaptop() : DeviceAgent.unmanaged(device, healthy());
        Evidence ev = d.evidence(w.clock.now());
        if (withMfa) {
            ev = mfa(user, device, key).addTo(ev);
        }
        ev = tamper.apply(ev);
        EdgeRequest login = new EdgeRequest(newId(), w.clock.now(), user, device, healthy(), resource, Action.READ,
                MUMBAI, "client", ev);
        Optional<SignatureProof> binding = d.bind(login, key.getPublic(), w.clock.now());
        byte[] body = JsonWriter.bytes(WireFormat.open(new WireFormat.OpenBody(login, key.getPublic(), binding)));
        return postLogin(body, key, user, device);
    }

    public RawSession postLogin(byte[] body, KeyPair key, String user, String device) throws Exception {
        HttpResponse<byte[]> r = http.send(HttpRequest.newBuilder(gateway.uri().resolve(ZtnaGateway.LOGIN_PATH))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build(), HttpResponse.BodyHandlers.ofByteArray());
        Optional<EdgeResult> result;
        try {
            result = Optional.of(WireFormat.readResult(new JsonReader().read(r.body())));
        } catch (RuntimeException e) {
            result = Optional.empty();
        }
        return new RawSession(r.statusCode(), result, key, body, user, device);
    }

    /** A request on a raw session, signed for {@code action}, with any extra headers. */
    public HttpRequest.Builder signed(RawSession s, KeyPair signWith, String method, String path, Action action,
                                      String resource, String requestId) {
        EdgeRequest r = new EdgeRequest(requestId, w.clock.now(), s.user(), s.device(), healthy(), resource, action,
                MUMBAI, "client", Evidence.none());
        SignatureProof p = ClientProofs.sign(signWith.getPrivate(), s.grant().sessionId(), r, w.clock.now());
        return HttpRequest.newBuilder(gateway.uri().resolve(path))
                .header(EdgeHttp.AUTHORIZATION, "Dwarpal " + s.grant().token())
                .header(EdgeHttp.SESSION, s.grant().sessionId())
                .header(EdgeHttp.REQUEST_ID, requestId)
                .header(EdgeHttp.PROOF_TIME, p.signedAt().toString())
                .header(EdgeHttp.PROOF, p.signature())
                .method(method, HttpRequest.BodyPublishers.noBody());
    }

    public HttpResponse<String> send(HttpRequest.Builder b) throws Exception {
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Writes bytes on a socket and returns the status line: for request targets no HTTP library would send. */
    public String rawStatus(String requestHead, byte[] body) throws IOException {
        try (Socket s = new Socket(gateway.uri().getHost(), gateway.uri().getPort())) {
            s.setSoTimeout(10_000);
            OutputStream out = s.getOutputStream();
            out.write(requestHead.getBytes(StandardCharsets.ISO_8859_1));
            out.write(body);
            out.flush();
            InputStream in = s.getInputStream();
            StringBuilder line = new StringBuilder();
            int c;
            while ((c = in.read()) != -1 && c != '\n') {
                line.append((char) c);
            }
            return line.toString().strip();
        }
    }

    public URI uri(String path) {
        return gateway.uri().resolve(path);
    }

    @Override
    public void close() {
        gateway.close();
        app.close();
        http.close();
    }
}

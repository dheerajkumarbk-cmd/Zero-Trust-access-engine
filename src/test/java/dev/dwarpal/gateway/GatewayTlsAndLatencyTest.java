package dev.dwarpal.gateway;

import dev.dwarpal.agent.ClientAgent;
import dev.dwarpal.edge.DevPki;
import dev.dwarpal.edge.EdgeHttp;
import dev.dwarpal.edge.TlsContexts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** HTTPS at the edge with device certificates, and how much latency the gateway adds. */
class GatewayTlsAndLatencyTest {

    @TempDir
    Path dir;

    private static SSLContext ctx(DevPki pki, String leaf) throws Exception {
        return TlsContexts.create(pki.keyStore(leaf), pki.password(), pki.trustStore(), pki.password());
    }

    @Test
    void theGatewayCanServeTls13AndDemandADeviceCertificate() throws Exception {
        DevPki pki = DevPki.create(dir.resolve("pki"), "Dwarpal Dev CA",
                List.of(DevPki.Leaf.valid("gateway"), DevPki.Leaf.valid("laptop-alice")));
        SSLContext server = ctx(pki, "gateway");
        try (GatewayWorld g = GatewayWorld.start(b -> b.tls(server, true))) {
            assertTrue(g.gateway.uri().getScheme().equals("https"));
            SSLContext device = ctx(pki, "laptop-alice");
            HttpClient tls = HttpClient.newBuilder().sslContext(device).sslParameters(TlsContexts.clientParameters(device))
                    .followRedirects(HttpClient.Redirect.NEVER).proxy(HttpClient.Builder.NO_PROXY).build();
            ClientAgent alice = ClientAgent.builder().gateway(g.gateway.uri()).routes(g.routes)
                    .identityProvider(g.idp.forClient("127.0.0.1")).subject("alice")
                    .password(() -> GatewayWorld.password("alice")).authenticator(g.authenticators.get("alice"))
                    .device(g.aliceLaptop()).clock(g.w.clock).http(tls).build();
            assertEquals(200, alice.send("GET", "/wiki/pages/home", new byte[0]).status());

            SSLContext trustOnly = SSLContext.getInstance("TLSv1.3");
            javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance("PKIX");
            java.security.KeyStore ts = java.security.KeyStore.getInstance("PKCS12");
            try (java.io.InputStream in = java.nio.file.Files.newInputStream(pki.trustStore())) {
                ts.load(in, pki.password());
            }
            tmf.init(ts);
            trustOnly.init(null, tmf.getTrustManagers(), null);
            HttpClient noCert = HttpClient.newBuilder().sslContext(trustOnly)
                    .sslParameters(TlsContexts.clientParameters(trustOnly)).proxy(HttpClient.Builder.NO_PROXY).build();
            assertThrows(IOException.class, () -> noCert.send(HttpRequest.newBuilder(g.uri("/wiki/pages/home")).build(),
                    HttpResponse.BodyHandlers.ofString()), "no device certificate, no connection");
            tls.close();
            noCert.close();
        }
    }

    @Test
    void latencyAddedByTheGatewayIsSmall() throws Exception {
        try (GatewayWorld g = GatewayWorld.start()) {
            ClientAgent alice = g.alice();
            HttpRequest direct = HttpRequest.newBuilder(g.app.uri().resolve("/wiki/pages/home"))
                    .header(ZtnaGateway.UPSTREAM_GATEWAY, Base64.getEncoder().encodeToString(g.secret))
                    .header(EdgeHttp.UPSTREAM_SUBJECT, "alice").build();
            for (int i = 0; i < 100; i++) {
                alice.send("GET", "/wiki/pages/home", new byte[0]);
                g.http.send(direct, HttpResponse.BodyHandlers.ofString());
            }
            List<Long> via = new ArrayList<>();
            List<Long> base = new ArrayList<>();
            for (int i = 0; i < 400; i++) {
                long t0 = System.nanoTime();
                assertEquals(200, alice.send("GET", "/wiki/pages/home", new byte[0]).status());
                long t1 = System.nanoTime();
                g.http.send(direct, HttpResponse.BodyHandlers.ofString());
                long t2 = System.nanoTime();
                via.add(t1 - t0);
                base.add(t2 - t1);
            }
            double viaP50 = pct(via, 0.50);
            double viaP99 = pct(via, 0.99);
            double baseP99 = pct(base, 0.99);
            System.out.printf("gateway latency: through gateway p50 %.2f ms p99 %.2f ms; direct p50 %.2f ms p99 %.2f ms;"
                    + " added p99 %.2f ms%n", viaP50, viaP99, pct(base, 0.50), baseP99, viaP99 - baseP99);
            assertTrue(viaP99 - baseP99 < 20.0, "target: the gateway adds under 20 ms at p99 locally");
        }
    }

    private static double pct(List<Long> nanos, double p) {
        List<Long> s = new ArrayList<>(nanos);
        Collections.sort(s);
        return s.get((int) Math.min(s.size() - 1, Math.ceil(p * s.size()) - 1)) / 1e6;
    }
}

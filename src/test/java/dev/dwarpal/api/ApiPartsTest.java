package dev.dwarpal.api;

import dev.dwarpal.edge.EdgeFixtures;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.TlsContexts;
import org.junit.jupiter.api.Test;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.InputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Settings bounds, the pinned trust manager on its own, and the client when its thread is interrupted. */
class ApiPartsTest {

    @Test
    void settingsOutOfRangeAreRefused() {
        Duration s = Duration.ofSeconds(1);
        int[][] bad = {{0, 1, 1, 1, 1, 1}, {257, 1, 1, 1, 1, 1}, {1, 0, 1, 1, 1, 1}, {1, 10_001, 1, 1, 1, 1},
                {1, 1, 0, 1, 1, 1}, {1, 1, 1, 0, 1, 1}, {1, 1, 1, 1, 0, 1}, {1, 1, 1, 1, 1, 0}};
        for (int[] b : bad) {
            assertThrows(IllegalArgumentException.class, () -> new ApiSettings(b[0], b[1], b[2], b[3], s, b[4], s, b[5]),
                    Arrays.toString(b));
        }
        assertThrows(IllegalArgumentException.class, () -> new ApiSettings(1, 1, 1, 1, Duration.ofMinutes(2), 1, s, 1));
        assertThrows(IllegalArgumentException.class, () -> new ApiSettings(1, 1, 1, 1, s.negated(), 1, s, 1));
        assertThrows(IllegalArgumentException.class, () -> new ApiSettings(1, 1, 1, 1, s, 1, Duration.ZERO, 1));
        assertThrows(IllegalArgumentException.class, () -> new ApiSettings(1, 1, 1, 1, s, 1, s.negated(), 1));
        assertDoesNotThrow(() -> new ApiSettings(1, 1, 1, 1, s, 1, s, 1));
    }

    @Test
    void thePinnedTrustManagerAcceptsOnlyTheApi() throws Exception {
        X509ExtendedTrustManager tm = PinnedTls.trust(ApiKit.pki().trustStore(), ApiKit.pki().password(),
                TlsContexts.component("api"));
        X509Certificate[] api = chain("api");
        X509Certificate[] swg = chain("swg");
        tm.checkServerTrusted(api, "ECDHE_ECDSA");
        tm.checkServerTrusted(api, "ECDHE_ECDSA", (Socket) null);
        assertThrows(CertificateException.class, () -> tm.checkServerTrusted(swg, "ECDHE_ECDSA"), "right CA, wrong component");
        assertThrows(CertificateException.class, () -> tm.checkServerTrusted(swg, "ECDHE_ECDSA", (Socket) null));
        assertThrows(RuntimeException.class, () -> tm.checkServerTrusted(new X509Certificate[0], "ECDHE_ECDSA"),
                "an empty chain is refused (by the PKIX check, before the subject check)");
        assertThrows(CertificateException.class, () -> tm.checkClientTrusted(api, "ECDHE_ECDSA"), "never a server's trust manager");
        assertThrows(CertificateException.class, () -> tm.checkClientTrusted(api, "ECDHE_ECDSA", (Socket) null));
        assertThrows(CertificateException.class, () -> tm.checkClientTrusted(api, "ECDHE_ECDSA", (javax.net.ssl.SSLEngine) null));
        assertEquals(1, tm.getAcceptedIssuers().length, "the Dwarpal CA only");
        assertTrue(PinnedTls.sameSubject(TlsContexts.component("api"), new javax.security.auth.x500.X500Principal("CN=api")));
    }

    private static X509Certificate[] chain(String leaf) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(ApiKit.pki().keyStore(leaf))) {
            ks.load(in, ApiKit.pki().password());
        }
        return Arrays.stream(ks.getCertificateChain(leaf)).map(c -> (X509Certificate) c).toArray(X509Certificate[]::new);
    }

    @Test
    void anInterruptedCallerGetsADenyAndKeepsItsInterrupt() {
        try (ApiKit.Harness h = new ApiKit.Harness(ApiSettings.defaults()); RemoteSessionAuthority c = h.client("gateway")) {
            Thread.currentThread().interrupt();
            EdgeResult r = c.decide(h.world.request().resource("web:general").build());
            assertTrue(Thread.interrupted(), "the interrupt is passed on");
            assertEquals(EdgeResult.Status.DENIED, r.status());
            KeyPairHolder k = new KeyPairHolder();
            EdgeResult used = c.use("A".repeat(43), dev.dwarpal.edge.ClientProofs.sign(k.pair.getPrivate(), "s-1",
                    h.world.request().build(), h.world.clock.now()), h.world.request().build());
            assertEquals(EdgeResult.Status.REJECTED, used.status(), "an unknown token, over the network");
        }
        assertEquals(EdgeFixtures.T, EdgeFixtures.world().clock.now());
    }

    private static final class KeyPairHolder {
        final java.security.KeyPair pair = dev.dwarpal.crypto.Ed25519.generateKeyPair();
    }
}

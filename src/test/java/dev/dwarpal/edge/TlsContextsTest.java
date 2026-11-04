package dev.dwarpal.edge;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Real TLS handshakes over loopback with certificates from the development CA. */
class TlsContextsTest {

    @TempDir
    static Path dir;
    private static DevPki pki;
    private static DevPki rogue;

    @BeforeAll
    static void pki() throws Exception {
        pki = DevPki.create(dir.resolve("dwarpal"), "Dwarpal Dev CA",
                List.of(DevPki.Leaf.valid("api"), DevPki.Leaf.valid("gateway"), DevPki.Leaf.expired("old-gateway")));
        rogue = DevPki.create(dir.resolve("rogue"), "Some Other CA", List.of(DevPki.Leaf.valid("gateway")));
    }

    private static SSLContext ctx(DevPki p, String leaf) throws Exception {
        return TlsContexts.create(p.keyStore(leaf), p.password(), pki.trustStore(), pki.password());
    }

    /** Server 'api' accepts one connection; returns the client's CN as the server saw it, or empty on failure. */
    private static Optional<javax.security.auth.x500.X500Principal> handshake(SSLContext client, SSLParameters clientParams) throws Exception {
        SSLContext server = ctx(pki, "api");
        try (SSLServerSocket ss = (SSLServerSocket) server.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            ss.setSSLParameters(TlsContexts.serverParameters(server));
            ss.setSoTimeout(10_000);
            CompletableFuture<Optional<javax.security.auth.x500.X500Principal>> seen = CompletableFuture.supplyAsync(() -> {
                try (SSLSocket s = (SSLSocket) ss.accept()) {
                    s.setSoTimeout(10_000);
                    s.startHandshake();
                    Optional<javax.security.auth.x500.X500Principal> cn = TlsContexts.peerPrincipal(s.getSession());
                    s.getOutputStream().write(1);
                    s.getOutputStream().flush();
                    return cn;
                } catch (IOException e) {
                    return Optional.empty();
                }
            });
            try (SSLSocket c = (SSLSocket) client.getSocketFactory().createSocket("localhost", ss.getLocalPort())) {
                c.setSSLParameters(clientParams);
                c.setSoTimeout(10_000);
                c.startHandshake();
                c.getInputStream().read();
            } catch (IOException expectedOnFailure) {
                // the server's view decides the outcome
            }
            return seen.get(20, TimeUnit.SECONDS);
        }
    }

    @Test
    void mutualTls13WorksAndTheServerLearnsWhoIsCalling() throws Exception {
        SSLContext gw = ctx(pki, "gateway");
        assertEquals(Optional.of(TlsContexts.component("gateway")), handshake(gw, TlsContexts.clientParameters(gw)));
    }

    @Test
    void aClientWithoutACertificateIsRefused() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        KeyStore trust = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(pki.trustStore())) {
            trust.load(in, pki.password());
        }
        tmf.init(trust);
        SSLContext anonymous = SSLContext.getInstance("TLSv1.3");
        anonymous.init(null, tmf.getTrustManagers(), null);
        assertTrue(handshake(anonymous, TlsContexts.clientParameters(anonymous)).isEmpty());
    }

    @Test
    void aCertificateFromAnotherCaIsRefusedEvenWithTheRightName() throws Exception {
        SSLContext impostor = TlsContexts.create(rogue.keyStore("gateway"), rogue.password(), pki.trustStore(), pki.password());
        assertTrue(handshake(impostor, TlsContexts.clientParameters(impostor)).isEmpty());
    }

    @Test
    void anExpiredCertificateIsRefused() throws Exception {
        SSLContext old = ctx(pki, "old-gateway");
        assertTrue(handshake(old, TlsContexts.clientParameters(old)).isEmpty());
    }

    @Test
    void olderTlsVersionsAreRefused() throws Exception {
        SSLContext gw = ctx(pki, "gateway");
        SSLParameters tls12 = TlsContexts.clientParameters(gw);
        tls12.setProtocols(new String[]{"TLSv1.2"});
        tls12.setCipherSuites(new String[]{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"});
        assertTrue(handshake(gw, tls12).isEmpty());
        assertEquals(List.of("TLSv1.3"), List.of(TlsContexts.serverParameters(gw).getProtocols()));
        assertTrue(TlsContexts.serverParameters(gw).getNeedClientAuth());
    }

    @Test
    void devPkiRefusesLeafNamesThatWouldShareAFile() {
        // Integration request R6: Gateway.p12 and gateway.p12 are the same file on Windows.
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> DevPki.create(
                java.nio.file.Path.of("unused"), "x", java.util.List.of(DevPki.Leaf.valid("gateway"), DevPki.Leaf.valid("Gateway"))));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> DevPki.create(
                java.nio.file.Path.of("unused"), "x", java.util.List.of(DevPki.Leaf.valid("CA"))));
    }
}

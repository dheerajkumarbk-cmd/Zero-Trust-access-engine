package dev.dwarpal.swg;

import dev.dwarpal.edge.DevPki;
import dev.dwarpal.edge.TlsContexts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The gateway as an HTTPS proxy: the deployer hands it a TLS listener from {@link TlsContexts}, so the
 * leg between the client agent and the gateway is TLS 1.3 with a client certificate, and the tunnel
 * runs inside it. Also the rules for the listener itself.
 */
class HttpsProxyTest {

    @TempDir
    Path dir;

    private final SwgWorld s = new SwgWorld();
    private final List<AutoCloseable> open = new ArrayList<>();

    @AfterEach
    void closeAll() throws Exception {
        for (AutoCloseable c : open) {
            c.close();
        }
    }

    @Test
    void aTunnelRunsInsideMutualTls() throws Exception {
        DevPki pki = DevPki.create(dir.resolve("pki"), "Dwarpal Dev CA",
                List.of(DevPki.Leaf.valid("gateway"), DevPki.Leaf.valid("agent")));
        SSLContext server = TlsContexts.create(pki.keyStore("gateway"), pki.password(), pki.trustStore(), pki.password());
        SSLContext agent = TlsContexts.create(pki.keyStore("agent"), pki.password(), pki.trustStore(), pki.password());
        TestServers.Server echo = TestServers.echo();
        open.add(echo);

        SSLServerSocket listener = (SSLServerSocket) server.getServerSocketFactory()
                .createServerSocket(0, 16, InetAddress.getLoopbackAddress());
        listener.setSSLParameters(TlsContexts.serverParameters(server));
        WebAccess access = s.access(SwgWorld.policy().tunnelPorts(Set.of(echo.port()))
                .allowInternalAddresses(Set.of("127.0.0.1")).build());
        WebGateway g = new WebGateway(access, s.loopbackIsAlice(), SwgWorld.allLoopback(), WebGateway.Settings.defaults());
        g.start(listener);
        open.add(g);

        try (SSLSocket c = (SSLSocket) agent.getSocketFactory().createSocket(InetAddress.getLoopbackAddress(), g.port())) {
            c.setSSLParameters(TlsContexts.clientParameters(agent));
            c.setSoTimeout(5000);
            c.startHandshake();
            assertEquals("TLSv1.3", c.getSession().getProtocol());
            c.getOutputStream().write(("CONNECT news.example:" + echo.port() + " HTTP/1.1\r\n\r\nhi")
                    .getBytes(StandardCharsets.US_ASCII));
            InputStream in = c.getInputStream();
            assertTrue(TestServers.readHead(in).startsWith("HTTP/1.1 200"));
            assertEquals("hi", new String(in.readNBytes(2), StandardCharsets.US_ASCII));
        }
    }

    @Test
    void aClientWithoutACertificateFromTheRightCaGetsNothing() throws Exception {
        DevPki pki = DevPki.create(dir.resolve("pki"), "Dwarpal Dev CA", List.of(DevPki.Leaf.valid("gateway")));
        DevPki rogue = DevPki.create(dir.resolve("rogue"), "Some Other CA", List.of(DevPki.Leaf.valid("agent")));
        SSLContext server = TlsContexts.create(pki.keyStore("gateway"), pki.password(), pki.trustStore(), pki.password());
        SSLContext stranger = TlsContexts.create(rogue.keyStore("agent"), rogue.password(), pki.trustStore(), pki.password());

        SSLServerSocket listener = (SSLServerSocket) server.getServerSocketFactory()
                .createServerSocket(0, 16, InetAddress.getLoopbackAddress());
        listener.setSSLParameters(TlsContexts.serverParameters(server));
        WebGateway g = new WebGateway(s.access(WebPolicy.defaults()), s.loopbackIsAlice(), SwgWorld.allLoopback(),
                WebGateway.Settings.defaults());
        g.start(listener);
        open.add(g);

        assertThrows(IOException.class, () -> {
            try (SSLSocket c = (SSLSocket) stranger.getSocketFactory().createSocket(InetAddress.getLoopbackAddress(), g.port())) {
                c.setSSLParameters(TlsContexts.clientParameters(stranger));
                c.setSoTimeout(5000);
                c.startHandshake();
                c.getOutputStream().write("CONNECT news.example:443 HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                if (c.getInputStream().read() < 0) {
                    throw new SSLException("closed by the gateway");
                }
            }
        });
    }

    @Test
    void theListenerMustBeBoundAndOpenAndUsedOnce() throws IOException {
        WebGateway g = new WebGateway(s.access(WebPolicy.defaults()), s.loopbackIsAlice(), SwgWorld.allLoopback(),
                WebGateway.Settings.defaults());
        open.add(g);
        assertThrows(IllegalArgumentException.class, () -> g.start(new ServerSocket()));
        ServerSocket closed = TestServers.loopbackListener();
        closed.close();
        assertThrows(IllegalArgumentException.class, () -> g.start(closed));
        g.start(TestServers.loopbackListener());
        assertThrows(IllegalStateException.class, () -> g.start(TestServers.loopbackListener()));
    }
}

package dev.dwarpal.edge;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * One TLS configuration for every connection between Dwarpal components: TLS 1.3 only, AEAD cipher
 * suites only, and <b>mutual</b> authentication (both sides present a certificate from the private
 * Dwarpal CA). Nothing in Layer 4 should configure TLS any other way.
 *
 * <p>The trust store should contain only the Dwarpal CA, so a certificate from any public CA, however
 * valid, is not accepted as a Dwarpal component.
 */
public final class TlsContexts {

    public static final List<String> PROTOCOLS = List.of("TLSv1.3");
    public static final List<String> CIPHER_SUITES = List.of(
            "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256");
    private static final String STORE_TYPE = "PKCS12";

    private TlsContexts() {
    }

    /**
     * @param keyStore   this component's private key and certificate chain (PKCS12)
     * @param trustStore the Dwarpal CA certificate (PKCS12)
     */
    public static SSLContext create(Path keyStore, char[] keyStorePassword, Path trustStore, char[] trustStorePassword)
            throws IOException, GeneralSecurityException {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        kmf.init(load(keyStore, keyStorePassword), keyStorePassword);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(load(trustStore, trustStorePassword));
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    /** For a server: TLS 1.3, strong suites, client certificate required. */
    public static SSLParameters serverParameters(SSLContext ctx) {
        SSLParameters p = hardened(ctx);
        p.setNeedClientAuth(true);
        return p;
    }

    /** For a client: TLS 1.3, strong suites, and the server's certificate must match the host name. */
    public static SSLParameters clientParameters(SSLContext ctx) {
        SSLParameters p = hardened(ctx);
        p.setEndpointIdentificationAlgorithm("HTTPS");
        return p;
    }

    /**
     * The subject of the peer's verified certificate (who is calling), if the peer presented one.
     * Callers identify components by comparing this whole name exactly, for example with
     * {@code new X500Principal("CN=gateway")}, never by parsing parts out of it.
     */
    public static Optional<X500Principal> peerPrincipal(SSLSession session) {
        Objects.requireNonNull(session, "session");
        try {
            Certificate[] chain = session.getPeerCertificates();
            if (chain.length == 0 || !(chain[0] instanceof X509Certificate leaf)) {
                return Optional.empty();
            }
            return Optional.of(leaf.getSubjectX500Principal());
        } catch (SSLPeerUnverifiedException e) {
            return Optional.empty();
        }
    }

    /** The principal of a Dwarpal component certificate made by the development CA: {@code CN=name}. */
    public static X500Principal component(String name) {
        return new X500Principal("CN=" + dev.dwarpal.domain.Validate.id(name, "component"));
    }

    private static SSLParameters hardened(SSLContext ctx) {
        SSLParameters p = ctx.getDefaultSSLParameters();
        p.setProtocols(PROTOCOLS.toArray(String[]::new));
        p.setCipherSuites(CIPHER_SUITES.toArray(String[]::new));
        return p;
    }

    private static KeyStore load(Path file, char[] password) throws IOException, GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance(STORE_TYPE);
        try (InputStream in = Files.newInputStream(file)) {
            ks.load(in, password);
        }
        return ks;
    }
}

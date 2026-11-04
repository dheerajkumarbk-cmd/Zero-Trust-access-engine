package dev.dwarpal.edge;


import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.security.auth.x500.X500Principal;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * A client TLS context that trusts the Dwarpal CA <em>and</em> only one server certificate subject.
 *
 * <p>Why (red-team finding A1): every component certificate from the CA is valid for {@code localhost},
 * so with the CA alone a compromised web gateway or CASB could answer in the API's place, receive the
 * session tokens and proofs sent to it, and say GRANTED. The subject is checked during the handshake,
 * before a single byte of a request is sent. Built by {@link TlsContexts#createPinned}.
 */
final class PinnedTrust {

    private PinnedTrust() {
    }


    /** The trust manager on its own: PKIX against the trust store, then the exact subject. */
    static X509ExtendedTrustManager trust(KeyStore trustStore, X500Principal server) throws GeneralSecurityException {
        Objects.requireNonNull(server, "server");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(trustStore);
        X509ExtendedTrustManager pkix = null;
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509ExtendedTrustManager x) {
                pkix = x;
            }
        }
        if (pkix == null) {
            throw new GeneralSecurityException("no PKIX trust manager");
        }
        return new Pinned(pkix, server);
    }



    /** The CA's PKIX checks (chain, validity, host name), then the subject. */
    private static final class Pinned extends X509ExtendedTrustManager {
        private final X509ExtendedTrustManager pkix;
        private final X500Principal server;

        Pinned(X509ExtendedTrustManager pkix, X500Principal server) {
            this.pkix = pkix;
            this.server = server;
        }

        private void pinned(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length == 0 || !TlsContexts.samePrincipal(chain[0].getSubjectX500Principal(), server)) {
                throw new CertificateException("server is not the expected component");
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            pkix.checkServerTrusted(chain, authType, engine);
            pinned(chain);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            pkix.checkServerTrusted(chain, authType, socket);
            pinned(chain);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            pkix.checkServerTrusted(chain, authType);
            pinned(chain);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            throw new CertificateException("client context");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            throw new CertificateException("client context");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("client context");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return pkix.getAcceptedIssuers();
        }
    }
}

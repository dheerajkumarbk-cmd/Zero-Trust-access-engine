package dev.dwarpal.gateway;

import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.domain.Validate;

import javax.net.ssl.SSLContext;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Everything the gateway is configured with. Defaults are the safe ones: loopback only, bounded sizes,
 * short timeouts. The upstream secret is copied in and out, never shown by {@link #toString()}.
 */
public final class GatewayConfig {

    public static final int MIN_SECRET_BYTES = 32;
    public static final Duration MIN_DEADLINE = Duration.ofMillis(100);
    public static final Duration MAX_DEADLINE = Duration.ofMinutes(5);

    private final byte[] bindAddress;
    private final int port;
    private final RouteTable routes;
    private final byte[] upstreamSecret;
    private final KeyRing identityProviders;
    private final NetworkResolver network;
    private final String pepRegion;
    private final Clock clock;
    private final int maxRequestBody;
    private final int maxResponseBody;
    private final int maxHeaderBytes;
    private final int maxHeaders;
    private final int maxInFlight;
    private final int maxSessions;
    private final int loginsPerMinutePerAddress;
    private final Duration connectTimeout;
    private final Duration upstreamTimeout;
    private final Duration requestDeadline;
    private final Duration maxLoginAuthenticationAge;
    private final SSLContext tls;
    private final boolean requireClientCertificate;

    private GatewayConfig(Builder b) {
        this.bindAddress = Objects.requireNonNull(b.bindAddress, "bindAddress").getAddress();
        if (b.port < 0 || b.port > 65_535) {
            throw new IllegalArgumentException("port out of range");
        }
        this.port = b.port;
        this.routes = Objects.requireNonNull(b.routes, "routes");
        if (b.upstreamSecret == null || b.upstreamSecret.length < MIN_SECRET_BYTES) {
            throw new IllegalArgumentException("upstream secret must be at least " + MIN_SECRET_BYTES + " bytes");
        }
        this.upstreamSecret = b.upstreamSecret.clone();
        this.identityProviders = Objects.requireNonNull(b.identityProviders, "identityProviders");
        this.network = Objects.requireNonNull(b.network, "network");
        this.pepRegion = Validate.label(b.pepRegion, "pepRegion");
        this.clock = Objects.requireNonNull(b.clock, "clock");
        this.maxRequestBody = positive(b.maxRequestBody, "maxRequestBody");
        this.maxResponseBody = positive(b.maxResponseBody, "maxResponseBody");
        this.maxHeaderBytes = positive(b.maxHeaderBytes, "maxHeaderBytes");
        this.maxHeaders = positive(b.maxHeaders, "maxHeaders");
        this.maxInFlight = positive(b.maxInFlight, "maxInFlight");
        this.maxSessions = positive(b.maxSessions, "maxSessions");
        this.loginsPerMinutePerAddress = positive(b.loginsPerMinutePerAddress, "loginsPerMinutePerAddress");
        this.connectTimeout = Objects.requireNonNull(b.connectTimeout, "connectTimeout");
        this.upstreamTimeout = Objects.requireNonNull(b.upstreamTimeout, "upstreamTimeout");
        this.requestDeadline = Objects.requireNonNull(b.requestDeadline, "requestDeadline");
        if (requestDeadline.compareTo(MIN_DEADLINE) < 0 || requestDeadline.compareTo(MAX_DEADLINE) > 0) {
            throw new IllegalArgumentException("requestDeadline must be between " + MIN_DEADLINE + " and " + MAX_DEADLINE);
        }
        this.maxLoginAuthenticationAge = Objects.requireNonNull(b.maxLoginAuthenticationAge, "maxLoginAuthenticationAge");
        this.tls = b.tls;
        this.requireClientCertificate = b.requireClientCertificate;
    }

    public static Builder builder(RouteTable routes, byte[] upstreamSecret, KeyRing identityProviders) {
        return new Builder(routes, upstreamSecret, identityProviders);
    }

    /** A fresh object each time: the configuration cannot be changed through it. */
    public InetAddress bindAddress() {
        try {
            return InetAddress.getByAddress(bindAddress);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("unreachable: the address had a valid length", e);
        }
    }

    public int port() {
        return port;
    }

    public RouteTable routes() {
        return routes;
    }

    /** A copy: the caller cannot change the gateway's secret. */
    public byte[] upstreamSecret() {
        return upstreamSecret.clone();
    }

    /** Keys trusted to sign the authentication a login must carry. */
    public KeyRing identityProviders() {
        return identityProviders;
    }

    public NetworkResolver network() {
        return network;
    }

    public String pepRegion() {
        return pepRegion;
    }

    public Clock clock() {
        return clock;
    }

    public int maxRequestBody() {
        return maxRequestBody;
    }

    public int maxResponseBody() {
        return maxResponseBody;
    }

    public int maxHeaderBytes() {
        return maxHeaderBytes;
    }

    public int maxHeaders() {
        return maxHeaders;
    }

    public int maxInFlight() {
        return maxInFlight;
    }

    public int maxSessions() {
        return maxSessions;
    }

    public int loginsPerMinutePerAddress() {
        return loginsPerMinutePerAddress;
    }

    public Duration connectTimeout() {
        return connectTimeout;
    }

    public Duration upstreamTimeout() {
        return upstreamTimeout;
    }

    /** The most time one request may take from the moment it holds a slot, body reading included (B9). */
    public Duration requestDeadline() {
        return requestDeadline;
    }

    public Duration maxLoginAuthenticationAge() {
        return maxLoginAuthenticationAge;
    }

    /** When present the gateway serves HTTPS (TLS 1.3) instead of plain HTTP. */
    public Optional<SSLContext> tls() {
        return Optional.ofNullable(tls);
    }

    public boolean requireClientCertificate() {
        return requireClientCertificate;
    }

    @Override
    public String toString() {
        return "GatewayConfig[bind=" + bindAddress().getHostAddress() + ":" + port + ", routes=" + routes.routes().size()
                + ", upstreamSecret=<redacted>, tls=" + (tls != null) + "]";
    }

    private static int positive(int v, String name) {
        if (v <= 0) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return v;
    }

    public static final class Builder {
        private InetAddress bindAddress = InetAddress.getLoopbackAddress();
        private int port;
        private final RouteTable routes;
        private final byte[] upstreamSecret;
        private final KeyRing identityProviders;
        private NetworkResolver network = NetworkResolver.fixed(Map.of(),
                new NetworkContext("0.0.0.0", "AS0", "ZZ", 0, 0, 20_000));
        private String pepRegion = "gateway";
        private Clock clock = Clock.systemUTC();
        private int maxRequestBody = 1 << 20;
        private int maxResponseBody = 8 << 20;
        private int maxHeaderBytes = 32 * 1024;
        private int maxHeaders = 100;
        private int maxInFlight = 256;
        private int maxSessions = 100_000;
        private int loginsPerMinutePerAddress = 30;
        private Duration connectTimeout = Duration.ofSeconds(2);
        private Duration upstreamTimeout = Duration.ofSeconds(10);
        private Duration requestDeadline = Duration.ofSeconds(30);
        private Duration maxLoginAuthenticationAge = Duration.ofMinutes(5);
        private SSLContext tls;
        private boolean requireClientCertificate;

        private Builder(RouteTable routes, byte[] upstreamSecret, KeyRing identityProviders) {
            this.routes = routes;
            this.upstreamSecret = upstreamSecret == null ? null : upstreamSecret.clone();
            this.identityProviders = identityProviders;
        }

        public Builder bindAddress(InetAddress v) {
            bindAddress = v == null ? null : copy(v);
            return this;
        }

        private static InetAddress copy(InetAddress v) {
            try {
                return InetAddress.getByAddress(v.getAddress());
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("invalid bind address", e);
            }
        }

        public Builder port(int v) { port = v; return this; }
        public Builder network(NetworkResolver v) { network = v; return this; }
        public Builder pepRegion(String v) { pepRegion = v; return this; }
        public Builder clock(Clock v) { clock = v; return this; }
        public Builder maxRequestBody(int v) { maxRequestBody = v; return this; }
        public Builder maxResponseBody(int v) { maxResponseBody = v; return this; }
        public Builder maxHeaderBytes(int v) { maxHeaderBytes = v; return this; }
        public Builder maxHeaders(int v) { maxHeaders = v; return this; }
        public Builder maxInFlight(int v) { maxInFlight = v; return this; }
        public Builder maxSessions(int v) { maxSessions = v; return this; }
        public Builder loginsPerMinutePerAddress(int v) { loginsPerMinutePerAddress = v; return this; }
        public Builder connectTimeout(Duration v) { connectTimeout = v; return this; }
        public Builder upstreamTimeout(Duration v) { upstreamTimeout = v; return this; }
        public Builder requestDeadline(Duration v) { requestDeadline = v; return this; }
        public Builder maxLoginAuthenticationAge(Duration v) { maxLoginAuthenticationAge = v; return this; }
        /** Serve HTTPS with this context (TLS 1.3 only); optionally demand a client certificate. */
        public Builder tls(SSLContext v, boolean requireClientCertificate) {
            tls = v;
            this.requireClientCertificate = requireClientCertificate;
            return this;
        }

        public GatewayConfig build() {
            return new GatewayConfig(this);
        }
    }
}

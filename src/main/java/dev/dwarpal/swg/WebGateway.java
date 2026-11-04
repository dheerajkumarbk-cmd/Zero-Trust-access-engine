package dev.dwarpal.swg;

import dev.dwarpal.domain.Action;
import dev.dwarpal.edge.EdgeHttp;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import javax.net.SocketFactory;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The secure web gateway: an HTTP forward proxy that filters by host name.
 *
 * <ul>
 *   <li>{@code CONNECT host:port} (HTTPS): the destination is decided from the host name alone; the
 *       tunnel is opened only if allowed, and its bytes are relayed untouched (no TLS interception, so
 *       no certificate has to be installed on the client).</li>
 *   <li>Plain HTTP in absolute form ({@code GET http://host/path}): decided the same way, then forwarded
 *       with client-only and hop-by-hop headers removed, one request per connection.</li>
 * </ul>
 * Every connection must belong to a known client ({@link IdentityResolver}); the decision itself is
 * {@link WebAccess#check}. Refusals carry a generic message and a reference, never the reason.
 */
public final class WebGateway implements AutoCloseable {

    /** Headers a proxy must not forward (RFC 9110 section 7.6.1), plus ones it sets itself. */
    private static final Set<String> HOP_BY_HOP = Set.of("connection", "keep-alive", "proxy-connection",
            "proxy-authorization", "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade", "host",
            "content-length");

    private final WebAccess access;
    private final IdentityResolver identities;
    private final HostResolver resolver;
    private final Settings settings;
    private final SocketFactory upstreamSockets;
    private final Semaphore slots;
    private final ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
    private final ScheduledExecutorService watchdog = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "swg-watchdog");
        t.setDaemon(true);
        return t;
    });
    /** Closes the listener; the gateway keeps this handle and the port, not the socket itself. */
    private volatile Closeable stopListening;
    private volatile int localPort = -1;

    /**
     * Limits and timeouts.
     *
     * @param maxHeadBytes     largest request head accepted
     * @param maxHeaders       most header fields accepted
     * @param maxBodyBytes     largest plain HTTP request body forwarded
     * @param maxResponseBytes largest plain HTTP response relayed (the connection is cut after that)
     * @param readTimeout      longest wait for the next byte from the client, and also the longest total time to receive
     *                         one request head (and, separately, its body): a slow trickle is cut off
     * @param connectTimeout   longest wait to connect to a destination
     * @param tunnelIdle       a tunnel with no traffic for this long is closed
     * @param tunnelLifetime   a tunnel is closed after this long whatever happens (the decision is re-made on reconnect)
     * @param maxConnections   connections served at once; more are answered 503
     */
    public record Settings(int maxHeadBytes, int maxHeaders, int maxBodyBytes, long maxResponseBytes,
                           Duration readTimeout, Duration connectTimeout, Duration tunnelIdle,
                           Duration tunnelLifetime, int maxConnections) {

        public Settings {
            if (maxHeadBytes < 256 || maxHeaders < 1 || maxBodyBytes < 0 || maxResponseBytes < 1 || maxConnections < 1) {
                throw new IllegalArgumentException("limits must be positive");
            }
            for (Duration d : List.of(readTimeout, connectTimeout, tunnelIdle, tunnelLifetime)) {
                if (d.isNegative() || d.isZero() || d.toMillis() > Integer.MAX_VALUE) {
                    throw new IllegalArgumentException("timeouts must be positive");
                }
            }
        }

        public static Settings defaults() {
            return new Settings(32 * 1024, 100, 1024 * 1024, 32L * 1024 * 1024, Duration.ofSeconds(10),
                    Duration.ofSeconds(5), Duration.ofMinutes(5), Duration.ofMinutes(30), 256);
        }
    }

    public WebGateway(WebAccess access, IdentityResolver identities, HostResolver resolver, Settings settings) {
        this(access, identities, resolver, settings, SocketFactory.getDefault());
    }

    /**
     * @param upstreamSockets makes the sockets to destinations. These carry whatever the client sends
     *                        (its own TLS inside a tunnel, or plain HTTP), so they are plain TCP by nature
     */
    public WebGateway(WebAccess access, IdentityResolver identities, HostResolver resolver, Settings settings,
                      SocketFactory upstreamSockets) {
        this.upstreamSockets = Objects.requireNonNull(upstreamSockets, "upstreamSockets");
        this.access = Objects.requireNonNull(access, "access");
        this.identities = Objects.requireNonNull(identities, "identities");
        this.resolver = Objects.requireNonNull(resolver, "resolver");
        this.settings = Objects.requireNonNull(settings, "settings");
        this.slots = new Semaphore(settings.maxConnections());
    }

    /**
     * Serves clients that connect to {@code listener}, which the deployer creates and binds. The choice of
     * listener is the deployer's: a plain {@link ServerSocket} on a protected interface (the usual
     * HTTP proxy), or an {@code SSLServerSocket} from {@link dev.dwarpal.edge.TlsContexts} to make this
     * an HTTPS proxy whose clients authenticate with certificates.
     */
    public void start(ServerSocket listener) {
        Objects.requireNonNull(listener, "listener");
        if (!listener.isBound() || listener.isClosed()) {
            throw new IllegalArgumentException("the listener must be bound and open");
        }
        if (stopListening != null) {
            throw new IllegalStateException("already started");
        }
        stopListening = listener::close;
        localPort = listener.getLocalPort();
        Thread acceptor = new Thread(() -> acceptLoop(listener), "swg-accept");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    public int port() {
        int p = localPort;
        if (p < 0) {
            throw new IllegalStateException("not started");
        }
        return p;
    }

    @Override
    public void close() throws IOException {
        Closeable c = stopListening;
        if (c != null) {
            c.close();
        }
        workers.shutdownNow();
        watchdog.shutdownNow();
    }

    private void acceptLoop(ServerSocket s) {
        while (!s.isClosed()) {
            Socket client;
            try {
                client = s.accept();
            } catch (IOException e) {
                continue;
            }
            if (!slots.tryAcquire()) {
                workers.execute(() -> busy(client));
                continue;
            }
            workers.execute(() -> {
                try {
                    serve(client);
                } finally {
                    slots.release();
                }
            });
        }
    }

    private void busy(Socket client) {
        try (client) {
            client.setSoTimeout((int) settings.readTimeout().toMillis());
            respond(client.getOutputStream(), access.refuse(BlockReason.BUSY));
            lingeringClose(client, client.getInputStream(), 200_000_000L);
        } catch (IOException ignored) {
            // the client went away; nothing to do
        }
    }

    private void serve(Socket client) {
        try (client) {
            client.setSoTimeout((int) settings.readTimeout().toMillis());
            InputStream in = new BufferedInputStream(client.getInputStream());
            OutputStream out = new BufferedOutputStream(client.getOutputStream());
            Optional<HttpHead> read;
            RequestTimer timer = new RequestTimer(client);
            try {
                read = HttpHead.read(in, settings.maxHeadBytes(), settings.maxHeaders());
            } catch (HttpHead.Malformed e) {
                if (timer.finish()) {
                    respond(out, access.refuse(BlockReason.BAD_REQUEST));
                    lingeringClose(client, in, 2_000_000_000L);
                }
                return;
            }
            if (!timer.finish() || read.isEmpty()) {
                return;
            }
            HttpHead head = read.get();
            Optional<WebIdentity> who = identities.resolve(client.getInetAddress());
            if (who.isEmpty()) {
                respond(out, access.refuse(BlockReason.UNKNOWN_CLIENT));
                lingeringClose(client, in, 2_000_000_000L);
                return;
            }
            if (head.method.equals("CONNECT")) {
                tunnel(client, in, out, head, who.get());
            } else {
                forward(client, in, out, head, who.get());
            }
            lingeringClose(client, in, 2_000_000_000L);
        } catch (IOException | RuntimeException e) {
            // connection-level failure: the socket is closed by try-with-resources, nothing is forwarded
        }
    }

    private void tunnel(Socket client, InputStream in, OutputStream out, HttpHead head, WebIdentity who)
            throws IOException {
        WebVerdict v = access.check(who, head.target, true, Action.READ);
        if (!v.allowed()) {
            respond(out, v);
            return;
        }
        Destination d = v.destination().orElseThrow();
        Connection up = connect(d);
        if (up.socket() == null) {
            respond(out, access.refuseAfter(up.failure(), d, v.reference()));
            return;
        }
        try (Socket upstream = up.socket()) {
            out.write(HttpHead.ascii("HTTP/1.1 200 Connection Established\r\n\r\n"));
            out.flush();
            int idle = (int) settings.tunnelIdle().toMillis();
            client.setSoTimeout(idle);
            upstream.setSoTimeout(idle);
            var lifetime = watchdog.schedule(() -> {
                closeQuietly(upstream);
                closeQuietly(client);
            }, settings.tunnelLifetime().toMillis(), TimeUnit.MILLISECONDS);
            var back = workers.submit(() -> {
                pump(upstream.getInputStream(), client.getOutputStream(), Long.MAX_VALUE);
                closeQuietly(client);
                return null;
            });
            pump(in, upstream.getOutputStream(), Long.MAX_VALUE);
            closeQuietly(upstream);
            back.cancel(true);
            lifetime.cancel(false);
        }
    }

    private void forward(Socket client, InputStream in, OutputStream out, HttpHead head, WebIdentity who)
            throws IOException {
        Optional<Action> action = EdgeHttp.action(head.method, false, false);
        if (action.isEmpty()) {
            respond(out, access.refuse(BlockReason.METHOD_NOT_ALLOWED));
            return;
        }
        Optional<String[]> target = absoluteHttp(head.target);
        if (target.isEmpty()) {
            respond(out, access.refuse(BlockReason.BAD_REQUEST));
            return;
        }
        long length;
        try {
            length = bodyLength(head);
        } catch (HttpHead.Malformed e) {
            respond(out, access.refuse(BlockReason.BODY_NOT_ACCEPTED));
            return;
        }
        WebVerdict v = access.check(who, target.get()[0], false, action.get());
        if (!v.allowed()) {
            respond(out, v);
            return;
        }
        Destination d = v.destination().orElseThrow();
        RequestTimer timer = new RequestTimer(client);
        byte[] body = in.readNBytes((int) length);
        if (!timer.finish() || body.length != length) {
            return;
        }
        Connection up = connect(d);
        if (up.socket() == null) {
            respond(out, access.refuseAfter(up.failure(), d, v.reference()));
            return;
        }
        try (Socket upstream = up.socket()) {
            upstream.setSoTimeout((int) settings.readTimeout().toMillis());
            OutputStream uo = new BufferedOutputStream(upstream.getOutputStream());
            uo.write(HttpHead.ascii(requestHead(head, d, target.get()[1], body.length)));
            uo.write(body);
            uo.flush();
            pump(upstream.getInputStream(), out, settings.maxResponseBytes());
        }
    }

    /** {@code [authority, path-and-query]} of an absolute {@code http://} target. */
    static Optional<String[]> absoluteHttp(String target) {
        if (target.length() < 8 || !target.substring(0, 7).toLowerCase(Locale.ROOT).equals("http://")) {
            return Optional.empty();
        }
        String rest = target.substring(7);
        int slash = rest.indexOf('/');
        int query = rest.indexOf('?');
        int end = slash < 0 ? query : (query < 0 ? slash : Math.min(slash, query));
        String authority = end < 0 ? rest : rest.substring(0, end);
        String path = end < 0 ? "/" : rest.substring(end);
        if (path.startsWith("?")) {
            path = "/" + path;
        }
        if (authority.isEmpty() || path.indexOf('#') >= 0) {
            return Optional.empty();
        }
        return Optional.of(new String[] {authority, path});
    }

    private long bodyLength(HttpHead head) throws HttpHead.Malformed {
        if (!head.values("Transfer-Encoding").isEmpty()) {
            throw new HttpHead.Malformed("transfer codings are not accepted");
        }
        Optional<String> cl = head.single("Content-Length");
        if (cl.isEmpty()) {
            return 0;
        }
        String s = cl.get();
        if (s.isEmpty() || s.length() > 10 || !s.chars().allMatch(c -> c >= '0' && c <= '9')) {
            throw new HttpHead.Malformed("bad Content-Length");
        }
        long n = Long.parseLong(s);
        if (n > settings.maxBodyBytes()) {
            throw new HttpHead.Malformed("body too large");
        }
        return n;
    }

    private static String requestHead(HttpHead head, Destination d, String path, int bodyLength) {
        Set<String> named = new HashSet<>();
        for (String v : head.values("Connection")) {
            for (String t : v.split(",")) {
                named.add(t.strip().toLowerCase(Locale.ROOT));
            }
        }
        StringBuilder sb = new StringBuilder(256).append(head.method).append(' ').append(path).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(d.port() == 80 ? d.host().toString() : d.authority()).append("\r\n");
        for (HttpHead.Header h : head.headers) {
            String n = h.name().toLowerCase(Locale.ROOT);
            if (!HOP_BY_HOP.contains(n) && !named.contains(n) && !EdgeHttp.clientOnly(h.name())) {
                sb.append(h.name()).append(": ").append(h.value()).append("\r\n");
            }
        }
        if (bodyLength > 0 || !head.method.equals("GET") && !head.method.equals("HEAD")) {
            sb.append("Content-Length: ").append(bodyLength).append("\r\n");
        }
        return sb.append("Connection: close\r\n\r\n").toString();
    }

    /** A connected socket, or why there is none. */
    private record Connection(Socket socket, BlockReason failure) {
    }

    /**
     * Connects to one of the destination's addresses. Addresses that are not on the public internet are
     * skipped unless the operator allowed them: a public name pointing inward is an SSRF, not a website.
     * We connect to the address we checked, never to a second lookup of the name (no rebinding window).
     */
    private Connection connect(Destination d) {
        List<InetAddress> addresses;
        try {
            addresses = resolver.resolve(d.host());
        } catch (IOException | RuntimeException e) {
            return new Connection(null, BlockReason.UPSTREAM_FAILED);
        }
        WebPolicy policy = access.filter().policy();
        boolean skipped = false;
        boolean tried = false;
        for (InetAddress a : addresses) {
            if (Addresses.internal(a) && !policy.internalAddressAllowed(HostName.of(a).value())) {
                skipped = true;
                continue;
            }
            tried = true;
            Socket s = null;
            try {
                s = upstreamSockets.createSocket();
                s.connect(new InetSocketAddress(a, d.port()), (int) settings.connectTimeout().toMillis());
                return new Connection(s, null);
            } catch (IOException e) {
                if (s != null) {
                    closeQuietly(s);
                }
            }
        }
        return new Connection(null, skipped && !tried ? BlockReason.INTERNAL_ADDRESS : BlockReason.UPSTREAM_FAILED);
    }

    private static void pump(InputStream from, OutputStream to, long max) throws IOException {
        byte[] buf = new byte[16 * 1024];
        long total = 0;
        try {
            while (true) {
                int n = from.read(buf);
                if (n < 0) {
                    break;
                }
                total += n;
                if (total > max) {
                    break;
                }
                to.write(buf, 0, n);
                to.flush();
            }
        } catch (SocketException e) {
            // the other side or the watchdog closed the connection
        }
        to.flush();
    }

    private static void respond(OutputStream out, WebVerdict v) throws IOException {
        BlockReason r = v.reason().orElse(BlockReason.DENIED);
        String status = switch (r) {
            case BAD_REQUEST, BAD_HOST -> "400 Bad Request";
            case REQUEST_TIMEOUT -> "408 Request Timeout";
            case METHOD_NOT_ALLOWED -> "405 Method Not Allowed";
            case BODY_NOT_ACCEPTED -> "413 Content Too Large";
            case UPSTREAM_FAILED -> "502 Bad Gateway";
            case BUSY -> "503 Service Unavailable";
            default -> "403 Forbidden";
        };
        byte[] body = (v.userMessage() + "\n").getBytes(StandardCharsets.UTF_8);
        String head = "HTTP/1.1 " + status + "\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: "
                + body.length + "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n";
        out.write(HttpHead.ascii(head));
        out.write(body);
        out.flush();
    }

    /**
     * Gives a client {@code readTimeout} in total to send its request head (or body). When it runs out,
     * the client is told 408 and the connection is closed, so a trickle of one byte per read cannot
     * keep a connection slot busy for hours (slow-loris). {@link #finish} says whether the request
     * arrived in time.
     */
    private final class RequestTimer {
        private final AtomicInteger state = new AtomicInteger();
        private final ScheduledFuture<?> task;

        RequestTimer(Socket client) {
            task = watchdog.schedule(() -> {
                if (state.compareAndSet(0, 1)) {
                    try {
                        respond(client.getOutputStream(), access.refuse(BlockReason.REQUEST_TIMEOUT));
                    } catch (IOException ignored) {
                        // the client is gone already
                    }
                    closeQuietly(client);
                }
            }, settings.readTimeout().toMillis(), TimeUnit.MILLISECONDS);
        }

        /** False if time ran out first (the client has been answered and disconnected). */
        boolean finish() {
            boolean inTime = state.compareAndSet(0, 2);
            task.cancel(false);
            return inTime;
        }
    }

    /**
     * Closes our side first and reads away what the client is still sending, briefly, so that the
     * answer is not lost to a connection reset when the client has not finished writing.
     */
    private static void lingeringClose(Socket client, InputStream in, long budgetNanos) {
        if (client.isClosed()) {
            return;
        }
        try {
            client.shutdownOutput();
            client.setSoTimeout(100);
            byte[] buf = new byte[8192];
            long left = 256 * 1024;
            long deadline = System.nanoTime() + budgetNanos;
            int n;
            while (left > 0 && System.nanoTime() < deadline && (n = in.read(buf)) > 0) {
                left -= n;
            }
        } catch (IOException e) {
            // the client closed or stopped sending; either way we are done
        }
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // already closed
        }
    }
}

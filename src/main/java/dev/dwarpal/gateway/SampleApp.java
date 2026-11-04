package dev.dwarpal.gateway;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.dwarpal.edge.EdgeHttp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A tiny internal application behind the gateway, for tests and the demo: a wiki with pages to read
 * and edit, files to download and an admin settings page, plus a vault with one secret page.
 *
 * <pre>
 *   GET            /wiki/pages/{name}     read           PUT|POST /wiki/pages/{name}   edit
 *   DELETE         /wiki/pages/{name}     delete         GET      /wiki/download/{name} download
 *   GET|POST       /wiki/admin/settings   administer     GET      /vault/secrets/{name} read a secret
 *   GET            /wiki/go/{name}        redirect (absolute, to its own address)
 * </pre>
 *
 * <p>It deliberately behaves like many real servers, because those are what a gateway must protect:
 * it matches paths case-insensitively, honours {@code X-HTTP-Method-Override} (as method-override
 * middleware does), and builds absolute redirects from its own address. It trusts nobody but the gateway:
 * it listens on loopback only and refuses any request without the gateway's secret (compared in
 * constant time). It records the header names it receives, so tests can prove the client's Dwarpal
 * headers never reach it.
 */
public final class SampleApp implements AutoCloseable {

    /** What the application saw of one request. */
    public record Seen(String method, String path, String subject, Set<String> headerNames) {
        public Seen {
            headerNames = Set.copyOf(headerNames);
        }
    }

    private static final Pattern PAGE = Pattern.compile("/wiki/pages/([a-z0-9-]{1,64})");
    private static final Pattern DOWNLOAD = Pattern.compile("/wiki/download/([a-z0-9-]{1,64})");
    private static final Pattern GO = Pattern.compile("/wiki/go/([a-z0-9-]{1,64})");
    private static final Pattern SECRET = Pattern.compile("/vault/secrets/([a-z0-9-]{1,64})");
    private static final int MAX_PAGE = 64 * 1024;
    private static final int MAX_PAGES = 1000;
    private static final int KEEP_SEEN = 1000;

    private final HttpServer server;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final byte[] secret;
    private final Map<String, String> pages = new ConcurrentHashMap<>();
    private final Deque<Seen> seen = new ArrayDeque<>();
    private final Object seenLock = new Object();
    private volatile String settings = "theme=light";

    private SampleApp(HttpServer server, byte[] gatewaySecret) {
        this.server = server;
        this.secret = Base64.getEncoder().encode(gatewaySecret);
        pages.put("home", "Welcome to the wiki.");
        pages.put("plans", "Q4 plans: ship Layer 4.");
    }

    /**
     * Starts on a loopback address only.
     *
     * @param gatewaySecret the same secret the gateway is configured with
     */
    public static SampleApp start(InetAddress loopback, int port, byte[] gatewaySecret) throws IOException {
        if (!loopback.isLoopbackAddress()) {
            throw new IllegalArgumentException("the sample app listens on loopback only");
        }
        if (gatewaySecret.length < GatewayConfig.MIN_SECRET_BYTES) {
            throw new IllegalArgumentException("gateway secret too short");
        }
        SampleApp app = new SampleApp(HttpServer.create(new InetSocketAddress(loopback, port), 0), gatewaySecret);
        app.server.createContext("/", app::handle);
        app.server.setExecutor(app.executor);
        app.server.start();
        return app;
    }

    public URI uri() {
        InetSocketAddress a = server.getAddress();
        return URI.create("http://" + a.getAddress().getHostAddress() + ":" + a.getPort());
    }

    /** The most recent requests, oldest first. */
    public List<Seen> seen() {
        synchronized (seenLock) {
            return List.copyOf(seen);
        }
    }

    public Optional<String> page(String name) {
        return Optional.ofNullable(pages.get(name));
    }

    public String settings() {
        return settings;
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    private void handle(HttpExchange ex) {
        try (ex) {
            Headers h = ex.getRequestHeaders();
            String presented = h.getFirst(ZtnaGateway.UPSTREAM_GATEWAY);
            if (presented == null || !MessageDigest.isEqual(secret, presented.getBytes(StandardCharsets.US_ASCII))) {
                reply(ex, 401, "unauthorised");
                return;
            }
            String subject = h.getFirst(EdgeHttp.UPSTREAM_SUBJECT);
            if (subject == null) {
                reply(ex, 401, "unauthorised");
                return;
            }
            String path = ex.getRequestURI().getPath().toLowerCase(Locale.ROOT);
            String override = h.getFirst("X-HTTP-Method-Override");
            String method = override != null ? override.toUpperCase(Locale.ROOT) : ex.getRequestMethod();
            record(method, path, subject, h);
            route(ex, method, path, subject);
        } catch (IOException | RuntimeException e) {
            // The gateway sees a dropped response and refuses; nothing else to do here.
        }
    }

    private void route(HttpExchange ex, String method, String path, String subject) throws IOException {
        Matcher m;
        if ((m = PAGE.matcher(path)).matches()) {
            String name = m.group(1);
            switch (method) {
                case "GET", "HEAD" -> {
                    String p = pages.get(name);
                    reply(ex, p == null ? 404 : 200, p == null ? "no such page" : p);
                }
                case "PUT", "POST" -> {
                    Optional<byte[]> body = readBody(ex);
                    if (body.isEmpty() || pages.size() >= MAX_PAGES && !pages.containsKey(name)) {
                        reply(ex, 413, "too large");
                        return;
                    }
                    pages.put(name, new String(body.get(), StandardCharsets.UTF_8));
                    reply(ex, 200, "saved by " + subject);
                }
                case "DELETE" -> reply(ex, pages.remove(name) == null ? 404 : 200, "deleted");
                default -> reply(ex, 405, "method not allowed");
            }
        } else if ((m = DOWNLOAD.matcher(path)).matches() && method.equals("GET")) {
            String p = pages.get(m.group(1));
            if (p == null) {
                reply(ex, 404, "no such file");
                return;
            }
            ex.getResponseHeaders().set("Content-Disposition", "attachment; filename=" + m.group(1) + ".txt");
            reply(ex, 200, p);
        } else if (path.equals("/wiki/admin/settings")) {
            if (method.equals("POST")) {
                Optional<byte[]> body = readBody(ex);
                if (body.isEmpty()) {
                    reply(ex, 413, "too large");
                    return;
                }
                settings = new String(body.get(), StandardCharsets.UTF_8);
                reply(ex, 200, "settings changed by " + subject);
            } else {
                reply(ex, 200, settings);
            }
        } else if ((m = GO.matcher(path)).matches() && method.equals("GET")) {
            ex.getResponseHeaders().set("Location", uri() + "/wiki/pages/" + m.group(1));
            reply(ex, 302, "moved");
        } else if ((m = SECRET.matcher(path)).matches() && method.equals("GET")) {
            reply(ex, 200, "secret " + m.group(1) + " for " + subject);
        } else {
            reply(ex, 404, "not found");
        }
    }

    private void record(String method, String path, String subject, Headers h) {
        Set<String> names = new TreeSet<>();
        for (String n : h.keySet()) {
            names.add(n.toLowerCase(Locale.ROOT));
        }
        synchronized (seenLock) {
            seen.addLast(new Seen(method, path, subject, names));
            while (seen.size() > KEEP_SEEN) {
                seen.removeFirst();
            }
        }
    }

    private static Optional<byte[]> readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            return ZtnaGateway.readBounded(in, MAX_PAGE);
        }
    }

    private static void reply(HttpExchange ex, int status, String text) throws IOException {
        byte[] b = text.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        boolean head = "HEAD".equals(ex.getRequestMethod()) || status == 204 || status == 304;
        ex.sendResponseHeaders(status, head ? -1 : b.length);
        if (!head) {
            try (OutputStream os = ex.getResponseBody()) {
                os.write(b);
            }
        }
    }

    /** For tests: the names of headers in {@code seen} that a client could have injected. */
    public static List<String> clientOnlyNames(Seen s) {
        List<String> out = new ArrayList<>();
        for (String n : s.headerNames()) {
            boolean ours = HeaderPolicy.normal(n).equals(HeaderPolicy.normal(EdgeHttp.UPSTREAM_SUBJECT))
                    || HeaderPolicy.normal(n).equals(HeaderPolicy.normal(EdgeHttp.UPSTREAM_SESSION))
                    || HeaderPolicy.normal(n).equals(HeaderPolicy.normal(ZtnaGateway.UPSTREAM_GATEWAY));
            if (EdgeHttp.clientOnly(n) && !ours) {
                out.add(n);
            }
        }
        return out;
    }
}

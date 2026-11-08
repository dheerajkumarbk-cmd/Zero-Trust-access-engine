package dev.dwarpal.console;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.guard.RateLimiter;
import dev.dwarpal.lab.LabRunner;
import dev.dwarpal.lab.LabWorld;
import dev.dwarpal.wire.JsonException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The console server (Layer 6 part G): HTTPS only (TLS 1.3 through {@link TlsContexts}, no client certificate because a
 * browser holds none), the static console from a fixed in-jar allow-list, and the JSON API of docs/layer-6/contract.md
 * section 3. JDK {@code HttpsServer}, no framework.
 *
 * <p>Every request takes the same steps and the first that fails answers; every answer, whatever its status, carries
 * the headers of {@link SecurityHeaders}:
 * <ol>
 *   <li>{@code Host} must be one of the server's own names (DNS rebinding): 421;</li>
 *   <li>method GET or POST only, no CORS at all: 405;</li>
 *   <li>the raw path must be plain (no percent-encoding, no {@code ..}, no semicolon or backslash): 404;</li>
 *   <li>static files: exact name in the allow-list, else 404; module files only for people who may see the module;</li>
 *   <li>API: route (404) and method (405); every POST needs {@code Origin} equal to the console's own origin, a
 *       cross-site fetch is refused, and the body must be {@code application/json} (415);</li>
 *   <li>session cookie: server-side lookup with idle and absolute timeout and the address/agent binding (401);</li>
 *   <li>CSRF token in {@code X-Dwarpal-CSRF} on every authenticated POST (403);</li>
 *   <li>role (403), rate limits (429), step-up freshness for privileged writes (403 "step-up required");</li>
 *   <li>body size (413) and strict JSON (400); a write is audited before it runs and after; a sensitive read is
 *       audited before its data is sent, and if the record cannot be written the data is not sent (503).</li>
 * </ol>
 */
public final class ConsoleServer implements AutoCloseable {

    public static final String COOKIE = "__Host-dwarpal";
    public static final String CSRF_HEADER = "X-Dwarpal-CSRF";
    public static final String BACKGROUND_HEADER = "X-Dwarpal-Background";
    static final String API = "/console/api/";

    enum Kind { PUBLIC, READ, SENSITIVE, WRITE }

    @FunctionalInterface
    interface RouteHandler {
        Reply handle(Ctx ctx) throws Exception;
    }

    record Route(String method, String pattern, String[] parts, Kind kind, ConsoleModule.Role minimum, boolean stepUp,
                 String moduleId, RouteHandler handler) {
    }

    /** The JDK server limits the number of request headers but not their size; this is the console's own bound. */
    static final int MAX_HEADER_BYTES = 16 * 1024;
    private static final int PAGE_FILES_FACTOR = 10;
    private static final Set<String> RESERVED = Set.of("session", "me", "modules", "stream", "soc", "audit", "profile", "home");
    /** What a person whose password or PIN has run out may still reach: enough to change them. */
    private static final Set<String> OPEN_WHILE_DUE = Set.of("me", "modules", "lab", "stream", "profile");

    final LabHandle lab;
    final SocChannel channel;
    final VerdictSigner signer;
    final ConsoleAuth auth;
    final ConsoleSettings settings;
    final Clock wall;
    final ConsoleSessions sessions;
    final ConsoleAudit audit;
    /** The saved audit trail (kept across restarts); null when this server writes into the lab's chain only. */
    final ConsoleTrail trail;
    /** A sensitive read repeated within a minute is one record with a count; an ordinary view, within five minutes. */
    private final ReadWindow sensitiveReads = new ReadWindow(Duration.ofSeconds(60), 10_000);
    private final ReadWindow views = new ReadWindow(Duration.ofMinutes(5), 10_000);
    final StreamHub hub;
    /** How long the passkey keeps confidential views open; null when this server has no passkey lock. */
    final Duration passkeyWindow;
    private final StaticFiles files;
    private final List<ConsoleModule> modules;
    private final List<Route> routes = new ArrayList<>();
    private final HttpsServer server;
    private final ThreadPoolExecutor workers;
    private final ScheduledThreadPoolExecutor watchdog;
    private final ScheduledExecutorService poller;
    private final Semaphore inFlight;
    private final RateLimiter anonymous;
    /** Page files: a fixed list, about 30 per page load, so their limit must allow several reloads a minute. */
    private final RateLimiter pageFiles;
    private final RateLimiter reads;
    private final RateLimiter writes;
    private final RateLimiter refusalAudits;
    final RateLimiter auditFailedLogins;
    final RateLimiter auditReads;
    final RateLimiter auditVerifies;
    private final AtomicLong internalFailures = new AtomicLong();
    private final AtomicLong timedOut = new AtomicLong();
    private final AtomicLong refused = new AtomicLong();
    private volatile Set<String> hosts = Set.of();
    private volatile Set<String> origins = Set.of();
    private long lastRaised;
    private long lastCases;
    private long lastIsolations;
    private int pollCount;

    private ConsoleServer(Builder b) throws IOException {
        this.lab = Objects.requireNonNull(b.lab, "lab");
        this.channel = Objects.requireNonNull(b.channel, "channel");
        this.signer = Objects.requireNonNull(b.signer, "signer");
        this.auth = Objects.requireNonNull(b.auth, "auth");
        this.settings = Objects.requireNonNull(b.settings, "settings");
        this.wall = Objects.requireNonNull(b.wall, "wall");
        this.files = StaticFiles.fromClasspath(b.staticRoot);
        this.modules = List.copyOf(b.modules);
        this.sessions = new ConsoleSessions(wall, settings);
        this.trail = b.trail;
        this.audit = new ConsoleAudit(() -> b.auditLog.get() != null ? b.auditLog.get() : lab.world().org.audit,
                () -> lab.world().org.clock, wall, b.trail != null);
        this.hub = new StreamHub(settings.maxStreams());
        this.passkeyWindow = b.passkeyWindow;
        this.inFlight = new Semaphore(settings.maxConcurrent());
        this.anonymous = new RateLimiter(settings.anonymousPerMinute(), Duration.ofMinutes(1), 10_000);
        this.pageFiles = new RateLimiter(settings.anonymousPerMinute() * PAGE_FILES_FACTOR, Duration.ofMinutes(1), 10_000);
        this.reads = new RateLimiter(settings.readsPerMinute(), Duration.ofMinutes(1), 1_000);
        this.writes = new RateLimiter(settings.writesPerMinute(), Duration.ofMinutes(1), 1_000);
        this.refusalAudits = new RateLimiter(20, Duration.ofMinutes(1), 5_000);
        this.auditFailedLogins = new RateLimiter(20, Duration.ofMinutes(1), 5_000);
        this.auditReads = new RateLimiter(60, Duration.ofMinutes(1), 1_000);
        this.auditVerifies = new RateLimiter(6, Duration.ofMinutes(1), 1_000);
        this.workers = new ThreadPoolExecutor(settings.threads(), settings.threads(), 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(settings.queue()), daemonThreads("dwarpal-console-"),
                new ThreadPoolExecutor.AbortPolicy());
        this.watchdog = new ScheduledThreadPoolExecutor(1, daemonThreads("dwarpal-console-watchdog-"));
        watchdog.setRemoveOnCancelPolicy(true);
        this.poller = Executors.newSingleThreadScheduledExecutor(daemonThreads("dwarpal-console-poller-"));
        ConsoleRoutes.register(this);
        for (ConsoleModule m : modules) {
            register(m);
        }
        SSLContext tls = Objects.requireNonNull(b.tls, "tls");
        this.server = HttpsServer.create(Objects.requireNonNull(b.address, "address"), 64);
        server.setHttpsConfigurator(new HttpsConfigurator(tls) {
            @Override
            public void configure(HttpsParameters p) {
                p.setSSLParameters(browserParameters(getSSLContext()));
            }
        });
        server.setExecutor(task -> workers.execute(withDeadline(task)));
        server.createContext("/", this::handle);
    }

    /** TLS 1.3, the strong suites of {@link TlsContexts}, and no client certificate: a browser holds none. */
    static SSLParameters browserParameters(SSLContext ctx) {
        SSLParameters p = ctx.getDefaultSSLParameters();
        p.setProtocols(TlsContexts.PROTOCOLS.toArray(String[]::new));
        p.setCipherSuites(TlsContexts.CIPHER_SUITES.toArray(String[]::new));
        p.setNeedClientAuth(false);
        p.setWantClientAuth(false);
        return p;
    }

    public static Builder builder(LabHandle lab, SocChannel channel, VerdictSigner signer, ConsoleAuth auth,
                                  SSLContext tls) {
        return new Builder(lab, channel, signer, auth, tls);
    }

    public ConsoleServer start() {
        server.start();
        int port = server.getAddress().getPort();
        Set<String> h = new LinkedHashSet<>(List.of("localhost:" + port, "127.0.0.1:" + port));
        h.addAll(settings.extraHosts());
        hosts = Set.copyOf(h);
        Set<String> o = new LinkedHashSet<>();
        h.forEach(x -> o.add("https://" + x));
        origins = Set.copyOf(o);
        lastRaised = world().raised.size();
        poller.scheduleWithFixedDelay(this::poll, 1, 1, TimeUnit.SECONDS);
        return this;
    }

    LabWorld world() {
        return lab.world();
    }

    LabRunner runner() {
        return lab.runner();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public String url() {
        return "https://localhost:" + port() + "/";
    }

    @Override
    public void close() {
        poller.shutdownNow();
        hub.close();
        server.stop(0);
        workers.shutdownNow();
        watchdog.shutdownNow();
    }

    public long internalFailures() {
        return internalFailures.get();
    }

    public long auditFailures() {
        return audit.failures();
    }

    public long timedOut() {
        return timedOut.get();
    }

    public int openStreams() {
        return hub.open();
    }

    public int sessionCount() {
        return sessions.size();
    }

    // ---- routes -----------------------------------------------------------------------------------------------

    void route(String method, String pattern, Kind kind, ConsoleModule.Role minimum, boolean stepUp, RouteHandler h) {
        routes.add(new Route(method, pattern, pattern.split("/", -1), kind, minimum, stepUp, null, h));
    }

    private void register(ConsoleModule m) {
        String id = m.id();
        if (id == null || !id.matches("[a-z][a-z0-9-]{1,31}") || RESERVED.contains(id)) {
            throw new IllegalArgumentException("module id is not allowed: " + id);
        }
        if (routes.stream().anyMatch(r -> id.equals(r.moduleId()))) {
            throw new IllegalArgumentException("two modules with the id " + id);
        }
        m.routes(new ConsoleModule.Routes() {
            @Override
            public void get(String pattern, ConsoleModule.Role minimum, ConsoleModule.Handler handler) {
                add("GET", pattern, Kind.READ, minimum, false, handler);
            }

            @Override
            public void post(String pattern, ConsoleModule.Role minimum, boolean needsStepUp, ConsoleModule.Handler handler) {
                add("POST", pattern, Kind.WRITE, minimum, needsStepUp, handler);
            }

            private void add(String method, String pattern, Kind kind, ConsoleModule.Role minimum, boolean stepUp,
                             ConsoleModule.Handler handler) {
                String full = id + "/" + pattern;
                for (String seg : pattern.split("/", -1)) {
                    if (!seg.equals("{}") && !ConsoleIds.isPlain(seg)) {
                        throw new IllegalArgumentException("module route segment is not allowed");
                    }
                }
                routes.add(new Route(method, full, full.split("/", -1), kind, Objects.requireNonNull(minimum, "minimum"),
                        stepUp, id, ctx -> moduleCall(m, method, ctx, handler)));
            }
        });
    }

    private Reply moduleCall(ConsoleModule m, String method, Ctx ctx, ConsoleModule.Handler handler) throws Exception {
        ConsoleModule.Principal who = principal(ctx.session);
        ConsoleModule.Request req = new ConsoleModule.Request(who, method, ctx.exchange.getRequestURI().getRawPath(),
                ctx.query, Ctx.utf8(ctx.body));
        ConsoleModule.Response r = handler.handle(req, ctx.params);
        if (r == null || r.body() == null || r.status() < 200 || r.status() > 599) {
            internalFailures.incrementAndGet();
            return Reply.error(503, "unavailable");
        }
        return Reply.rawJson(r.status(), r.body()).audited("module " + m.id());
    }

    ConsoleModule.Principal principal(ConsoleSessions.Session s) {
        return new ConsoleModule.Principal(s.person.id(), s.person.roles(), sessions.stepUpFresh(s));
    }

    List<ConsoleModule> modules() {
        return modules;
    }

    /**
     * The meaning of a module's {@code minimum}: hierarchical, ANALYST below LEAD below ADMIN, and USER (any signed-in
     * person) separate and lowest. Built-in SOC and audit routes use {@link #satisfies} instead, which keeps an
     * administrator out of SOC data.
     */
    static boolean satisfiesModule(Set<ConsoleModule.Role> roles, ConsoleModule.Role minimum) {
        return switch (minimum) {
            case USER -> !roles.isEmpty();
            case ANALYST -> roles.contains(ConsoleModule.Role.ANALYST) || roles.contains(ConsoleModule.Role.LEAD)
                    || roles.contains(ConsoleModule.Role.ADMIN);
            case LEAD -> roles.contains(ConsoleModule.Role.LEAD) || roles.contains(ConsoleModule.Role.ADMIN);
            case ADMIN -> roles.contains(ConsoleModule.Role.ADMIN);
            case HR -> roles.contains(ConsoleModule.Role.HR);
        };
    }

    /** A role is met by itself; a lead is also an analyst; an administrator and every other person are users. */
    static boolean satisfies(Set<ConsoleModule.Role> roles, ConsoleModule.Role minimum) {
        return switch (minimum) {
            case USER -> !roles.isEmpty();
            case ANALYST -> roles.contains(ConsoleModule.Role.ANALYST) || roles.contains(ConsoleModule.Role.LEAD);
            case LEAD -> roles.contains(ConsoleModule.Role.LEAD);
            case ADMIN -> roles.contains(ConsoleModule.Role.ADMIN);
            case HR -> roles.contains(ConsoleModule.Role.HR);
        };
    }

    // ---- the request pipeline ---------------------------------------------------------------------------------

    private void handle(HttpExchange ex) {
        boolean handed = false;
        try {
            Reply r;
            try {
                r = process(ex);
            } catch (JsonException | IllegalArgumentException | ArithmeticException bad) {
                r = Reply.error(400, "invalid request");
            } catch (Exception e) {
                internalFailures.incrementAndGet();
                r = Reply.error(503, "unavailable");
            }
            if (r.handled()) {
                handed = true;
                return;
            }
            send(ex, r);
        } catch (IOException | RuntimeException e) {
            // the connection broke while answering; nobody is left to answer
        } finally {
            if (!handed) {
                ex.close();
            }
        }
    }

    private Reply process(HttpExchange ex) throws Exception {
        Headers in = ex.getRequestHeaders();
        if (headerBytes(in) > MAX_HEADER_BYTES) {
            return Reply.error(431, "request header fields too large");
        }
        String host = in.getFirst("Host");
        if (host == null || !hosts.contains(host.toLowerCase(Locale.ROOT))) {
            return Reply.error(421, "misdirected request");
        }
        String method = ex.getRequestMethod();
        if (!method.equals("GET") && !method.equals("POST")) {
            return Reply.error(405, "method not allowed").withHeader("Allow", "GET, POST");
        }
        String rawPath = ex.getRequestURI().getRawPath();
        if (rawPath == null || rawPath.length() > 300 || rawPath.indexOf('%') >= 0 || rawPath.indexOf('\\') >= 0
                || rawPath.indexOf(';') >= 0 || rawPath.contains("..") || rawPath.contains("//") || !rawPath.startsWith("/")) {
            return Reply.error(404, "not found");
        }
        String source = clientAddress(ex);
        String agent = in.getFirst("User-Agent");
        if (rawPath.equals("/console/api") || rawPath.startsWith(API)) {
            return api(ex, method, rawPath, source, agent);
        }
        return staticFile(ex, method, rawPath, source, agent);
    }

    // ---- static files -----------------------------------------------------------------------------------------

    private static long headerBytes(Headers h) {
        long total = 0;
        for (Map.Entry<String, List<String>> e : h.entrySet()) {
            total += e.getKey().length();
            for (String v : e.getValue()) {
                total += v.length();
            }
        }
        return total;
    }

    private Reply staticFile(HttpExchange ex, String method, String rawPath, String source, String agent) {
        if (!method.equals("GET")) {
            return Reply.error(405, "method not allowed").withHeader("Allow", "GET");
        }
        if (!pageFiles.tryAcquire("static|" + source, wall.instant())) {
            refused.incrementAndGet();
            return Reply.error(429, "too many requests").withHeader("Retry-After", "60");
        }
        String rel;
        if (rawPath.equals("/") || rawPath.equals("/console") || rawPath.equals("/console/")) {
            rel = "index.html";
        } else if (rawPath.startsWith("/console/")) {
            rel = rawPath.substring("/console/".length());
        } else {
            return Reply.error(404, "not found");
        }
        if (!StaticFiles.safeName(rel)) {
            return Reply.error(404, "not found");
        }
        String[] seg = rel.split("/", -1);
        if (seg[0].equals("modules")) {
            // files of a module go only to people who may see that module
            Optional<ConsoleModule> m = seg.length > 2 ? modules.stream().filter(x -> x.id().equals(seg[1])).findFirst()
                    : Optional.empty();
            if (m.isEmpty()) {
                return Reply.error(404, "not found");
            }
            ConsoleSessions.Found f = sessions.find(cookie(ex), source, agent);
            if (f.lookup() != ConsoleSessions.Lookup.OK || !satisfiesModule(f.session().person.roles(), m.get().minimum())) {
                return Reply.error(f.lookup() == ConsoleSessions.Lookup.OK ? 403 : 401,
                        f.lookup() == ConsoleSessions.Lookup.OK ? "forbidden" : "login required");
            }
        }
        Optional<StaticFiles.Asset> a = files.get(rel);
        if (a.isEmpty()) {
            return Reply.error(404, "not found");
        }
        String tag = ex.getRequestHeaders().getFirst("If-None-Match");
        Reply r = tag != null && tag.equals(a.get().etag())
                ? new Reply(304, new byte[0], a.get().contentType(), "", List.of(), Map.of(), false)
                : new Reply(200, a.get().bytes(), a.get().contentType(), "", List.of(), Map.of(), false);
        // no build step means no hashed file names, so: always revalidate (ETag), never trust a stale copy
        return r.withHeader("ETag", a.get().etag()).withHeader("Cache-Control", "no-cache");
    }

    // ---- the API ----------------------------------------------------------------------------------------------

    private Reply api(HttpExchange ex, String method, String rawPath, String source, String agent) throws Exception {
        String rest = rawPath.length() <= API.length() ? "" : rawPath.substring(API.length());
        String[] got = rest.split("/", -1);
        Route route = null;
        List<String> params = List.of();
        boolean pathMatched = false;
        for (Route r : routes) {
            Optional<List<String>> p = match(r.parts(), got);
            if (p.isPresent()) {
                pathMatched = true;
                if (r.method().equals(method)) {
                    route = r;
                    params = p.get();
                    break;
                }
            }
        }
        if (route == null) {
            return pathMatched ? Reply.error(405, "method not allowed") : Reply.error(404, "not found");
        }
        Map<String, String> query = query(ex.getRequestURI().getRawQuery());
        // ---- every POST: where it came from, and what it is
        if (method.equals("POST")) {
            String origin = ex.getRequestHeaders().getFirst("Origin");
            if (origin == null || !origins.contains(origin.toLowerCase(Locale.ROOT))) {
                return audited403(null, "origin", route, "Origin missing or not the console's own");
            }
            String site = ex.getRequestHeaders().getFirst("Sec-Fetch-Site");
            if (site != null && !site.equals("same-origin") && !site.equals("none")) {
                return audited403(null, "fetch-site", route, "cross-site fetch");
            }
            if (!jsonContent(ex.getRequestHeaders().getFirst("Content-Type"))) {
                return Reply.error(415, "unsupported media type");
            }
        }
        // ---- who
        ConsoleSessions.Session session = null;
        Reply cookieClear = null;
        if (route.kind() != Kind.PUBLIC) {
            ConsoleSessions.Found f = sessions.find(cookie(ex), source, agent);
            switch (f.lookup()) {
                case OK -> session = f.session();
                case EXPIRED -> {
                    audit.write("CONSOLE_SESSION_ENDED", f.session().person.id(), fields("session", f.session().tag(),
                            "reason", "timeout"));
                    hub.closeSession(f.session().id);
                    cookieClear = Reply.error(401, "login required").withCookie(clearCookie());
                }
                case BOUND_ELSEWHERE -> {
                    audit.write("CONSOLE_SESSION_REFUSED", f.session().person.id(), fields("session", f.session().tag(),
                            "reason", "cookie used from another address or browser"));
                    hub.closeSession(f.session().id);
                    cookieClear = Reply.error(401, "login required").withCookie(clearCookie());
                }
                case NONE -> {
                }
            }
        }
        if (route.kind() != Kind.PUBLIC && session == null) {
            return cookieClear != null ? cookieClear : Reply.error(401, "login required");
        }
        // ---- limits
        if (session == null) {
            if (!anonymous.tryAcquire("api|" + source, wall.instant())) {
                refused.incrementAndGet();
                return Reply.error(429, "too many requests").withHeader("Retry-After", "60");
            }
        } else {
            boolean ok = route.kind() == Kind.WRITE
                    ? writes.tryAcquire(session.person.id(), wall.instant()) : reads.tryAcquire(session.person.id(), wall.instant());
            if (!ok) {
                refused.incrementAndGet();
                return Reply.error(429, "too many requests").withHeader("Retry-After", "60");
            }
        }
        // ---- CSRF, role, step-up
        if (method.equals("POST") && session != null) {
            String token = ex.getRequestHeaders().getFirst(CSRF_HEADER);
            if (token == null || !MessageDigest.isEqual(token.getBytes(StandardCharsets.UTF_8),
                    session.csrf.getBytes(StandardCharsets.UTF_8))) {
                return audited403(session, "csrf", route, "anti-forgery token missing or wrong");
            }
        }
        if (route.minimum() != null && !(route.moduleId() != null ? satisfiesModule(session.person.roles(), route.minimum())
                : satisfies(session.person.roles(), route.minimum()))) {
            return audited403(session, "role", route, "needs " + route.minimum());
        }
        if (route.stepUp() && !sessions.stepUpFresh(session)) {
            if (refusalAudits.tryAcquire("stepup|" + session.person.id(), wall.instant())) {
                audit.write("CONSOLE_REFUSED", session.person.id(), fields("session", session.tag(), "route", route.pattern(),
                        "why", "step-up not fresh"));
            }
            return Reply.error(403, "step-up required");
        }
        if (session != null && auth.changeDue(session.person.id()) && !route.pattern().startsWith("session/")
                && !route.pattern().startsWith("profile/") && !OPEN_WHILE_DUE.contains(route.pattern())) {
            return Reply.error(428, "change your password and PIN first");
        }
        if (passkeyWindow != null && ConsoleRoutes.CONFIDENTIAL.contains(route.pattern())) {
            if (!sessions.unlocked(session)) {
                if (refusalAudits.tryAcquire("passkey|" + session.person.id(), wall.instant())) {
                    audit.write("CONSOLE_REFUSED", session.person.id(), fields("session", session.tag(), "route",
                            route.pattern(), "why", "passkey not given"));
                }
                return Reply.error(423, "passkey required");
            }
            // a page left open refreshes itself in the background; only something the person did keeps it unlocked
            if (!"1".equals(ex.getRequestHeaders().getFirst(BACKGROUND_HEADER))) {
                sessions.unlock(session, passkeyWindow);
            }
        }
        if (!inFlight.tryAcquire()) {
            return Reply.error(503, "busy");
        }
        try {
            byte[] body = new byte[0];
            if (method.equals("POST")) {
                Optional<byte[]> read = readBody(ex);
                if (read.isEmpty()) {
                    return Reply.error(413, "request too large");
                }
                body = read.get();
            }
            Ctx ctx = new Ctx(ex, session, source, agent, query, body, params);
            return run(route, ctx, session);
        } finally {
            inFlight.release();
        }
    }

    private Reply run(Route route, Ctx ctx, ConsoleSessions.Session session) throws Exception {
        String person = session == null ? null : session.person.id();
        String tag = session == null ? "" : session.tag();
        String object = String.join("/", ctx.params);
        if (route.kind() == Kind.WRITE && session != null) {
            // the record of intent comes first: if the trail cannot take it, the write does not happen
            if (!audit.write("CONSOLE_WRITE", person, fields("session", tag, "route", route.pattern(), "object", object,
                    "phase", "attempt"))) {
                return Reply.error(503, "audit trail unavailable");
            }
        }
        Reply r;
        try {
            r = route.handler().handle(ctx);
        } catch (JsonException | IllegalArgumentException | ArithmeticException bad) {
            r = Reply.error(400, "invalid request").audited("rejected input");
        }
        boolean background = "1".equals(ctx.exchange.getRequestHeaders().getFirst(BACKGROUND_HEADER))
                && ctx.exchange.getRequestMethod().equals("GET");
        if (session != null && !background) {
            sessions.touch(session);
        }
        if (r.handled()) {
            return r;
        }
        if (route.kind() == Kind.WRITE && session != null) {
            audit.write("CONSOLE_WRITE", person, fields("session", tag, "route", route.pattern(), "object", object, "phase",
                    "result", "status", Integer.toString(r.status()), "detail", r.audit()));
        } else if (route.kind() == Kind.SENSITIVE && session != null) {
            // a page left open that refreshes itself is not somebody reading again; a person reading the same thing
            // twice within a minute is one record that says "twice"
            boolean throttled = r.status() != 200 && !refusalAudits.tryAcquire("read|" + person + "|" + r.status(),
                    wall.instant());
            if (!throttled && !background) {
                String key = person + "|" + tag + "|" + route.pattern() + "|" + object + "|" + r.status();
                ReadWindow.Decision d = sensitiveReads.see(key, wall.instant());
                if (d.record()) {
                    Map<String, String> f = fields("session", tag, "route", route.pattern(), "object", object, "status",
                            Integer.toString(r.status()), "detail", r.audit());
                    if (d.repeats() > 0) {
                        f.put("repeats", Integer.toString(d.repeats()));
                    }
                    if (!audit.write("CONSOLE_READ", person, f)) {
                        sensitiveReads.undo(key);
                        return Reply.error(503, "audit trail unavailable");
                    }
                }
            }
        } else if (route.kind() == Kind.READ && route.minimum() != null && session != null && !background
                && ctx.exchange.getRequestMethod().equals("GET") && r.status() == 200) {
            // an ordinary view of a working page (not the person's own account pages): the first one per window
            String key = person + "|" + tag + "|" + route.pattern();
            ReadWindow.Decision d = views.see(key, wall.instant());
            if (d.record()) {
                Map<String, String> f = fields("session", tag, "route", route.pattern());
                if (d.repeats() > 0) {
                    f.put("repeats", Integer.toString(d.repeats()));
                }
                if (!audit.write("CONSOLE_VIEW", person, f)) {
                    views.undo(key);
                }
            }
        }
        return r;
    }

    private Reply audited403(ConsoleSessions.Session s, String why, Route route, String detail) {
        if (refusalAudits.tryAcquire("403|" + why + "|" + (s == null ? "-" : s.person.id()), wall.instant())) {
            audit.write("CONSOLE_REFUSED", s == null ? null : s.person.id(), fields("session", s == null ? "" : s.tag(),
                    "route", route.pattern(), "why", detail));
        }
        return Reply.error(403, "forbidden");
    }

    static Map<String, String> fields(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put(kv[i], kv[i + 1]);
        }
        return m;
    }

    private static Optional<List<String>> match(String[] pattern, String[] got) {
        if (pattern.length != got.length) {
            return Optional.empty();
        }
        List<String> params = new ArrayList<>();
        for (int i = 0; i < pattern.length; i++) {
            if (pattern[i].equals("{}")) {
                if (!ConsoleIds.isPlain(got[i])) {
                    return Optional.empty();
                }
                params.add(got[i]);
            } else if (!pattern[i].equals(got[i])) {
                return Optional.empty();
            }
        }
        return Optional.of(List.copyOf(params));
    }

    /** {@code a=b&c=d} with plain characters only: no percent-encoding, at most 8 pairs. Anything else is an error. */
    static Map<String, String> query(String raw) {
        if (raw == null || raw.isEmpty()) {
            return Map.of();
        }
        if (raw.length() > 300 || raw.indexOf('%') >= 0 || raw.indexOf('+') >= 0) {
            throw new IllegalArgumentException("query");
        }
        Map<String, String> q = new LinkedHashMap<>();
        for (String pair : raw.split("&", -1)) {
            int eq = pair.indexOf('=');
            if (eq < 1 || q.size() >= 8) {
                throw new IllegalArgumentException("query");
            }
            String k = pair.substring(0, eq);
            String v = pair.substring(eq + 1);
            if (!ConsoleIds.isPlain(k) || (!v.isEmpty() && !ConsoleIds.isPlain(v)) || q.putIfAbsent(k, v) != null) {
                throw new IllegalArgumentException("query");
            }
        }
        return Map.copyOf(q);
    }

    private static boolean jsonContent(String contentType) {
        if (contentType == null) {
            return false;
        }
        String t = contentType.strip().toLowerCase(Locale.ROOT).replace(" ", "");
        return t.equals("application/json") || t.equals("application/json;charset=utf-8");
    }

    private Optional<byte[]> readBody(HttpExchange ex) throws IOException {
        int max = settings.maxBodyBytes();
        String declared = ex.getRequestHeaders().getFirst("Content-Length");
        if (declared != null) {
            try {
                if (Long.parseLong(declared.strip()) > max) {
                    return Optional.empty();
                }
            } catch (NumberFormatException e) {
                throw new JsonException("bad content length");
            }
        }
        try (InputStream in = ex.getRequestBody()) {
            byte[] bytes = in.readNBytes(max + 1);
            return bytes.length > max ? Optional.empty() : Optional.of(bytes);
        }
    }

    /** The one session cookie's value, if there is exactly one such cookie and it looks like an identifier. */
    static String cookie(HttpExchange ex) {
        List<String> headers = ex.getRequestHeaders().get("Cookie");
        if (headers == null) {
            return null;
        }
        String found = null;
        for (String h : headers) {
            for (String part : h.split(";")) {
                String p = part.strip();
                if (p.startsWith(COOKIE + "=")) {
                    if (found != null) {
                        return null;
                    }
                    found = p.substring(COOKIE.length() + 1);
                }
            }
        }
        return found != null && found.matches("[A-Za-z0-9_-]{43}") ? found : null;
    }

    static String sessionCookie(String id) {
        return COOKIE + "=" + id + "; Secure; HttpOnly; SameSite=Strict; Path=/";
    }

    static String clearCookie() {
        return COOKIE + "=; Max-Age=0; Secure; HttpOnly; SameSite=Strict; Path=/";
    }

    /** The peer's address as an identifier (an IPv6 zone is cut off). */
    static String clientAddress(HttpExchange ex) {
        String a = ex.getRemoteAddress().getAddress().getHostAddress();
        int zone = a.indexOf('%');
        return zone < 0 ? a : a.substring(0, zone);
    }

    // ---- sending ----------------------------------------------------------------------------------------------

    private static void send(HttpExchange ex, Reply r) throws IOException {
        Headers h = ex.getResponseHeaders();
        SecurityHeaders.apply(h);
        h.set("Content-Type", r.contentType());
        if (!r.headers().containsKey("Cache-Control")) {
            h.set("Cache-Control", "no-store");
        }
        r.headers().forEach(h::set);
        for (String c : r.cookies()) {
            h.add("Set-Cookie", c);
        }
        boolean noBody = r.status() == 304 || ex.getRequestMethod().equals("HEAD");
        if (noBody) {
            ex.sendResponseHeaders(r.status(), -1);
            return;
        }
        if (r.status() == 413) {
            // the body was left unread, so this connection cannot carry another request: say so, or the caller reuses it and hangs
            ex.getResponseHeaders().set("Connection", "close");
        }
        ex.sendResponseHeaders(r.status(), r.body().length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(r.body());
        }
    }

    /** Opens the event stream on the exchange; false when the server's stream limit is reached. */
    boolean openStream(HttpExchange ex, String sessionId) throws IOException {
        if (hub.open() >= settings.maxStreams() && !hub.sessions().contains(sessionId)) {
            return false;
        }
        Headers h = ex.getResponseHeaders();
        SecurityHeaders.apply(h);
        h.set("Content-Type", "text/event-stream; charset=utf-8");
        h.set("Cache-Control", "no-store");
        h.set("X-Accel-Buffering", "no");
        ex.sendResponseHeaders(200, 0);
        if (!hub.open(sessionId, ex.getResponseBody())) {
            ex.close();
        }
        return true;
    }

    // ---- the live feed ----------------------------------------------------------------------------------------

    private void poll() {
        try {
            hub.closeWhere(id -> !sessions.valid(id));
            if (hub.open() == 0) {
                lastRaised = world().raised.size();
                return;
            }
            hub.publish("lab.tick", ConsoleRoutes.labJson(this, false), id -> true);
            int raisedNow = world().raised.size();
            if (raisedNow != lastRaised) {
                lastRaised = raisedNow;
                hub.publish("alert.new", "{}", id -> true);
            }
            if (pollCount++ % 2 == 0) {
                long cases = 17;
                for (var c : world().cases.all()) {
                    cases = cases * 31 + Objects.hash(c.id(), c.state(), c.assignee(), c.alerts().size(), c.notes().size(),
                            c.timeline().size(), c.priority(), c.holdsActions());
                }
                if (cases != lastCases) {
                    lastCases = cases;
                    hub.publish("case.changed", "{}", id -> true);
                }
                long iso = 19;
                for (var i : world().isolation.all()) {
                    iso = iso * 31 + Objects.hash(i.deviceId(), i.state(), i.delivered(), i.overdue());
                }
                if (iso != lastIsolations) {
                    lastIsolations = iso;
                    hub.publish("isolation.changed", "{}", id -> true);
                }
            }
        } catch (RuntimeException e) {
            internalFailures.incrementAndGet();
        }
    }

    // ---- plumbing ---------------------------------------------------------------------------------------------

    private Runnable withDeadline(Runnable task) {
        return () -> {
            Deadline d = new Deadline(Thread.currentThread());
            ScheduledFuture<?> alarm;
            try {
                alarm = watchdog.schedule(d::expire, settings.requestDeadline().toMillis(), TimeUnit.MILLISECONDS);
            } catch (RejectedExecutionException stopping) {
                return;
            }
            try {
                task.run();
            } finally {
                alarm.cancel(false);
                if (d.finish()) {
                    timedOut.incrementAndGet();
                }
                Thread.interrupted();
            }
        };
    }

    /** One task's deadline: interrupts its worker only while that task still runs on it. */
    private static final class Deadline {
        private final Thread worker;
        private boolean running = true;
        private boolean expired;

        Deadline(Thread worker) {
            this.worker = worker;
        }

        synchronized void expire() {
            if (running) {
                expired = true;
                worker.interrupt();
            }
        }

        synchronized boolean finish() {
            running = false;
            return expired;
        }
    }

    private static ThreadFactory daemonThreads(String prefix) {
        AtomicInteger n = new AtomicInteger();
        return r -> {
            Thread t = new Thread(r, prefix + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }

    public static final class Builder {
        private final LabHandle lab;
        private final SocChannel channel;
        private final VerdictSigner signer;
        private final ConsoleAuth auth;
        private final SSLContext tls;
        private final java.util.concurrent.atomic.AtomicReference<dev.dwarpal.audit.AuditLog> auditLog = new java.util.concurrent.atomic.AtomicReference<>();
        private ConsoleTrail trail;
        private ConsoleSettings settings = ConsoleSettings.defaults();
        private Clock wall = Clock.systemUTC();
        private InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), 8443);
        private String staticRoot = "console";
        private final List<ConsoleModule> modules = new ArrayList<>();
        private Duration passkeyWindow;

        private Builder(LabHandle lab, SocChannel channel, VerdictSigner signer, ConsoleAuth auth, SSLContext tls) {
            this.lab = lab;
            this.channel = channel;
            this.signer = signer;
            this.auth = auth;
            this.tls = tls;
        }

        /** Where the console writes its records (default: the lab's chain); tests pass a log whose sink can fail. */
        public Builder auditLog(dev.dwarpal.audit.AuditLog v) {
            auditLog.set(v);
            return this;
        }

        /**
         * Writes the console's records into this saved trail (real time, kept across restarts) instead of the lab's
         * chain, and lets the audit explorer read it as its second source.
         */
        public Builder trail(ConsoleTrail v) {
            trail = Objects.requireNonNull(v, "trail");
            auditLog.set(v.log());
            return this;
        }

        /** Confidential views need the person's passkey, and stay open this long after it. */
        public Builder passkeyLock(Duration window) {
            passkeyWindow = Objects.requireNonNull(window, "window");
            return this;
        }

        public Builder settings(ConsoleSettings v) {
            settings = v;
            return this;
        }

        /** The clock for sessions and step-up; scenario time is a different thing (the audit uses that). */
        public Builder wallClock(Clock v) {
            wall = v;
            return this;
        }

        /** Loopback by default; anything else is the owner's decision (docs/runbooks). */
        public Builder address(InetSocketAddress v) {
            address = v;
            return this;
        }

        public Builder staticRoot(String classpathDirectory) {
            staticRoot = classpathDirectory;
            return this;
        }

        public Builder module(ConsoleModule m) {
            modules.add(m);
            return this;
        }

        public ConsoleServer build() throws IOException {
            return new ConsoleServer(this);
        }
    }
}

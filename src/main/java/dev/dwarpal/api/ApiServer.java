package dev.dwarpal.api;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.SessionAuthority;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.edge.WireFormat;
import dev.dwarpal.guard.RateLimiter;
import dev.dwarpal.pam.PrivilegedAccessManager;
import dev.dwarpal.session.PolicyAdministrator;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Duration;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The engine API: Layers 1 to 3 behind HTTPS with mutual TLS 1.3, for enforcement points and
 * administrative tools. Built on the JDK's {@code HttpsServer}; no framework.
 *
 * <p>Every request goes through the same steps, in this order, and the first that fails answers:
 * <ol>
 *   <li><b>Who is calling:</b> the subject of the verified client certificate, compared exactly with
 *       the configured callers. Unknown: 403. (TLS has already refused anyone without a certificate
 *       from the Dwarpal CA.)</li>
 *   <li><b>Per-caller rate limit:</b> 429.</li>
 *   <li><b>Route:</b> the raw path must equal an endpoint path exactly (no prefixes, no query): 404.</li>
 *   <li><b>Role:</b> the caller's role must be one the endpoint serves: 403. Method: 405.</li>
 *   <li><b>Capacity:</b> at most N requests in flight: 503.</li>
 *   <li><b>Body:</b> {@code application/json}, at most 64 KiB, strict JSON and strict schema: 415, 413, 400.</li>
 *   <li><b>Work:</b> the engine, the Policy Administrator or PAM answers.</li>
 * </ol>
 * Error bodies are generic ({@code {"error":"invalid request"}}); the detail goes only to the audit
 * trail. Any unexpected exception is a 403 deny, never a 500 with a stack trace. Every call is audited
 * (caller, endpoint, status, result); refusals are throttled per caller and status so a flood cannot
 * flood the trail. An allowed answer whose audit record cannot be written is not sent: no audit, no access.
 */
public final class ApiServer implements AutoCloseable {

    public static final String ACTOR = "engine-api";

    /** The v1 endpoints and who may call each. */
    public enum Endpoint {
        OPEN("POST", "/v1/sessions", EnumSet.of(CallerRole.PEP)),
        USE("POST", "/v1/sessions/use", EnumSet.of(CallerRole.PEP)),
        DECIDE("POST", "/v1/decisions", EnumSet.of(CallerRole.PEP)),
        REVOKE("POST", "/v1/sessions/revoke", EnumSet.of(CallerRole.SOC, CallerRole.ADMIN_CONSOLE)),
        PAM_REQUEST("POST", "/v1/pam/requests", EnumSet.of(CallerRole.ADMIN_CONSOLE)),
        PAM_APPROVAL("POST", "/v1/pam/approvals", EnumSet.of(CallerRole.ADMIN_CONSOLE)),
        PAM_BREAK_GLASS("POST", "/v1/pam/break-glass", EnumSet.of(CallerRole.ADMIN_CONSOLE)),
        PAM_REVIEW("POST", "/v1/pam/reviews", EnumSet.of(CallerRole.ADMIN_CONSOLE)),
        HEALTH("GET", "/v1/health", EnumSet.allOf(CallerRole.class));

        private final String method;
        private final String path;
        private final Set<CallerRole> roles;

        Endpoint(String method, String path, Set<CallerRole> roles) {
            this.method = method;
            this.path = path;
            this.roles = roles;
        }

        public String method() {
            return method;
        }

        public String path() {
            return path;
        }

        public boolean serves(CallerRole role) {
            return roles.contains(role);
        }

        static Optional<Endpoint> of(String rawPath) {
            for (Endpoint e : values()) {
                if (e.path.equals(rawPath)) {
                    return Optional.of(e);
                }
            }
            return Optional.empty();
        }
    }

    /** One answer: what is sent, and what is audited about it. */
    private record Answer(int status, JsonValue body, String result, Optional<String> reference, String detail,
                          boolean allowed) {
        static Answer refuse(int status, String publicText, String detail) {
            return new Answer(status, ApiBodies.error(publicText), "refused", Optional.empty(), detail, false);
        }
    }

    private final HttpsServer server;
    private final ThreadPoolExecutor workers;
    private final ScheduledThreadPoolExecutor watchdog;
    private final AtomicLong timedOut = new AtomicLong();
    private final SessionAuthority authority;
    private final PolicyAdministrator administrator;
    private final PrivilegedAccessManager pam;
    private final AuditLog audit;
    private final Clock clock;
    private final ApiSettings settings;
    /** Keyed by the RFC 2253 form of the subject: compared exactly, not canonically (finding A5). */
    private final Map<String, Caller> callers;
    private final JsonReader json;
    private final Semaphore inFlight;
    private final RateLimiter callerLimit;
    private final RateLimiter refusalAudits;
    private final AtomicLong internalFailures = new AtomicLong();
    private final AtomicLong auditFailures = new AtomicLong();

    private ApiServer(Builder b) throws IOException {
        this.authority = Objects.requireNonNull(b.authority, "authority");
        this.administrator = Objects.requireNonNull(b.administrator, "administrator");
        this.pam = Objects.requireNonNull(b.pam, "pam");
        this.audit = Objects.requireNonNull(b.audit, "audit");
        this.clock = Objects.requireNonNull(b.clock, "clock");
        this.settings = Objects.requireNonNull(b.settings, "settings");
        SSLContext tls = Objects.requireNonNull(b.tls, "tls");
        Map<String, Caller> byPrincipal = new LinkedHashMap<>();
        for (Caller c : Objects.requireNonNull(b.callers, "callers")) {
            if (byPrincipal.putIfAbsent(c.subject(), c) != null) {
                throw new IllegalArgumentException("two callers with the same certificate subject");
            }
        }
        if (byPrincipal.isEmpty()) {
            throw new IllegalArgumentException("no callers configured");
        }
        this.callers = Map.copyOf(byPrincipal);
        JsonLimits d = JsonLimits.defaults();
        this.json = new JsonReader(new JsonLimits(settings.maxBodyBytes(), d.maxDepth(), d.maxStringChars(),
                d.maxMembers(), d.maxElements(), d.maxNumberChars(), d.maxValues()));
        this.inFlight = new Semaphore(settings.maxConcurrent());
        this.callerLimit = new RateLimiter(settings.callerLimit(), settings.callerWindow(), 10_000);
        this.refusalAudits = new RateLimiter(settings.refusalAuditsPerMinute(), Duration.ofMinutes(1), 10_000);
        this.workers = new ThreadPoolExecutor(settings.threads(), settings.threads(), 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(settings.queue()), daemonThreads("dwarpal-api-"),
                new ThreadPoolExecutor.AbortPolicy());
        this.server = HttpsServer.create(Objects.requireNonNull(b.address, "address"), 128);
        server.setHttpsConfigurator(new HttpsConfigurator(tls) {
            @Override
            public void configure(HttpsParameters p) {
                p.setSSLParameters(TlsContexts.serverParameters(getSSLContext()));
            }
        });
        this.watchdog = new ScheduledThreadPoolExecutor(1, daemonThreads("dwarpal-api-watchdog-"));
        watchdog.setRemoveOnCancelPolicy(true);
        server.setExecutor(task -> workers.execute(withDeadline(task)));
        server.createContext("/", this::handle);
    }

    /** The audit trail and privileged access are not optional: no audit, no answer. */
    public static Builder builder(AuditLog audit, PrivilegedAccessManager pam) {
        return new Builder(audit, pam);
    }

    /** Starts serving; returns this server. */
    public ApiServer start() {
        server.start();
        return this;
    }

    /** The bound port (useful when the builder asked for port 0). */
    public int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
        workers.shutdownNow();
        watchdog.shutdownNow();
    }

    /** Requests answered 403 because something failed inside (each is a bug or an outage to look at). */
    public long internalFailures() {
        return internalFailures.get();
    }

    /** API audit records that could not be written. */
    public long auditFailures() {
        return auditFailures.get();
    }

    /** Refusal records not written because their caller and status were over the throttle. */
    public long suppressedAuditEvents() {
        return refusalAudits.refused();
    }

    // ---- request handling ---------------------------------------------------------------------------------

    private void handle(HttpExchange ex) {
        try (ex) {
            Optional<Caller> caller = identify(ex);
            String callerName = caller.map(Caller::name).orElse("unknown");
            Optional<Endpoint> endpoint = Endpoint.of(ex.getRequestURI().getRawPath());
            Answer a;
            try {
                a = answer(ex, caller, endpoint);
            } catch (RuntimeException e) {
                internalFailures.incrementAndGet();
                a = Answer.refuse(403, "denied", "internal failure: " + e.getClass().getSimpleName());
            }
            a = audited(a, callerName, endpoint);
            send(ex, a);
        } catch (IOException | RuntimeException e) {
            // The connection broke while answering; there is nobody left to answer.
        }
    }

    private Optional<Caller> identify(HttpExchange ex) {
        if (!(ex instanceof HttpsExchange https)) {
            return Optional.empty();
        }
        SSLSession session = https.getSSLSession();
        if (session == null) {
            return Optional.empty();
        }
        return TlsContexts.peerPrincipal(session).flatMap(this::caller);
    }

    /**
     * The configured caller with exactly this certificate subject. {@code X500Principal.equals} compares
     * canonical forms, which fold case, so {@code CN=GATEWAY} would "equal" {@code CN=gateway}: the
     * RFC 2253 strings are compared instead (finding A5).
     */
    Optional<Caller> caller(X500Principal subject) {
        return Optional.ofNullable(callers.get(subject.getName(X500Principal.RFC2253)));
    }

    /** Requests (handshake, headers, body and handling) cut off at the deadline. */
    public long timedOut() {
        return timedOut.get();
    }

    /**
     * Finding A2: the JDK server reads the handshake, headers and body on the worker thread with no time
     * limit, so a few clients sending one byte at a time held every worker. Each task now has a deadline;
     * when it passes the worker is interrupted, which closes its (interruptible) channel and frees it.
     */
    private Runnable withDeadline(Runnable task) {
        return () -> {
            Deadline d = new Deadline(Thread.currentThread());
            ScheduledFuture<?> alarm;
            try {
                alarm = watchdog.schedule(d::expire, settings.requestDeadline().toMillis(), TimeUnit.MILLISECONDS);
            } catch (RejectedExecutionException stopping) {
                return; // the server is closing; its connections are closed with it
            }
            try {
                task.run();
            } finally {
                alarm.cancel(false);
                if (d.finish()) {
                    timedOut.incrementAndGet();
                }
                Thread.interrupted(); // never carry an interrupt into the next task
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

        /** Marks the task finished; true if its deadline had passed. */
        synchronized boolean finish() {
            running = false;
            return expired;
        }
    }

    private Answer answer(HttpExchange ex, Optional<Caller> caller, Optional<Endpoint> endpoint) throws IOException {
        if (caller.isEmpty()) {
            return Answer.refuse(403, "forbidden", "certificate subject is not a configured caller");
        }
        Caller c = caller.get();
        if (!callerLimit.tryAcquire(c.name(), clock.instant())) {
            return Answer.refuse(429, "too many requests", "caller over its rate limit");
        }
        if (endpoint.isEmpty() || ex.getRequestURI().getRawQuery() != null) {
            return Answer.refuse(404, "not found", "no such endpoint");
        }
        Endpoint e = endpoint.get();
        if (!e.serves(c.role())) {
            return Answer.refuse(403, "forbidden", "role " + c.role() + " may not call this endpoint");
        }
        if (!e.method().equals(ex.getRequestMethod())) {
            return Answer.refuse(405, "method not allowed", "wrong method");
        }
        if (!inFlight.tryAcquire()) {
            return Answer.refuse(503, "busy", "too many requests in flight");
        }
        try {
            if (e == Endpoint.HEALTH) {
                return new Answer(200, JsonValue.object().put("status", "ok").build(), "ok", Optional.empty(), "", false);
            }
            if (!jsonContent(ex.getRequestHeaders().getFirst("Content-Type"))) {
                return Answer.refuse(415, "unsupported media type", "content type is not application/json");
            }
            Optional<byte[]> body = readBody(ex);
            if (body.isEmpty()) {
                return Answer.refuse(413, "request too large", "body over " + settings.maxBodyBytes() + " bytes");
            }
            return work(e, c, json.read(body.get()));
        } catch (JsonException j) {
            return Answer.refuse(400, "invalid request", "invalid JSON: " + j.getMessage());
        } catch (IllegalArgumentException iae) {
            return Answer.refuse(400, "invalid request", "invalid value");
        } finally {
            inFlight.release();
        }
    }

    private Answer work(Endpoint e, Caller c, JsonValue body) {
        String actor = "api/" + c.name();
        return switch (e) {
            case OPEN -> {
                WireFormat.OpenBody b = WireFormat.readOpen(body);
                yield inScope(c, b.login().resourceId())
                        .orElseGet(() -> edge(authority.open(b.login(), b.sessionKey(), b.deviceBinding())));
            }
            case USE -> {
                WireFormat.UseBody b = WireFormat.readUse(body);
                yield inScope(c, b.request().resourceId())
                        .orElseGet(() -> edge(authority.use(b.token(), b.proof(), b.request())));
            }
            case DECIDE -> {
                WireFormat.DecideBody b = WireFormat.readDecide(body);
                yield inScope(c, b.request().resourceId()).orElseGet(() -> edge(authority.decide(b.request())));
            }
            case REVOKE -> {
                ApiBodies.RevokeBody b = ApiBodies.readRevoke(body);
                int n = switch (b.scope()) {
                    case SESSION -> administrator.revokeSession(b.id(), actor, b.reason());
                    case SUBJECT -> administrator.revokeSubject(b.id(), actor, b.reason());
                    case DEVICE -> administrator.revokeDevice(b.id(), actor, b.reason());
                };
                if (b.scope() != ApiBodies.Scope.SUBJECT) {
                    yield new Answer(200, ApiBodies.revoked(n), "revoked " + n, Optional.of(b.id()), "", false);
                }
                // Integration request R8: cutting a person off also ends their just-in-time admin rights,
                // or a compromised admin would keep elevation that a new session could use at once.
                int ended = pam.revokeSubject(b.id(), actor, b.reason());
                JsonValue answer = JsonValue.object().put("revoked", JsonValue.num(n)).put("elevations", JsonValue.num(ended)).build();
                yield new Answer(200, answer, "revoked " + n + ", elevations " + ended, Optional.of(b.id()), "", false);
            }
            case PAM_REQUEST -> {
                ApiBodies.ElevationBody b = ApiBodies.readElevation(body);
                yield pam(pam.request(b.subjectId(), b.deviceId(), b.role(), b.duration(), b.justification(),
                        b.authentication(), b.authenticationProof()));
            }
            case PAM_APPROVAL -> {
                ApiBodies.ApprovalBody b = ApiBodies.readApproval(body);
                yield pam(pam.approve(b.requestId(), b.approverId(), b.approval()));
            }
            case PAM_BREAK_GLASS -> {
                ApiBodies.BreakGlassBody b = ApiBodies.readBreakGlass(body);
                yield pam(pam.breakGlass(b.accountId(), b.role(), b.justification(), b.sealed()));
            }
            case PAM_REVIEW -> {
                ApiBodies.ReviewBody b = ApiBodies.readReview(body);
                yield pam(pam.review(b.grantId(), b.reviewerId(), b.verdict(), b.signed()));
            }
            case HEALTH -> throw new IllegalStateException("health has no body");
        };
    }

    /**
     * Integration request R7: an enforcement point asks only about the resources it fronts. Otherwise a
     * compromised web gateway could open sessions for the wiki, or spend a wiki session it captured.
     * Empty when in scope; otherwise the refusal.
     */
    private static Optional<Answer> inScope(Caller c, String resourceId) {
        return c.mayAsk(resourceId) ? Optional.empty()
                : Optional.of(Answer.refuse(403, "forbidden", "resource outside the caller's scope"));
    }

    private static Answer edge(EdgeResult r) {
        return new Answer(200, WireFormat.result(r), r.status().name(), Optional.of(r.reference()), "",
                r.status().allowed());
    }

    private static Answer pam(PrivilegedAccessManager.Result r) {
        // PAM audits its own reasons; the console only learns whether it worked.
        return new Answer(200, ApiBodies.pamAnswer(r.ok(), r.id()), r.ok() ? "ok" : "refused", r.id(), "", r.ok());
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

    private static boolean jsonContent(String contentType) {
        if (contentType == null) {
            return false;
        }
        String t = contentType.strip().toLowerCase(Locale.ROOT).replace(" ", "");
        return t.equals("application/json") || t.equals("application/json;charset=utf-8");
    }

    // ---- audit and output ---------------------------------------------------------------------------------

    private Answer audited(Answer a, String caller, Optional<Endpoint> endpoint) {
        boolean refusal = a.status() != 200;
        boolean routine = endpoint.orElse(null) == Endpoint.HEALTH;
        if ((refusal || routine) && !refusalAudits.tryAcquire(caller + ":" + a.status(), clock.instant())) {
            return a;
        }
        Map<String, String> f = new LinkedHashMap<>();
        f.put("caller", caller);
        f.put("endpoint", endpoint.map(Endpoint::path).orElse("unknown"));
        f.put("status", Integer.toString(a.status()));
        f.put("result", a.result());
        a.reference().ifPresent(r -> f.put("reference", r));
        if (!a.detail().isEmpty()) {
            f.put("detail", a.detail());
        }
        try {
            audit.append(refusal ? "API_REFUSED" : "API_CALL", ACTOR, clock.instant(), f);
            return a;
        } catch (RuntimeException e) {
            auditFailures.incrementAndGet();
            return a.allowed() ? Answer.refuse(403, "denied", "audit trail unavailable") : a;
        }
    }

    private static void send(HttpExchange ex, Answer a) throws IOException {
        byte[] bytes = JsonWriter.bytes(a.body());
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.sendResponseHeaders(a.status(), bytes.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
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
        private SSLContext tls;
        private InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        private SessionAuthority authority;
        private PolicyAdministrator administrator;
        private final PrivilegedAccessManager pam;
        private final AuditLog audit;
        private Clock clock = Clock.systemUTC();
        private List<Caller> callers = List.of();
        private ApiSettings settings = ApiSettings.defaults();

        private Builder(AuditLog audit, PrivilegedAccessManager pam) {
            this.audit = audit;
            this.pam = pam;
        }

        /** From {@link TlsContexts#create}: the API's key store and a trust store holding only the Dwarpal CA. */
        public Builder tls(SSLContext v) {
            tls = v;
            return this;
        }

        /** Default: loopback, a free port. */
        public Builder address(InetSocketAddress v) {
            address = v;
            return this;
        }

        public Builder authority(SessionAuthority v) {
            authority = v;
            return this;
        }

        public Builder administrator(PolicyAdministrator v) {
            administrator = v;
            return this;
        }

        public Builder clock(Clock v) {
            clock = v;
            return this;
        }

        public Builder callers(List<Caller> v) {
            callers = List.copyOf(v);
            return this;
        }

        public Builder settings(ApiSettings v) {
            settings = v;
            return this;
        }

        public ApiServer build() throws IOException {
            return new ApiServer(this);
        }
    }
}

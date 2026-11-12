package dev.dwarpal.socapi;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.guard.RateLimiter;
import dev.dwarpal.response.Playbooks;
import dev.dwarpal.soar.Analyst;
import dev.dwarpal.soar.CaseManager;
import dev.dwarpal.soar.CaseView;
import dev.dwarpal.soar.DeviceIsolation;
import dev.dwarpal.soar.Soar;
import dev.dwarpal.soc.ChainedEvent;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EntityRisk;
import dev.dwarpal.soc.EventSearch;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.Verdict;
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
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
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
 * The SOC API: what the Layer 6 console calls. HTTPS with mutual TLS 1.3 ({@link TlsContexts}); analysts are known
 * by the exact subject of their client certificate, compared case-sensitively in RFC 2253 form. JDK
 * {@code HttpsServer}, no framework.
 *
 * <p>Read endpoints: the ranked queue, cases with their alerts, notes and timelines, entity risk, search (passed
 * through to {@link EventSearch}), isolations, metrics and reports. Write endpoints: case notes, assignments and
 * signed verdicts, and nothing else (no endpoint revokes, denies or isolates directly: that only happens through a
 * verdict and the playbooks' guard rails).
 *
 * <p>Every request goes through the same steps, and the first that fails answers:
 * <ol>
 *   <li>who is calling (exact certificate subject): 403;</li>
 *   <li>per-analyst rate limit on all calls, then on writes and on searches: 429;</li>
 *   <li>route: the raw path must match an endpoint segment by segment, parameters must be plain identifiers (no
 *       percent-encoding, no {@code ..}, no query string): 404; method: 405;</li>
 *   <li>capacity: 503;</li>
 *   <li>body (writes and search): {@code application/json}, at most 16 KiB, strict JSON and a strict schema:
 *       415, 413, 400;</li>
 *   <li>visibility: an analyst never sees a case, risk or event about themselves; cases and data about other
 *       analysts are for leads only; an analyst sees unassigned cases, their own, and cases waiting for a second
 *       analyst. Anything not visible is answered 404, the same as anything that does not exist;</li>
 *   <li>work; a verdict must be signed by the calling analyst's own key.</li>
 * </ol>
 * Error bodies are one of a few fixed strings; reasons go only to the audit trail. Every call is audited (refusals
 * throttled per caller and status, the rest counted); an answer that carries data is not sent if its audit record
 * cannot be written. Each request has a deadline covering handshake, headers, body and work.
 */
public final class SocApiServer implements AutoCloseable {

    public static final String ACTOR = "soc-api";

    enum Kind { READ, WRITE, SEARCH }

    /** The endpoints; {@code {}} is one identifier segment. */
    enum Endpoint {
        HEALTH("GET", "/v1/health", Kind.READ),
        QUEUE("GET", "/v1/queue", Kind.READ),
        CASES("GET", "/v1/cases", Kind.READ),
        CASE("GET", "/v1/cases/{}", Kind.READ),
        TIMELINE("GET", "/v1/cases/{}/timeline", Kind.READ),
        NOTE("POST", "/v1/cases/{}/notes", Kind.WRITE),
        ASSIGN("POST", "/v1/cases/{}/assignment", Kind.WRITE),
        VERDICT("POST", "/v1/verdicts", Kind.WRITE),
        RISK_TOP("GET", "/v1/risk/top", Kind.READ),
        RISK("GET", "/v1/risk/{}/{}", Kind.READ),
        SEARCH("POST", "/v1/search", Kind.SEARCH),
        COUNTS("POST", "/v1/counts", Kind.SEARCH),
        ISOLATIONS("GET", "/v1/isolations", Kind.READ),
        METRICS("GET", "/v1/metrics", Kind.READ),
        REPORT("GET", "/v1/reports/{}", Kind.READ);

        final String method;
        final String template;
        final Kind kind;
        private final String[] parts;

        Endpoint(String method, String template, Kind kind) {
            this.method = method;
            this.template = template;
            this.kind = kind;
            this.parts = template.split("/", -1);
        }

        /** The parameters if {@code rawPath} matches this endpoint. */
        Optional<List<String>> match(String rawPath) {
            String[] got = rawPath.split("/", -1);
            if (got.length != parts.length) {
                return Optional.empty();
            }
            List<String> params = new ArrayList<>();
            for (int i = 0; i < parts.length; i++) {
                if (parts[i].equals("{}")) {
                    if (!plainId(got[i])) {
                        return Optional.empty();
                    }
                    params.add(got[i]);
                } else if (!parts[i].equals(got[i])) {
                    return Optional.empty();
                }
            }
            return Optional.of(List.copyOf(params));
        }

        private static boolean plainId(String s) {
            if (s.isEmpty() || s.length() > 128 || s.contains("..")) {
                return false;
            }
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
                        || c == '_' || c == '.' || c == ':' || c == '@';
                if (!ok) {
                    return false;
                }
            }
            return true;
        }
    }

    record Routed(Endpoint endpoint, List<String> params) {
    }

    private record Answer(int status, JsonValue body, String result, String detail, boolean data) {
        static Answer refuse(int status, String publicText, String detail) {
            return new Answer(status, SocJson.error(publicText), "refused", detail, false);
        }

        static Answer ok(JsonValue body, String result) {
            return new Answer(200, body, result, "", true);
        }

        static Answer notFound(String detail) {
            return refuse(404, "not found", detail);
        }
    }

    private final HttpsServer server;
    private final ThreadPoolExecutor workers;
    private final ScheduledThreadPoolExecutor watchdog;
    private final AuditLog audit;
    private final Clock clock;
    private final SocApiSettings settings;
    private final Soar soar;
    private final CaseManager cases;
    private final EventSearch search;
    private final EntityRisk risk;
    private final ReportSource reports;
    private final Map<String, Analyst> callers;
    private final JsonReader json;
    private final Semaphore inFlight;
    private final RateLimiter reads;
    private final RateLimiter writes;
    private final RateLimiter searches;
    private final RateLimiter refusalAudits;
    private final AtomicLong internalFailures = new AtomicLong();
    private final AtomicLong auditFailures = new AtomicLong();
    private final AtomicLong timedOut = new AtomicLong();
    private final String consoleSubject;
    private final Delegation.Verifier delegation;
    private final Map<String, Analyst> analystsById;

    private SocApiServer(Builder b) throws IOException {
        this.audit = Objects.requireNonNull(b.audit, "audit");
        this.soar = Objects.requireNonNull(b.soar, "soar");
        this.cases = soar.cases();
        this.search = Objects.requireNonNull(b.search, "search");
        this.risk = Objects.requireNonNull(b.risk, "risk");
        this.reports = Objects.requireNonNull(b.reports, "reports");
        this.clock = Objects.requireNonNull(b.clock, "clock");
        this.settings = Objects.requireNonNull(b.settings, "settings");
        SSLContext tls = Objects.requireNonNull(b.tls, "tls");
        Map<String, Analyst> byPrincipal = new LinkedHashMap<>();
        for (SocCaller c : b.callers) {
            Optional<Analyst> known = cases.analyst(c.analyst().id());
            if (known.isEmpty() || !known.get().equals(c.analyst())) {
                throw new IllegalArgumentException("caller " + c.analyst().id() + " is not an analyst of case management");
            }
            if (byPrincipal.putIfAbsent(c.subject(), c.analyst()) != null) {
                throw new IllegalArgumentException("two callers with the same certificate subject");
            }
        }
        if (byPrincipal.isEmpty()) {
            throw new IllegalArgumentException("no callers configured");
        }
        this.callers = Map.copyOf(byPrincipal);
        Map<String, Analyst> byId = new LinkedHashMap<>();
        byPrincipal.values().forEach(a -> byId.put(a.id(), a));
        this.analystsById = Map.copyOf(byId);
        if ((b.consoleSubject == null) != (b.delegation == null)) {
            throw new IllegalArgumentException("delegation needs both the console's certificate subject and a verifier");
        }
        if (b.consoleSubject != null && byPrincipal.containsKey(b.consoleSubject)) {
            throw new IllegalArgumentException("the console's certificate cannot also be an analyst's");
        }
        this.consoleSubject = b.consoleSubject;
        this.delegation = b.delegation;
        this.json = new JsonReader(new JsonLimits(settings.maxBodyBytes(), 4, SocJson.MAX_TEXT, 16, 16, 20, 64));
        this.inFlight = new Semaphore(settings.maxConcurrent());
        this.reads = new RateLimiter(settings.readsPerMinute(), Duration.ofMinutes(1), 1_000);
        this.writes = new RateLimiter(settings.writesPerMinute(), Duration.ofMinutes(1), 1_000);
        this.searches = new RateLimiter(settings.searchesPerMinute(), Duration.ofMinutes(1), 1_000);
        this.refusalAudits = new RateLimiter(settings.refusalAuditsPerMinute(), Duration.ofMinutes(1), 1_000);
        this.workers = new ThreadPoolExecutor(settings.threads(), settings.threads(), 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(settings.queue()), daemonThreads("dwarpal-socapi-"),
                new ThreadPoolExecutor.AbortPolicy());
        this.server = HttpsServer.create(Objects.requireNonNull(b.address, "address"), 64);
        server.setHttpsConfigurator(new HttpsConfigurator(tls) {
            @Override
            public void configure(HttpsParameters p) {
                p.setSSLParameters(TlsContexts.serverParameters(getSSLContext()));
            }
        });
        this.watchdog = new ScheduledThreadPoolExecutor(1, daemonThreads("dwarpal-socapi-watchdog-"));
        watchdog.setRemoveOnCancelPolicy(true);
        server.setExecutor(task -> workers.execute(withDeadline(task)));
        server.createContext("/", this::handle);
    }

    /** The audit trail and the SOAR are not optional. */
    public static Builder builder(AuditLog audit, Soar soar) {
        return new Builder(audit, soar);
    }

    public SocApiServer start() {
        server.start();
        return this;
    }

    public int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
        workers.shutdownNow();
        watchdog.shutdownNow();
    }

    public long internalFailures() {
        return internalFailures.get();
    }

    public long auditFailures() {
        return auditFailures.get();
    }

    public long suppressedAuditEvents() {
        return refusalAudits.refused();
    }

    public long timedOut() {
        return timedOut.get();
    }

    // ---- request handling ---------------------------------------------------------------------------------------

    private void handle(HttpExchange ex) {
        try (ex) {
            Optional<byte[]> preRead = Optional.empty();
            Optional<Analyst> caller;
            String delegationNote = "";
            if (viaConsole(ex)) {
                // the console speaks for an analyst: the signed assertion covers the body, so read it first
                boolean tooLarge = false;
                if (ex.getRequestMethod().equals("POST") && jsonContent(ex.getRequestHeaders().getFirst("Content-Type"))) {
                    preRead = readBody(ex);
                    tooLarge = preRead.isEmpty();
                }
                Delegation.Verdict v = tooLarge ? Delegation.Verdict.refuse("body too large") : delegation.verify(
                        ex.getRequestHeaders().getFirst(Delegation.HEADER), ex.getRequestMethod(),
                        ex.getRequestURI().getRawPath(), preRead.orElse(new byte[0]));
                caller = v.analystId().map(analystsById::get);
                delegationNote = caller.isPresent() ? " (via console)" : " [delegation refused: " + v.reason() + "]";
            } else {
                caller = identify(ex);
            }
            Optional<Routed> route = route(ex.getRequestURI().getRawPath(), ex.getRequestURI().getRawQuery());
            Answer a;
            try {
                a = answer(ex, caller, route, preRead);
            } catch (RuntimeException e) {
                internalFailures.incrementAndGet();
                a = Answer.refuse(503, "unavailable", "internal failure: " + e.getClass().getSimpleName());
            }
            a = audited(a, caller.map(Analyst::id).orElse("unknown"), ex.getRequestMethod(), route, delegationNote);
            send(ex, a);
        } catch (IOException | RuntimeException e) {
            // the connection broke while answering; nobody is left to answer
        }
    }

    private Optional<Analyst> identify(HttpExchange ex) {
        if (!(ex instanceof HttpsExchange https)) {
            return Optional.empty();
        }
        SSLSession session = https.getSSLSession();
        if (session == null) {
            return Optional.empty();
        }
        return TlsContexts.peerPrincipal(session).flatMap(this::caller);
    }

    /** The analyst with exactly this certificate subject (RFC 2253 strings, not case-folding {@code equals}). */
    private boolean viaConsole(HttpExchange ex) {
        if (consoleSubject == null || !(ex instanceof HttpsExchange https) || https.getSSLSession() == null) {
            return false;
        }
        return TlsContexts.peerPrincipal(https.getSSLSession())
                .map(p -> p.getName(X500Principal.RFC2253).equals(consoleSubject)).orElse(false);
    }

    Optional<Analyst> caller(X500Principal subject) {
        return Optional.ofNullable(callers.get(subject.getName(X500Principal.RFC2253)));
    }

    static Optional<Routed> route(String rawPath, String rawQuery) {
        if (rawPath == null || rawQuery != null || rawPath.length() > 300 || rawPath.indexOf('%') >= 0
                || rawPath.indexOf('\\') >= 0 || rawPath.indexOf(';') >= 0) {
            return Optional.empty();
        }
        for (Endpoint e : Endpoint.values()) {
            Optional<List<String>> p = e.match(rawPath);
            if (p.isPresent()) {
                return Optional.of(new Routed(e, p.get()));
            }
        }
        return Optional.empty();
    }

    private Answer answer(HttpExchange ex, Optional<Analyst> caller, Optional<Routed> route, Optional<byte[]> preRead)
            throws IOException {
        if (caller.isEmpty()) {
            return Answer.refuse(403, "forbidden", "certificate subject is not a configured analyst");
        }
        Analyst who = caller.get();
        Instant now = clock.instant();
        if (!reads.tryAcquire(who.id(), now)) {
            return Answer.refuse(429, "too many requests", "over the per-analyst call limit");
        }
        if (route.isEmpty()) {
            return Answer.notFound("no such endpoint");
        }
        Endpoint e = route.get().endpoint();
        if (!e.method.equals(ex.getRequestMethod())) {
            return Answer.refuse(405, "method not allowed", "wrong method");
        }
        if (e.kind == Kind.WRITE && !writes.tryAcquire(who.id(), now)
                || e.kind == Kind.SEARCH && !searches.tryAcquire(who.id(), now)) {
            return Answer.refuse(429, "too many requests", "over the per-analyst " + e.kind.name().toLowerCase(Locale.ROOT)
                    + " limit");
        }
        if (!inFlight.tryAcquire()) {
            return Answer.refuse(503, "busy", "too many requests in flight");
        }
        try {
            JsonValue body = null;
            if (e.method.equals("POST")) {
                if (!jsonContent(ex.getRequestHeaders().getFirst("Content-Type"))) {
                    return Answer.refuse(415, "unsupported media type", "content type is not application/json");
                }
                Optional<byte[]> bytes = preRead.isPresent() ? preRead : readBody(ex);
                if (bytes.isEmpty()) {
                    return Answer.refuse(413, "request too large", "body over " + settings.maxBodyBytes() + " bytes");
                }
                body = json.read(bytes.get());
            }
            return work(e, route.get().params(), who, body, now);
        } catch (JsonException j) {
            return Answer.refuse(400, "invalid request", "invalid JSON: " + j.getMessage());
        } catch (IllegalArgumentException iae) {
            return Answer.refuse(400, "invalid request", "invalid value");
        } finally {
            inFlight.release();
        }
    }

    private Answer work(Endpoint e, List<String> p, Analyst who, JsonValue body, Instant now) {
        return switch (e) {
            case HEALTH -> new Answer(200, JsonValue.object().put("status", "ok").build(), "ok", "", false);
            case QUEUE -> queue(who);
            case CASES -> caseList(who);
            case CASE -> visibleCase(who, p.getFirst()).map(c -> Answer.ok(SocJson.caseDetail(c), "case " + c.id()))
                    .orElseGet(() -> Answer.notFound("case not visible"));
            case TIMELINE -> visibleCase(who, p.getFirst()).map(c -> Answer.ok(SocJson.timeline(c),
                    "timeline " + c.id())).orElseGet(() -> Answer.notFound("case not visible"));
            case NOTE -> change(cases.note(p.getFirst(), who, SocJson.readNote(body)), "note on " + p.getFirst());
            case ASSIGN -> change(cases.assign(p.getFirst(), who, SocJson.readAssignment(body)),
                    "assignment of " + p.getFirst());
            case VERDICT -> verdict(who, SocJson.readVerdict(body));
            case RISK_TOP -> riskTop(who, now);
            case RISK -> riskOf(who, p.get(0), p.get(1), now);
            case SEARCH -> search(who, SocJson.readSearch(body));
            case COUNTS -> counts(who, SocJson.readCounts(body));
            case ISOLATIONS -> isolations(who);
            case METRICS -> metrics();
            case REPORT -> report(who, p.getFirst(), now);
        };
    }

    // ---- reads --------------------------------------------------------------------------------------------------

    private List<CaseView> visibleCases(Analyst who) {
        return cases.all().stream().filter(c -> cases.canSee(who, c.id())).toList();
    }

    private Optional<CaseView> visibleCase(Analyst who, String caseId) {
        return cases.canSee(who, caseId) ? cases.view(caseId).map(c -> redacted(who, c)) : Optional.empty();
    }

    /**
     * The case as this analyst may see it: links, and timeline entries about links, only to cases they may see too
     * (red-team finding F-R4: links leaked the ids of cases about colleagues).
     */
    private CaseView redacted(Analyst who, CaseView c) {
        List<String> links = c.links().stream().filter(l -> cases.canSee(who, l)).toList();
        List<CaseView.TimelineEntry> timeline = c.timeline().stream()
                .filter(t -> t.kind() != CaseView.TimelineEntry.Kind.LINKED || !t.detail().startsWith(CaseManager.LINK_PREFIX)
                        || cases.canSee(who, t.detail().substring(CaseManager.LINK_PREFIX.length())))
                .toList();
        return new CaseView(c.id(), c.key(), c.state(), c.priority(), c.score(), c.openedAt(), c.deadline(),
                c.acknowledgedAt(), c.breached(), c.assignee(), c.holdsActions(), c.awaitingSecond(), c.alerts(),
                c.entities(), c.notes(), timeline, links, c.timelineDropped());
    }

    private Answer queue(Analyst who) {
        List<JsonValue> out = new ArrayList<>();
        for (CaseView c : visibleCases(who)) {
            if (c.state() != dev.dwarpal.response.Case.State.CLOSED && out.size() < 200) {
                out.add(SocJson.caseSummary(c));
            }
        }
        return Answer.ok(JsonValue.object().put("queue", new JsonValue.JArray(out)).build(), out.size() + " cases");
    }

    private Answer caseList(Analyst who) {
        List<JsonValue> out = new ArrayList<>();
        for (CaseView c : visibleCases(who)) {
            if (out.size() < 500) {
                out.add(SocJson.caseSummary(c));
            }
        }
        return Answer.ok(JsonValue.object().put("cases", new JsonValue.JArray(out)).build(), out.size() + " cases");
    }

    private boolean mayReadAbout(Analyst who, Entity e) {
        if (e.kind() == Entity.Kind.SUBJECT && e.id().equals(who.id())) {
            return false;
        }
        return who.lead() || !cases.aboutAnalyst(e);
    }

    private Answer riskOf(Analyst who, String kind, String id, Instant now) {
        Entity.Kind k = switch (kind) {
            case "subject" -> Entity.Kind.SUBJECT;
            case "device" -> Entity.Kind.DEVICE;
            case "ip" -> Entity.Kind.IP;
            case "session" -> Entity.Kind.SESSION;
            case "resource" -> Entity.Kind.RESOURCE;
            default -> null;
        };
        if (k == null) {
            return Answer.notFound("unknown entity kind");
        }
        Entity entity = new Entity(k, Validate.id(id, "id"));
        if (!mayReadAbout(who, entity)) {
            return Answer.notFound("entity not visible");
        }
        EntityRisk.RiskView v;
        try {
            v = risk.view(entity, now);
        } catch (RuntimeException ex) {
            return Answer.refuse(503, "unavailable", "entity risk failed: " + ex.getClass().getSimpleName());
        }
        if (v == null || !v.entity().equals(entity)) {
            return Answer.refuse(503, "unavailable", "entity risk answered about another entity");
        }
        return Answer.ok(SocJson.risk(v), "risk " + k.name().toLowerCase(Locale.ROOT) + " " + entity.id());
    }

    private Answer riskTop(Analyst who, Instant now) {
        List<EntityRisk.RiskView> top;
        try {
            top = risk.top(EntityRisk.MAX_TOP, now);
        } catch (RuntimeException ex) {
            return Answer.refuse(503, "unavailable", "entity risk failed: " + ex.getClass().getSimpleName());
        }
        List<JsonValue> out = new ArrayList<>();
        int hidden = 0;
        for (EntityRisk.RiskView v : top == null ? List.<EntityRisk.RiskView>of() : top) {
            if (out.size() >= 50) {
                break;
            }
            if (mayReadAbout(who, v.entity())) {
                out.add(SocJson.risk(v));
            } else {
                hidden++;
            }
        }
        return Answer.ok(JsonValue.object().put("top", new JsonValue.JArray(out)).build(),
                out.size() + " shown, " + hidden + " hidden");
    }

    private Answer search(Analyst who, SocJson.Search s) {
        if (!s.to().isAfter(s.from()) || Duration.between(s.from(), s.to()).compareTo(settings.maxSearchWindow()) > 0) {
            return Answer.refuse(400, "invalid request", "search window empty or too long");
        }
        EventSearch.Result r;
        try {
            r = search.search(s.query(), s.from(), s.to(), s.limit());
        } catch (IllegalArgumentException ex) {
            return Answer.refuse(400, "invalid request", "search refused the arguments");
        } catch (RuntimeException ex) {
            return Answer.refuse(503, "unavailable", "search failed: " + ex.getClass().getSimpleName());
        }
        if (r == null) {
            return Answer.refuse(503, "unavailable", "search answered nothing");
        }
        if (r.problem().isPresent()) {
            return new Answer(200, JsonValue.object().put("problem", Sanitize.text(r.problem().get(), 200)).build(),
                    "search problem", "", false);
        }
        List<JsonValue> events = new ArrayList<>();
        int hidden = 0;
        for (ChainedEvent c : r.events()) {
            if (events.size() >= s.limit()) {
                break;
            }
            if (c.event().entities().stream().allMatch(en -> mayReadAbout(who, en))) {
                events.add(SocJson.event(c));
            } else {
                hidden++;
            }
        }
        // Red-team finding F-R3: hidden events must not show in any number either (the count of a colleague's events
        // is itself information about them). The audit record keeps how many were hidden.
        long matched = hidden > 0 ? events.size() : r.matched();
        boolean truncated = hidden > 0 ? events.size() >= s.limit() : r.truncated();
        JsonValue answer = JsonValue.object().put("events", new JsonValue.JArray(events))
                .put("matched", JsonValue.num(matched)).put("truncated", JsonValue.bool(truncated)).build();
        return Answer.ok(answer, "search: " + events.size() + " shown, " + hidden + " hidden, query sha256 "
                + dev.dwarpal.crypto.Digests.sha256Hex(s.query()).substring(0, 16));
    }

    /** {@code count by}: the same window, the same per-event visibility as search, and no total beyond what is shown. */
    private Answer counts(Analyst who, SocJson.Search s) {
        if (!s.to().isAfter(s.from()) || Duration.between(s.from(), s.to()).compareTo(settings.maxSearchWindow()) > 0) {
            return Answer.refuse(400, "invalid request", "counts window empty or too long");
        }
        EventSearch.Counts r;
        try {
            r = search.counts(s.query(), s.from(), s.to(),
                    c -> c.event().entities().stream().allMatch(en -> mayReadAbout(who, en)));
        } catch (IllegalArgumentException ex) {
            return Answer.refuse(400, "invalid request", "counts refused the arguments");
        } catch (RuntimeException ex) {
            return Answer.refuse(503, "unavailable", "counts failed: " + ex.getClass().getSimpleName());
        }
        if (r.problem().isPresent()) {
            return new Answer(200, JsonValue.object().put("problem", Sanitize.text(r.problem().get(), 200)).build(),
                    "counts problem", "", false);
        }
        List<JsonValue> groups = new ArrayList<>();
        for (EventSearch.Group g : r.groups()) {
            if (groups.size() >= 1_000) {
                break;
            }
            List<JsonValue> values = new ArrayList<>();
            for (String v : g.values()) {
                values.add(JsonValue.str(Sanitize.text(v, 200)));
            }
            groups.add(JsonValue.object().put("values", new JsonValue.JArray(values))
                    .put("count", JsonValue.num(g.count())).build());
        }
        JsonValue answer = JsonValue.object().put("groups", new JsonValue.JArray(groups))
                .put("matched", JsonValue.num(r.matched())).put("truncated", JsonValue.bool(r.truncated())).build();
        return Answer.ok(answer, "counts: " + groups.size() + " groups, query sha256 "
                + dev.dwarpal.crypto.Digests.sha256Hex(s.query()).substring(0, 16));
    }

    private Answer isolations(Analyst who) {
        List<JsonValue> out = new ArrayList<>();
        for (DeviceIsolation.Isolation i : soar.isolation().all()) {
            List<String> visible = i.cases().stream().filter(c -> cases.canSee(who, c)).toList();
            if (!visible.isEmpty() && out.size() < 500) {
                out.add(SocJson.isolation(i, visible));
            }
        }
        return Answer.ok(JsonValue.object().put("isolations", new JsonValue.JArray(out)).build(),
                out.size() + " isolations");
    }

    private Answer metrics() {
        CaseManager.Metrics m = cases.metrics();
        Soar.Metrics s = soar.metrics();
        JsonValue.JObject.Builder open = JsonValue.object();
        for (Priority p : Priority.values()) {
            open.put(p.name(), JsonValue.num(m.openByPriority().getOrDefault(p, 0)));
        }
        long isolated = soar.isolation().all().stream().filter(i -> i.state() == DeviceIsolation.State.ISOLATED).count();
        long overdue = soar.isolation().all().stream().filter(DeviceIsolation.Isolation::overdue).count();
        JsonValue body = JsonValue.object()
                .put("cases", JsonValue.object().put("tracked", JsonValue.num(m.tracked())).put("open", open.build())
                        .put("breached", JsonValue.num(m.breached())).put("unassigned", JsonValue.num(m.unassigned()))
                        .put("refusedAlerts", JsonValue.num(m.refusedByBook()))
                        .put("rankerFailures", JsonValue.num(m.rankerFailures())).build())
                .put("response", JsonValue.object().put("playbookSequence", JsonValue.num(s.playbookSequence()))
                        .put("playbookVersion", s.playbookVersion())
                        .put("refusedVerdicts", JsonValue.num(s.refusedVerdicts()))
                        .put("heldBack", JsonValue.num(s.heldBack()))
                        .put("awaitingSecondAnalyst", JsonValue.num(s.pending()))
                        .put("notifyFailures", JsonValue.num(s.notifyFailures())).build())
                .put("isolation", JsonValue.object().put("isolated", JsonValue.num(isolated))
                        .put("overdue", JsonValue.num(overdue)).build())
                .put("api", JsonValue.object().put("internalFailures", JsonValue.num(internalFailures.get()))
                        .put("auditFailures", JsonValue.num(auditFailures.get()))
                        .put("timedOut", JsonValue.num(timedOut.get())).build())
                .build();
        return Answer.ok(body, "metrics");
    }

    private Answer report(Analyst who, String name, Instant now) {
        if (!who.lead()) {
            return Answer.notFound("reports are for leads");
        }
        Optional<String> text;
        try {
            text = reports.report(name, now);
        } catch (RuntimeException ex) {
            return Answer.refuse(503, "unavailable", "report failed: " + ex.getClass().getSimpleName());
        }
        if (text == null || text.isEmpty()) {
            return Answer.notFound("no such report");
        }
        if (text.get().length() > ReportSource.MAX_CHARS) {
            return Answer.refuse(503, "unavailable", "report too large");
        }
        return Answer.ok(JsonValue.object().put("name", name).put("text", text.get()).build(), "report " + name);
    }

    // ---- writes -------------------------------------------------------------------------------------------------

    private static Answer change(CaseManager.Outcome o, String what) {
        return switch (o) {
            case OK -> new Answer(200, JsonValue.object().put("ok", JsonValue.bool(true)).build(), what, "", false);
            case NOT_FOUND -> Answer.notFound(what + ": case not visible");
            case FORBIDDEN -> Answer.refuse(403, "forbidden", what + ": not allowed for this analyst");
            case CONFLICT -> Answer.refuse(409, "conflict", what + ": case closed or full");
            case INVALID -> Answer.refuse(400, "invalid request", what + ": invalid value");
            case UNAVAILABLE -> Answer.refuse(503, "unavailable", what + ": audit trail unavailable");
        };
    }

    private Answer verdict(Analyst who, Verdict v) {
        if (!v.analystId().equals(who.id())) {
            return Answer.refuse(403, "forbidden", "verdict names another analyst");
        }
        Optional<String> caseId = cases.caseOfAlert(v.alertId());
        if (caseId.isEmpty() || !cases.canSee(who, caseId.get())) {
            return Answer.notFound("alert not in a visible case");
        }
        Soar.Result r = soar.handle(v);
        if (r.status() == Playbooks.Status.REFUSED) {
            return Answer.refuse(403, "verdict refused", "verdict refused: " + Sanitize.text(r.message(), 200));
        }
        JsonValue body = JsonValue.object().put("status", r.status().name())
                .put("case", r.caseId().orElse(caseId.get()))
                .put("actions", JsonValue.num(r.actions()))
                .put("mode", r.mode().map(Enum::name).orElse("NONE"))
                .put("message", r.message())
                .put("isolated", SocJson.strings(r.isolated()))
                .put("released", SocJson.strings(r.released())).build();
        return new Answer(200, body, "verdict " + r.status().name(), "", false);
    }

    // ---- plumbing -----------------------------------------------------------------------------------------------

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

    private Answer audited(Answer a, String caller, String method, Optional<Routed> route, String via) {
        boolean refusal = a.status() != 200;
        boolean routine = route.map(r -> r.endpoint() == Endpoint.HEALTH).orElse(false);
        if ((refusal || routine) && !refusalAudits.tryAcquire(caller + ":" + a.status(), clock.instant())) {
            return a;
        }
        Map<String, String> f = new LinkedHashMap<>();
        f.put("caller", caller);
        if (!via.isEmpty()) {
            f.put("via", Sanitize.text(via.strip(), 160));
        }
        f.put("method", method == null || method.length() > 10 ? "other" : Sanitize.text(method, 10));
        f.put("endpoint", route.map(r -> r.endpoint().template).orElse("unknown"));
        route.ifPresent(r -> {
            for (int i = 0; i < r.params().size(); i++) {
                f.put("param" + i, r.params().get(i));
            }
        });
        f.put("status", Integer.toString(a.status()));
        f.put("result", Sanitize.text(a.result(), 200));
        if (!a.detail().isEmpty()) {
            f.put("detail", Sanitize.text(a.detail(), 300));
        }
        try {
            audit.append(refusal ? "SOCAPI_REFUSED" : "SOCAPI_CALL", ACTOR, clock.instant(), f);
            return a;
        } catch (RuntimeException e) {
            auditFailures.incrementAndGet();
            return a.data() ? Answer.refuse(503, "unavailable", "audit trail unavailable") : a;
        }
    }

    private static void send(HttpExchange ex, Answer a) throws IOException {
        byte[] bytes = JsonWriter.bytes(a.body());
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        if (a.status() == 413) {
            // the body was left unread, so this connection cannot carry another request: say so, or the caller reuses it and hangs
            ex.getResponseHeaders().set("Connection", "close");
        }
        ex.sendResponseHeaders(a.status(), bytes.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }

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

    /** One task's deadline: interrupts its worker only while that task still runs on it (Layer 4 finding A2). */
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
        private final AuditLog audit;
        private final Soar soar;
        private SSLContext tls;
        private InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        private Clock clock = Clock.systemUTC();
        private List<SocCaller> callers = List.of();
        private String consoleSubject;
        private Delegation.Verifier delegation;
        private SocApiSettings settings = SocApiSettings.defaults();
        private EventSearch search;
        private EntityRisk risk;
        private ReportSource reports = ReportSource.none();

        private Builder(AuditLog audit, Soar soar) {
            this.audit = audit;
            this.soar = soar;
        }

        public Builder tls(SSLContext v) {
            tls = v;
            return this;
        }

        public Builder address(InetSocketAddress v) {
            address = v;
            return this;
        }

        public Builder clock(Clock v) {
            clock = v;
            return this;
        }

        /**
         * Lets the console (the certificate with exactly this RFC 2253 subject) act for the configured analysts,
         * one signed assertion per call (see {@link Delegation}).
         */
        public Builder delegation(String consoleSubject, Delegation.Verifier verifier) {
            this.consoleSubject = Objects.requireNonNull(consoleSubject, "consoleSubject");
            this.delegation = Objects.requireNonNull(verifier, "verifier");
            return this;
        }

        public Builder callers(List<SocCaller> v) {
            callers = List.copyOf(v);
            return this;
        }

        public Builder settings(SocApiSettings v) {
            settings = v;
            return this;
        }

        public Builder search(EventSearch v) {
            search = v;
            return this;
        }

        public Builder risk(EntityRisk v) {
            risk = v;
            return this;
        }

        public Builder reports(ReportSource v) {
            reports = v;
            return this;
        }

        public SocApiServer build() throws IOException {
            return new SocApiServer(this);
        }
    }
}

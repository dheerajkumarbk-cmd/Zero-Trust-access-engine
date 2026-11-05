package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.console.ConsoleServer.Kind;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.lab.LabAudit;
import dev.dwarpal.lab.LabRunner;
import dev.dwarpal.soc.Verdict;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * The routes the server itself provides: session, identity, modules, lab status, the event stream, the SOC proxy and
 * the audit explorer (contract section 3). Person and role always come from the session; nothing in a request body
 * names who is calling, and every body is rebuilt from typed fields before it goes to the SOC API.
 */
final class ConsoleRoutes {

    /** The views the analyst console itself provides (part H): id, title. All need at least the analyst role. */
    static final List<String[]> BUILT_IN = List.of(
            new String[]{"overview", "Overview"}, new String[]{"queue", "Alert queue"}, new String[]{"cases", "Cases"},
            new String[]{"hunt", "Hunt"}, new String[]{"entity", "Entity"}, new String[]{"response", "Response"},
            new String[]{"audit", "Audit explorer"}, new String[]{"attack", "ATT&CK"});

    private static final int MAX_NOTE = 2_000;
    private static final Set<Integer> PASS = Set.of(200, 400, 403, 404, 409, 429, 503);

    private ConsoleRoutes() {
    }

    static void register(ConsoleServer s) {
        // ---- session
        s.route("POST", "session/login", Kind.PUBLIC, null, false, c -> login(s, c));
        s.route("POST", "session/verify", Kind.PUBLIC, null, false, c -> verify(s, c));
        s.route("POST", "session/stepup", Kind.READ, null, false, c -> stepUp(s, c));
        s.route("POST", "session/logout", Kind.READ, null, false, c -> logout(s, c));
        s.route("GET", "session/list", Kind.READ, null, false, c -> sessionList(s, c));
        s.route("POST", "session/revoke", Kind.READ, null, false, c -> revoke(s, c));
        // ---- identity, modules, lab, stream
        s.route("GET", "me", Kind.READ, null, false, c -> me(s, c));
        s.route("GET", "modules", Kind.READ, null, false, c -> modules(s, c));
        s.route("GET", "lab", Kind.READ, null, false, c -> Reply.rawJson(200, labJson(s, true)));
        s.route("GET", "stream", Kind.READ, null, false, c -> stream(s, c));
        // ---- the SOC API, as the person
        s.route("GET", "soc/queue", Kind.READ, Role.ANALYST, false, c -> soc(s, c, SocChannel.Calls::queue, ""));
        s.route("GET", "soc/cases", Kind.READ, Role.ANALYST, false, c -> soc(s, c, SocChannel.Calls::cases, ""));
        s.route("GET", "soc/cases/{}", Kind.SENSITIVE, Role.ANALYST, false,
                c -> soc(s, c, x -> x.caseDetail(c.params.get(0)), "case detail"));
        s.route("GET", "soc/cases/{}/timeline", Kind.SENSITIVE, Role.ANALYST, false,
                c -> soc(s, c, x -> x.timeline(c.params.get(0)), "case timeline"));
        s.route("POST", "soc/cases/{}/notes", Kind.WRITE, Role.ANALYST, false, c -> note(s, c));
        s.route("POST", "soc/cases/{}/assignment", Kind.WRITE, Role.ANALYST, false, c -> assign(s, c));
        s.route("POST", "soc/verdicts", Kind.WRITE, Role.ANALYST, true, c -> verdict(s, c));
        s.route("GET", "soc/risk/top", Kind.READ, Role.ANALYST, false, c -> soc(s, c, SocChannel.Calls::riskTop, ""));
        s.route("GET", "soc/risk/{}/{}", Kind.SENSITIVE, Role.ANALYST, false,
                c -> soc(s, c, x -> x.risk(c.params.get(0), c.params.get(1)), "entity risk"));
        s.route("POST", "soc/search", Kind.SENSITIVE, Role.ANALYST, false, c -> search(s, c, false));
        s.route("POST", "soc/counts", Kind.SENSITIVE, Role.ANALYST, false, c -> search(s, c, true));
        s.route("GET", "soc/isolations", Kind.READ, Role.ANALYST, false, c -> soc(s, c, SocChannel.Calls::isolations, ""));
        s.route("GET", "soc/metrics", Kind.READ, Role.ANALYST, false, c -> soc(s, c, SocChannel.Calls::metrics, ""));
        s.route("GET", "soc/reports/{}", Kind.SENSITIVE, Role.ANALYST, false,
                c -> soc(s, c, x -> x.report(c.params.get(0)), "report"));
        // ---- the audit explorer -----------------------------------------------------------------------------------

        s.route("GET", "audit/head", Kind.READ, Role.ANALYST, false, c -> auditHead(s));
        s.route("GET", "audit/records", Kind.READ, Role.ANALYST, false, c -> auditPage(s, c));
        s.route("GET", "audit/records/{}", Kind.SENSITIVE, Role.ANALYST, false, c -> auditRecord(s, c));
        s.route("GET", "audit/verify", Kind.SENSITIVE, Role.ANALYST, false, c -> auditVerify(s, c));
    }

    // ---- session ----------------------------------------------------------------------------------------------

    private static Reply login(ConsoleServer s, Ctx c) {
        Ctx.Fields f = c.fields(Set.of("user", "password"));
        String user = f.text("user", 128);
        ConsoleAuth.Begun b = s.auth.begin(user, f.text("password", 1024), c.source);
        return switch (b.status()) {
            case OK -> Reply.ok(JsonValue.object().put("loginId", b.loginId())
                    .put("expiresInSeconds", JsonValue.num(b.validFor().toSeconds()))
                    .put("secondFactor", JsonValue.object().put("kind", "security-key-pin")
                            .put("prompt", "Enter the PIN of your security key").build()).build());
            case LOCKED -> {
                loginFailed(s, user, c, "locked");
                yield locked(b.retryAfterSeconds());
            }
            case FAILED -> {
                loginFailed(s, user, c, "refused at the first step");
                yield Reply.error(401, "login failed");
            }
        };
    }

    private static Reply verify(ConsoleServer s, Ctx c) {
        Ctx.Fields f = c.fields(Set.of("loginId", "pin"));
        ConsoleAuth.Authenticated a = s.auth.complete(f.text("loginId", 64), f.text("pin", 64), c.source);
        switch (a.status()) {
            case OK -> {
                Optional<ConsoleSessions.Session> made = s.sessions.start(a.person(), c.source, c.agent);
                if (made.isEmpty()) {
                    return Reply.error(503, "busy");
                }
                ConsoleSessions.Session sess = made.get();
                if (!s.audit.write("CONSOLE_LOGIN", a.person().id(), ConsoleServer.fields("session", sess.tag(), "source",
                        c.source))) {
                    s.sessions.end(sess.id);
                    return Reply.error(503, "audit trail unavailable");
                }
                return Reply.ok(JsonValue.object().put("csrf", sess.csrf).put("person", person(a.person()))
                        .put("idleSeconds", JsonValue.num(s.settings.idle().toSeconds()))
                        .put("absoluteExpiresAt", s.sessions.absoluteUntil(sess).toString())
                        .put("stepUpUntil", s.sessions.stepUpUntil(sess).toString()).build())
                        .withCookie(ConsoleServer.sessionCookie(sess.id));
            }
            case LOCKED -> {
                loginFailed(s, a.subject(), c, "locked");
                return locked(a.retryAfterSeconds());
            }
            default -> {
                loginFailed(s, a.subject(), c, "wrong password, wrong key PIN, or unknown user");
                return Reply.error(401, "login failed");
            }
        }
    }

    private static void loginFailed(ConsoleServer s, String user, Ctx c, String why) {
        if (s.auditFailedLogins.tryAcquire("login|" + c.source, s.wall.instant())) {
            s.audit.write("CONSOLE_LOGIN_FAILED", null, ConsoleServer.fields("user", user == null ? "" : user, "source",
                    c.source, "why", why));
        }
    }

    private static Reply locked(long seconds) {
        return Reply.json(429, JsonValue.object().put("error", "too many attempts")
                .put("retryAfterSeconds", JsonValue.num(seconds)).build()).withHeader("Retry-After", Long.toString(seconds));
    }

    private static Reply stepUp(ConsoleServer s, Ctx c) {
        Ctx.Fields f = c.fields(Set.of("password", "pin"));
        ConsoleAuth.Authenticated a = s.auth.stepUp(c.person().id(), f.text("password", 1024), f.text("pin", 64), c.source);
        if (a.status() == ConsoleAuth.Status.LOCKED) {
            s.audit.write("CONSOLE_STEPUP_FAILED", c.person().id(), ConsoleServer.fields("session", c.session.tag(), "why",
                    "locked"));
            return locked(a.retryAfterSeconds());
        }
        if (a.status() != ConsoleAuth.Status.OK) {
            s.audit.write("CONSOLE_STEPUP_FAILED", c.person().id(), ConsoleServer.fields("session", c.session.tag(), "why",
                    "wrong password or key PIN"));
            return Reply.error(401, "step-up failed");
        }
        Optional<ConsoleSessions.Session> fresh = s.sessions.stepUp(c.session);
        if (fresh.isEmpty()) {
            return Reply.error(401, "login required");
        }
        s.hub.closeSession(c.session.id);
        if (!s.audit.write("CONSOLE_STEPUP", c.person().id(), ConsoleServer.fields("session", fresh.get().tag(), "was",
                c.session.tag()))) {
            s.sessions.end(fresh.get().id);
            return Reply.error(503, "audit trail unavailable");
        }
        return Reply.ok(JsonValue.object().put("csrf", fresh.get().csrf)
                .put("stepUpUntil", s.sessions.stepUpUntil(fresh.get()).toString()).build())
                .withCookie(ConsoleServer.sessionCookie(fresh.get().id));
    }

    private static Reply logout(ConsoleServer s, Ctx c) {
        s.sessions.end(c.session.id);
        s.hub.closeSession(c.session.id);
        s.audit.write("CONSOLE_LOGOUT", c.person().id(), ConsoleServer.fields("session", c.session.tag()));
        return Reply.ok(JsonValue.object().put("ok", JsonValue.bool(true)).build()).withCookie(ConsoleServer.clearCookie());
    }

    private static Reply sessionList(ConsoleServer s, Ctx c) {
        List<JsonValue> out = new ArrayList<>();
        for (ConsoleSessions.Session x : s.sessions.of(c.person().id())) {
            out.add(JsonValue.object().put("id", x.tag()).put("createdAt", x.createdAt.toString())
                    .put("lastSeen", x.lastSeen.toString()).put("source", x.source)
                    .put("current", JsonValue.bool(x.id.equals(c.session.id))).build());
        }
        return Reply.ok(JsonValue.object().put("sessions", new JsonValue.JArray(out)).build());
    }

    private static Reply revoke(ConsoleServer s, Ctx c) {
        String tag = c.fields(Set.of("id")).text("id", 64);
        for (ConsoleSessions.Session x : s.sessions.of(c.person().id())) {
            if (x.tag().equals(tag)) {
                if (x.id.equals(c.session.id)) {
                    return Reply.error(400, "use logout for this session");
                }
                s.sessions.end(x.id);
                s.hub.closeSession(x.id);
                s.audit.write("CONSOLE_SESSION_REVOKED", c.person().id(), ConsoleServer.fields("session", c.session.tag(),
                        "revoked", tag));
                return Reply.ok(JsonValue.object().put("ok", JsonValue.bool(true)).build());
            }
        }
        return Reply.error(404, "not found");
    }

    // ---- identity, modules, lab, stream -----------------------------------------------------------------------

    private static JsonValue person(ConsoleAuth.Person p) {
        List<JsonValue> roles = new ArrayList<>();
        p.roles().stream().map(Enum::name).sorted().forEach(r -> roles.add(JsonValue.str(r)));
        return JsonValue.object().put("id", p.id()).put("display", p.display()).put("roles", new JsonValue.JArray(roles))
                .build();
    }

    private static Reply me(ConsoleServer s, Ctx c) {
        ConsoleSessions.Session x = c.session;
        JsonValue.JObject.Builder b = JsonValue.object().put("person", person(x.person)).put("csrf", x.csrf)
                .put("session", x.tag())
                .put("idleExpiresAt", s.sessions.idleUntil(x).toString())
                .put("absoluteExpiresAt", s.sessions.absoluteUntil(x).toString())
                .put("stepUpFresh", JsonValue.bool(s.sessions.stepUpFresh(x)))
                .put("stepUpUntil", s.sessions.stepUpUntil(x).toString())
                .put("signing", JsonValue.object().put("notice", s.signer.notice()).build());
        return Reply.ok(b.build());
    }

    private static Reply modules(ConsoleServer s, Ctx c) {
        List<JsonValue> out = new ArrayList<>();
        Set<Role> roles = c.person().roles();
        if (ConsoleServer.satisfies(roles, Role.ANALYST)) {
            for (String[] m : BUILT_IN) {
                out.add(JsonValue.object().put("id", m[0]).put("title", m[1]).put("requires", Role.ANALYST.name())
                        .put("kind", "builtin").build());
            }
        }
        for (ConsoleModule m : s.modules()) {
            if (ConsoleServer.satisfiesModule(roles, m.minimum())) {
                out.add(JsonValue.object().put("id", m.id()).put("title", m.title()).put("requires", m.minimum().name())
                        .put("kind", "module").build());
            }
        }
        return Reply.ok(JsonValue.object().put("modules", new JsonValue.JArray(out)).build());
    }

    /** The lab's state as JSON text; {@code full} adds counts and the console's own health. */
    static String labJson(ConsoleServer s, boolean full) {
        LabRunner r = s.runner();
        JsonValue.JObject.Builder b = JsonValue.object().put("time", s.world().now().toString())
                .put("state", r == null ? "UNKNOWN" : r.state().name())
                .put("speed", r == null ? JsonValue.nul() : new JsonValue.JNumber(Double.toString(r.speed())))
                .put("failure", r == null || r.failure().isEmpty() ? JsonValue.nul()
                        : JsonValue.str(r.failure().get().getClass().getSimpleName()));
        if (full) {
            b.put("scriptStart", s.world().scriptStart.toString()).put("scriptEnd", s.world().scriptEnd.toString())
                    .put("counts", JsonValue.object().put("alertsRaised", JsonValue.num(s.world().raised.size()))
                            .put("ranked", JsonValue.num(s.world().rankedNow().size()))
                            .put("requestsDecided", JsonValue.num(s.world().requestsDecided())).build())
                    .put("console", JsonValue.object().put("auditFailures", JsonValue.num(s.audit.failures()))
                            .put("internalFailures", JsonValue.num(s.internalFailures()))
                            .put("sessions", JsonValue.num(s.sessions.size()))
                            .put("streams", JsonValue.num(s.hub.open())).build())
                    .put("audit", JsonValue.object().put("head", JsonValue.num(s.world().org.audit.head().sequence())).build());
        }
        return JsonWriter.write(b.build());
    }

    private static Reply stream(ConsoleServer s, Ctx c) throws Exception {
        if (!s.openStream(c.exchange, c.session.id)) {
            return Reply.error(503, "busy");
        }
        return Reply.handledElsewhere();
    }

    // ---- the SOC API ------------------------------------------------------------------------------------------

    private static Reply soc(ConsoleServer s, Ctx c, Function<SocChannel.Calls, SocChannel.Reply> call, String note) {
        Optional<SocChannel.Calls> calls = s.channel.forAnalyst(c.person().id());
        if (calls.isEmpty()) {
            return Reply.error(403, "forbidden");
        }
        SocChannel.Reply r = call.apply(calls.get());
        return PASS.contains(r.status()) ? Reply.rawJson(r.status(), r.body()).audited(note)
                : Reply.error(503, "unavailable").audited("unexpected SOC status " + r.status());
    }

    private static Reply note(ConsoleServer s, Ctx c) {
        String text = c.fields(Set.of("text")).text("text", MAX_NOTE);
        if (!cleanText(text)) {
            return Reply.error(400, "invalid request").audited("note has control or direction characters");
        }
        return soc(s, c, x -> x.note(c.params.get(0), text), "note of " + text.length() + " characters");
    }

    private static Reply assign(ConsoleServer s, Ctx c) {
        String assignee = ConsoleIds.plain(c.fields(Set.of("assignee")).text("assignee", 128));
        return soc(s, c, x -> x.assign(c.params.get(0), assignee), "assignee " + assignee);
    }

    private static Reply search(ConsoleServer s, Ctx c, boolean counts) {
        Ctx.Fields f = counts ? c.fields(Set.of("query", "from", "to")) : c.fields(Set.of("query", "from", "to", "limit"));
        String query = f.text("query", 2_000);
        SocChannel.Search q = new SocChannel.Search(query, f.time("from"), f.time("to"),
                counts ? 1 : (int) f.number("limit", 1, 1_000));
        String note = "query sha256 " + Digests.sha256Hex(query).substring(0, 16) + ", " + query.length() + " characters";
        return soc(s, c, counts ? x -> x.counts(q) : x -> x.search(q), note);
    }

    private static Reply verdict(ConsoleServer s, Ctx c) {
        Ctx.Fields f = c.fields(Set.of("alertId", "outcome"));
        String alertId = ConsoleIds.plain(f.text("alertId", 128));
        Verdict.Outcome outcome;
        try {
            outcome = Verdict.Outcome.valueOf(f.text("outcome", 20));
        } catch (IllegalArgumentException e) {
            return Reply.error(400, "invalid request");
        }
        Optional<Verdict> v = s.signer.sign(c.person().id(), alertId, outcome);
        if (v.isEmpty()) {
            return Reply.error(403, "this person has no signing key").audited("no signing key");
        }
        Optional<SocChannel.Calls> calls = s.channel.forAnalyst(c.person().id());
        if (calls.isEmpty()) {
            return Reply.error(403, "forbidden");
        }
        SocChannel.Reply r = calls.get().verdict(v.get());
        int status = PASS.contains(r.status()) ? r.status() : 503;
        JsonValue signature = JsonValue.object().put("signedBy", c.person().id()).put("keyId", v.get().proof().keyId())
                .put("signedAt", v.get().proof().signedAt().toString()).put("notice", s.signer.notice()).build();
        String body = "{\"socStatus\":" + r.status() + ",\"result\":" + r.body() + ",\"signature\":"
                + JsonWriter.write(signature) + "}";
        return Reply.rawJson(status, body).audited("alert " + alertId + " " + outcome + " -> SOC " + r.status() + ", key "
                + v.get().proof().keyId());
    }

    /** Free text for a note: letters, digits, punctuation, spaces, newlines and tabs; no controls, no direction marks. */
    static boolean cleanText(String t) {
        for (int i = 0; i < t.length(); ) {
            int cp = t.codePointAt(i);
            i += Character.charCount(cp);
            if (cp == 10 || cp == 9) {
                continue;
            }
            if (Character.isISOControl(cp) || cp == 0x2028 || cp == 0x2029 || cp == 0x200E || cp == 0x200F
                    || (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069) || cp == 0xFEFF
                    || (cp >= 0xD800 && cp <= 0xDFFF)) {
                return false;
            }
        }
        return true;
    }

    // ---- the audit explorer -----------------------------------------------------------------------------------

    /** A lead sees every record; an analyst sees the details of the console's and the SOC API's own records. */
    private static boolean detailVisible(ConsoleAuth.Person p, String type) {
        return p.roles().contains(Role.LEAD) || type.startsWith("CONSOLE_") || type.startsWith("SOCAPI_");
    }

    private static Reply auditHead(ConsoleServer s) {
        return Reply.ok(JsonValue.object().put("head", JsonValue.num(s.world().auditView.page(0, 1, Optional.empty()).head()))
                .build());
    }

    private static JsonValue entry(LabAudit.Entry e, boolean detail) {
        return JsonValue.object().put("sequence", JsonValue.num(e.sequence())).put("at", e.at().toString())
                .put("type", e.type()).put("actor", e.actor())
                .put("summary", detail ? e.summary() : "(details are for leads)").put("mac", e.mac()).build();
    }

    private static Reply auditPage(ConsoleServer s, Ctx c) {
        if (!s.auditReads.tryAcquire(c.person().id(), s.wall.instant())) {
            return Reply.error(429, "too many requests").withHeader("Retry-After", "60");
        }
        Map<String, String> q = c.query;
        long after = q.containsKey("after") ? Long.parseLong(q.get("after")) : 0;
        int limit = q.containsKey("limit") ? Integer.parseInt(q.get("limit")) : 100;
        Optional<String> type = Optional.ofNullable(q.get("type")).filter(t -> !t.isEmpty());
        if (type.isPresent() && !type.get().matches("[A-Za-z0-9_.:-]{1,64}")) {
            return Reply.error(400, "invalid request");
        }
        LabAudit.Page page = s.world().auditView.page(after, Math.min(limit, 200), type);
        List<JsonValue> out = new ArrayList<>();
        for (LabAudit.Entry e : page.entries()) {
            out.add(entry(e, detailVisible(c.person(), e.type())));
        }
        return Reply.ok(JsonValue.object().put("entries", new JsonValue.JArray(out)).put("head", JsonValue.num(page.head()))
                .put("more", JsonValue.bool(page.more())).build());
    }

    private static Reply auditRecord(ConsoleServer s, Ctx c) {
        long seq = Long.parseLong(c.params.get(0));
        Optional<LabAudit.Detail> d = s.world().auditView.record(seq);
        if (d.isEmpty()) {
            return Reply.error(404, "not found").audited("record " + seq);
        }
        boolean visible = detailVisible(c.person(), d.get().entry().type());
        return Reply.ok(JsonValue.object().put("entry", entry(d.get().entry(), visible))
                .put("payload", visible ? JsonValue.str(d.get().payloadJson()) : JsonValue.str("(withheld: for leads)"))
                .put("previousMac", d.get().previousMac()).build())
                .audited("record " + seq + " " + d.get().entry().type() + (visible ? "" : " (withheld)"));
    }

    private static Reply auditVerify(ConsoleServer s, Ctx c) {
        if (!s.auditVerifies.tryAcquire(c.person().id(), s.wall.instant())) {
            return Reply.error(429, "too many requests").withHeader("Retry-After", "60");
        }
        LabAudit.Verified v = s.world().auditView.verify();
        return Reply.ok(JsonValue.object().put("intact", JsonValue.bool(v.intact())).put("records", JsonValue.num(v.records()))
                .put("firstBad", JsonValue.num(v.firstBad())).put("reason", v.reason())
                .put("anchoredSeq", v.anchoredSeq().<JsonValue>map(JsonValue::num).orElse(JsonValue.nul()))
                .put("anchorAgrees", JsonValue.bool(v.anchorAgrees())).put("checkedAt", s.wall.instant().toString()).build())
                .audited("verify: " + (v.intact() ? "intact" : "BROKEN at " + v.firstBad()) + ", " + v.records() + " records");
    }
}

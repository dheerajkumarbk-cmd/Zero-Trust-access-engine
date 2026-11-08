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
            new String[]{"audit", "Audit explorer"}, new String[]{"attack", "ATT&CK"},
            new String[]{"scans", "Scans"});

    /**
     * How the passkey guards a route (only where the server has a passkey lock, and only for people whose role has one):
     * <ul>
     *   <li>WINDOW: the shared window; one passkey entry opens cases, entities and hunt together for a while;</li>
     *   <li>AUDIT: the audit explorer has its own, shorter unlock;</li>
     *   <li>EVERY_TIME: one passkey entry per action, whatever the windows say.</li>
     * </ul>
     */
    enum Gate { NONE, WINDOW, AUDIT, EVERY_TIME }

    /** Views of confidential data, opened by the shared window. */
    static final Set<String> WINDOW_ROUTES = Set.of("soc/cases/{}", "soc/cases/{}/timeline", "soc/risk/{}/{}", "soc/search");
    /** The audit explorer: a fresher unlock than the window. */
    static final Set<String> AUDIT_ROUTES = Set.of("audit/records", "audit/records/{}", "audit/verify");
    /** Report exports always ask; so does every route that needs a fresh step-up (response actions, administration). */
    static final Set<String> EVERY_TIME_ROUTES = Set.of("soc/reports/{}", "lab/export");

    static Gate gate(String pattern, boolean stepUp) {
        if (AUDIT_ROUTES.contains(pattern)) {
            return Gate.AUDIT;
        }
        if (stepUp || EVERY_TIME_ROUTES.contains(pattern)) {
            return Gate.EVERY_TIME;
        }
        return WINDOW_ROUTES.contains(pattern) ? Gate.WINDOW : Gate.NONE;
    }

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
        s.route("POST", "session/recover", Kind.PUBLIC, null, false, c -> recover(s, c));
        s.route("POST", "session/recover/code", Kind.PUBLIC, null, false, c -> recoverCode(s, c));
        s.route("POST", "session/unlock", Kind.READ, null, false, c -> unlock(s, c));
        s.route("POST", "session/lock", Kind.READ, null, false, c -> lock(s, c));
        s.route("POST", "session/elevate", Kind.WRITE, null, false, c -> startElevation(s, c));
        s.route("POST", "session/elevate/end", Kind.WRITE, null, false, c -> endElevation(s, c));
        s.route("GET", "session/list", Kind.READ, null, false, c -> sessionList(s, c));
        s.route("POST", "session/revoke", Kind.READ, null, false, c -> revoke(s, c));
        // ---- one's own sign-in
        s.route("GET", "profile", Kind.READ, null, false, c -> profile(s, c));
        s.route("POST", "profile/password", Kind.WRITE, null, false, c -> changePassword(s, c));
        s.route("POST", "profile/pin", Kind.WRITE, null, false, c -> changePin(s, c));
        s.route("POST", "profile/passkey", Kind.WRITE, null, false, c -> setPasskey(s, c));
        s.route("POST", "profile/backup-codes", Kind.WRITE, null, false, c -> backupCodes(s, c));
        // ---- identity, modules, lab, stream
        s.route("GET", "me", Kind.READ, null, false, c -> me(s, c));
        s.route("GET", "me/activity", Kind.READ, null, false, c -> activity(s, c));
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

        s.route("GET", "audit/head", Kind.READ, Role.ANALYST, false, c -> auditHead(s, c));
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

    // ---- one's own sign-in ---------------------------------------------------------------------------------------

    private static Reply profile(ConsoleServer s, Ctx c) {
        ConsoleAuth.Standing t = s.auth.standing(c.person().id());
        return Reply.ok(JsonValue.object().put("person", person(c.person()))
                .put("passwordChanged", t.passwordChanged().toString()).put("pinChanged", t.pinChanged().toString())
                .put("changeBy", t.changeBy().toString()).put("changeDue", JsonValue.bool(t.due()))
                .put("rotationDays", JsonValue.num(t.rotationDays())).put("passkeySet", JsonValue.bool(t.passkeySet()))
                .put("passkeyNeeded", JsonValue.bool(needsPasskey(c.person())))
                .put("passkeyLock", JsonValue.bool(s.passkeyWindow != null))
                .put("unlocked", JsonValue.bool(s.sessions.unlocked(c.session)))
                .put("unlockedSeconds", JsonValue.num(s.sessions.unlockedSeconds(c.session)))
                .put("auditSeconds", JsonValue.num(s.sessions.auditSeconds(c.session)))
                .put("backupCodesLeft", JsonValue.num(t.backupCodesLeft())).build());
    }

    private static Reply changed(ConsoleServer s, Ctx c, ConsoleAuth.Changed r, String what, boolean endOthers) {
        return switch (r.status()) {
            case OK -> {
                if (endOthers) {
                    endSessions(s, c.person().id(), c.session.id);
                }
                yield Reply.ok(JsonValue.object().put("ok", JsonValue.bool(true)).build()).audited(what + " changed");
            }
            case LOCKED -> locked(r.retryAfterSeconds());
            case WEAK -> Reply.error(400, "the new value is too short, too simple or the same as the old one").audited("weak " + what);
            case DENIED -> Reply.error(401, "wrong password or PIN").audited("wrong proof for " + what);
            case UNAVAILABLE -> Reply.error(503, "unavailable").audited("the credentials file could not be written");
        };
    }

    /** A changed secret means any other open session may be the person who stole the old one. */
    private static void endSessions(ConsoleServer s, String person, String keep) {
        for (ConsoleSessions.Session x : s.sessions.of(person)) {
            if (!x.id.equals(keep)) {
                s.sessions.end(x.id);
                s.hub.closeSession(x.id);
            }
        }
    }

    private static Reply changePassword(ConsoleServer s, Ctx c) {
        Ctx.Fields f = c.fields(Set.of("password", "pin", "newPassword"));
        return changed(s, c, s.auth.changePassword(c.person().id(), f.text("password", 1024), f.text("pin", 64),
                f.text("newPassword", 1024), c.source), "password", true);
    }

    private static Reply changePin(ConsoleServer s, Ctx c) {
        Ctx.Fields f = c.fields(Set.of("password", "pin", "newPin"));
        return changed(s, c, s.auth.changePin(c.person().id(), f.text("password", 1024), f.text("pin", 64),
                f.text("newPin", 64), c.source), "PIN", true);
    }

    /** Only people whose role opens confidential views have anything for a passkey to protect. */
    static boolean needsPasskey(ConsoleAuth.Person p) {
        return ConsoleServer.satisfiesModule(p.roles(), Role.ANALYST);
    }

    private static Reply setPasskey(ConsoleServer s, Ctx c) {
        if (!needsPasskey(c.person())) {
            return Reply.error(403, "your role opens nothing confidential, so it needs no passkey");
        }
        Ctx.Fields f = c.fields(Set.of("password", "pin", "passkey"));
        return changed(s, c, s.auth.setPasskey(c.person().id(), f.text("password", 1024), f.text("pin", 64),
                f.text("passkey", 1024), c.source), "passkey", false);
    }

    private static Reply backupCodes(ConsoleServer s, Ctx c) {
        Ctx.Fields f = c.fields(Set.of("password", "pin"));
        ConsoleAuth.Changed[] result = new ConsoleAuth.Changed[1];
        Optional<List<String>> codes = s.auth.newBackupCodes(c.person().id(), f.text("password", 1024), f.text("pin", 64),
                c.source, result);
        if (codes.isEmpty()) {
            return changed(s, c, result[0], "backup codes", false);
        }
        List<JsonValue> out = new ArrayList<>();
        codes.get().forEach(x -> out.add(JsonValue.str(x)));
        return Reply.ok(JsonValue.object().put("codes", new JsonValue.JArray(out)).build()).audited("new backup codes");
    }

    /** How long a passkey given for one risky action stays good if the action does not follow at once. */
    static final java.time.Duration ONCE_TTL = java.time.Duration.ofSeconds(60);

    private static Reply unlock(ConsoleServer s, Ctx c) {
        if (s.passkeyWindow == null) {
            return Reply.error(404, "not found");
        }
        String passkey;
        String scope;
        try {
            Ctx.Fields f = c.fields(Set.of("passkey", "scope"));
            passkey = f.text("passkey", 1024);
            scope = f.text("scope", 10);
        } catch (dev.dwarpal.wire.JsonException withoutScope) {
            passkey = c.fields(Set.of("passkey")).text("passkey", 1024);
            scope = "window";
        }
        if (!Set.of("window", "audit", "once").contains(scope)) {
            return Reply.error(400, "invalid request");
        }
        ConsoleAuth.Authenticated a = s.passkeys.verify(c.person().id(), passkey, c.source);
        if (a.status() != ConsoleAuth.Status.OK) {
            s.audit.write("CONSOLE_UNLOCK_FAILED", c.person().id(), ConsoleServer.fields("session", c.session.tag(), "scope", scope));
            return a.status() == ConsoleAuth.Status.LOCKED ? locked(a.retryAfterSeconds()) : Reply.error(401, "wrong passkey");
        }
        switch (scope) {
            case "audit" -> s.sessions.unlockAudit(c.session, s.auditWindow, s.passkeyWindow);
            case "once" -> s.sessions.grantOnce(c.session, ONCE_TTL);
            default -> s.sessions.unlock(c.session, s.passkeyWindow);
        }
        if (!s.audit.write("CONSOLE_UNLOCK", c.person().id(), ConsoleServer.fields("session", c.session.tag(), "scope", scope))) {
            return Reply.error(503, "audit trail unavailable");
        }
        return Reply.ok(JsonValue.object().put("ok", JsonValue.bool(true))
                .put("unlockedSeconds", JsonValue.num(s.sessions.unlockedSeconds(c.session)))
                .put("auditSeconds", JsonValue.num(s.sessions.auditSeconds(c.session))).build());
    }

    /**
     * An elevation: the privileged actions of the access process (a decision on a grant, a joiner, an administrator change)
     * are allowed for ten real minutes after the person gives their PIN, their passkey and a reason. Everything done inside
     * it is written under its identifier. Both secrets are always checked, so a refusal does not say which one was wrong.
     */
    private static Reply startElevation(ConsoleServer s, Ctx c) {
        if (!ConsoleServer.satisfiesModule(c.person().roles(), Role.LEAD)) {
            return Reply.error(403, "your role has no privileged actions");
        }
        Ctx.Fields f = c.fields(Set.of("pin", "passkey", "reason"));
        String pin = f.text("pin", 64);
        String passkey = f.text("passkey", 1024);
        String reason = f.text("reason", 300).strip();
        if (reason.length() < 5 || reason.length() > 200) {
            return Reply.error(400, "give a reason of 5 to 200 characters");
        }
        String id = c.person().id();
        ConsoleAuth.Authenticated byPin = s.auth.checkPin(id, pin, c.source);
        ConsoleAuth.Authenticated byKey = s.passkeys.verify(id, passkey, c.source);
        if (byPin.status() != ConsoleAuth.Status.OK || byKey.status() != ConsoleAuth.Status.OK) {
            s.audit.write("ELEVATION_FAILED", id, ConsoleServer.fields("session", c.session.tag()));
            long wait = Math.max(byPin.retryAfterSeconds(), byKey.retryAfterSeconds());
            return wait > 0 ? locked(wait) : Reply.error(401, "wrong PIN or passkey");
        }
        ConsoleModule.Elevation e = s.sessions.elevate(c.session, reason, s.elevationLength);
        if (!s.audit.write("ELEVATION_STARTED", id, ConsoleServer.fields("elevation", e.id(), "session", c.session.tag(),
                "reason", reason, "until", e.until().toString(), "minutes", Long.toString(s.elevationLength.toMinutes())))) {
            s.sessions.endElevation(c.session);
            return Reply.error(503, "audit trail unavailable");
        }
        return Reply.ok(JsonValue.object().put("ok", JsonValue.bool(true)).put("elevation", elevationJson(s, c.session)).build());
    }

    /** The person closes the elevation before its time is up. */
    private static Reply endElevation(ConsoleServer s, Ctx c) {
        ConsoleModule.Elevation e = s.sessions.endElevation(c.session);
        if (e != null) {
            s.audit.write("ELEVATION_ENDED", c.person().id(), ConsoleServer.fields("elevation", e.id(), "session", c.session.tag(),
                    "how", "ended by the person", "reason", e.reason(), "until", e.until().toString()));
        }
        return Reply.ok(JsonValue.object().put("ok", JsonValue.bool(true)).build());
    }

    static JsonValue elevationJson(ConsoleServer s, ConsoleSessions.Session x) {
        ConsoleModule.Elevation e = s.sessions.elevation(x);
        if (e == null) {
            return JsonValue.object().put("open", JsonValue.bool(false)).build();
        }
        return JsonValue.object().put("open", JsonValue.bool(true)).put("id", e.id()).put("reason", e.reason())
                .put("seconds", JsonValue.num(s.sessions.elevationSeconds(x))).build();
    }

    /** Closes everything the passkey opened, now (the footer has a Lock now button). */
    private static Reply lock(ConsoleServer s, Ctx c) {
        boolean wasOpen = s.sessions.unlocked(c.session) || s.sessions.auditOpen(c.session);
        s.sessions.lock(c.session);
        if (wasOpen) {
            s.audit.write("CONSOLE_LOCK", c.person().id(), ConsoleServer.fields("session", c.session.tag()));
        }
        return Reply.ok(JsonValue.object().put("ok", JsonValue.bool(true)).build());
    }

    private static Reply recoverCode(ConsoleServer s, Ctx c) {
        Ctx.Fields f = c.fields(Set.of("user", "code"));
        String user = f.text("user", 128);
        ConsoleAuth.Recovering r = s.auth.checkBackupCode(user, f.text("code", 64), c.source);
        return switch (r.status()) {
            case OK -> Reply.ok(JsonValue.object().put("ticket", r.ticket())
                    .put("expiresInSeconds", JsonValue.num(ConsoleAuth.RECOVERY_VALID.toSeconds())).build());
            case LOCKED -> {
                loginFailed(s, user, c, "backup code locked");
                yield locked(r.retryAfterSeconds());
            }
            default -> {
                loginFailed(s, user, c, "wrong backup code");
                yield Reply.error(401, "recovery failed");
            }
        };
    }

    private static Reply recover(ConsoleServer s, Ctx c) {
        Ctx.Fields f = c.fields(Set.of("ticket", "newPassword", "newPin"));
        String ticket = f.text("ticket", 64);
        Optional<String> who = s.auth.recoveryOf(ticket);
        ConsoleAuth.Changed r = s.auth.recover(ticket, f.text("newPassword", 1024), f.text("newPin", 64), c.source);
        switch (r.status()) {
            case OK -> {
                endSessions(s, who.orElseThrow(), "");
                s.audit.write("CONSOLE_RECOVERED", who.orElseThrow(), ConsoleServer.fields("source", c.source));
                return Reply.ok(JsonValue.object().put("ok", JsonValue.bool(true)).build());
            }
            case WEAK -> {
                return Reply.error(400, "the new password or PIN is too short or too simple");
            }
            case UNAVAILABLE -> {
                return Reply.error(503, "unavailable");
            }
            default -> {
                return Reply.error(401, "recovery failed");
            }
        }
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
                .put("changeDue", JsonValue.bool(s.auth.changeDue(x.person.id())))
                .put("passkeySet", JsonValue.bool(s.auth.standing(x.person.id()).passkeySet()))
                .put("passkeyNeeded", JsonValue.bool(needsPasskey(x.person)))
                .put("unlocked", JsonValue.bool(s.sessions.unlocked(x)))
                .put("unlockedSeconds", JsonValue.num(s.sessions.unlockedSeconds(x)))
                .put("auditSeconds", JsonValue.num(s.sessions.auditSeconds(x)))
                .put("elevationAllowed", JsonValue.bool(ConsoleServer.satisfiesModule(x.person.roles(), Role.LEAD)))
                .put("elevation", elevationJson(s, x))
                .put("signing", JsonValue.object().put("notice", s.signer.notice()).build());
        return Reply.ok(b.build());
    }

    /** Sign-ins and changes to the person's own account, and nobody else's. */
    private static Reply activity(ConsoleServer s, Ctx c) {
        List<JsonValue> out = new ArrayList<>();
        for (ConsoleAudit.Activity a : s.audit.activity(c.person().id())) {
            out.add(JsonValue.object().put("at", a.at().toString()).put("what", a.what()).build());
        }
        return Reply.ok(JsonValue.object().put("activity", new JsonValue.JArray(out)).build());
    }

    private static Reply modules(ConsoleServer s, Ctx c) {
        List<JsonValue> out = new ArrayList<>();
        Set<Role> roles = c.person().roles();
        if (!needsPasskey(c.person())) {
            out.add(JsonValue.object().put("id", "home").put("title", "Home").put("requires", Role.USER.name())
                    .put("kind", "builtin").build());
        }
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

    /** Record types of the vault (stage 6). Analysts cannot read them at all; a lead sees what was done and on whom. */
    static final String VAULT_PREFIX = "VAULT_";
    /** The only payload fields of a vault record a lead may see; who acted and when are the record's own actor and time. */
    private static final List<String> VAULT_LEAD_FIELDS = List.of("action", "target");

    /** A lead sees every record; an analyst sees the details of the console's and the SOC API's own records. */
    private static boolean detailVisible(ConsoleAuth.Person p, String type) {
        return p.roles().contains(Role.LEAD) || type.startsWith("CONSOLE_") || type.startsWith("SOCAPI_");
    }

    static boolean isVault(String type) {
        return type.startsWith(VAULT_PREFIX);
    }

    /** Whether this person may know a record of this type exists at all: vault events are for leads only. */
    static boolean listed(ConsoleAuth.Person p, String type) {
        return !isVault(type) || p.roles().contains(Role.LEAD);
    }

    /** The part of a vault record a lead may see, as a small JSON object text; never anything else from the payload. */
    static String vaultLeadView(String payloadJson) {
        Map<String, String> out = new java.util.LinkedHashMap<>();
        try {
            if (new dev.dwarpal.wire.JsonReader().read(payloadJson) instanceof JsonValue.JObject o) {
                for (String k : VAULT_LEAD_FIELDS) {
                    if (o.get(k).orElse(null) instanceof JsonValue.JString v) {
                        out.put(k, v.value());
                    }
                }
            }
        } catch (RuntimeException e) {
            return "{}";
        }
        return dev.dwarpal.audit.Json.object(out);
    }

    /** The explorer reads the lab's simulated chain, or (when this run keeps one) the console's saved trail. */
    private static Optional<LabAudit> source(ConsoleServer s, Ctx c) {
        return switch (c.query.getOrDefault("source", "lab")) {
            case "lab" -> Optional.of(s.world().auditView);
            case "console" -> Optional.ofNullable(s.trail).map(ConsoleTrail::view);
            default -> Optional.empty();
        };
    }

    private static Reply auditHead(ConsoleServer s, Ctx c) {
        Optional<LabAudit> view = source(s, c);
        if (view.isEmpty()) {
            return Reply.error(404, "not found");
        }
        List<JsonValue> sources = new ArrayList<>(List.of(JsonValue.str("lab")));
        if (s.trail != null) {
            sources.add(JsonValue.str("console"));
        }
        return Reply.ok(JsonValue.object().put("head", JsonValue.num(view.get().page(0, 1, Optional.empty()).head()))
                .put("sources", new JsonValue.JArray(sources)).build());
    }

    private static JsonValue entry(LabAudit.Entry e, String summary) {
        return JsonValue.object().put("sequence", JsonValue.num(e.sequence())).put("at", e.at().toString())
                .put("type", e.type()).put("actor", e.actor()).put("summary", summary).put("mac", e.mac()).build();
    }

    private static JsonValue entry(LabAudit.Entry e, boolean detail) {
        return entry(e, detail ? e.summary() : "(details are for leads)");
    }

    private static Reply auditPage(ConsoleServer s, Ctx c) {
        if (!s.auditReads.tryAcquire(c.person().id(), s.wall.instant())) {
            return Reply.error(429, "too many requests").withHeader("Retry-After", "60");
        }
        Optional<LabAudit> view = source(s, c);
        if (view.isEmpty()) {
            return Reply.error(404, "not found");
        }
        Map<String, String> q = c.query;
        long after = q.containsKey("after") ? Long.parseLong(q.get("after")) : 0;
        int limit = q.containsKey("limit") ? Integer.parseInt(q.get("limit")) : 100;
        Optional<String> type = Optional.ofNullable(q.get("type")).filter(t -> !t.isEmpty());
        if (type.isPresent() && !type.get().matches("[A-Za-z0-9_.:-]{1,64}")) {
            return Reply.error(400, "invalid request");
        }
        LabAudit.Page page = view.get().page(after, Math.min(limit, 200), type);
        List<JsonValue> out = new ArrayList<>();
        for (LabAudit.Entry e : page.entries()) {
            if (!listed(c.person(), e.type())) {
                continue;
            }
            if (isVault(e.type())) {
                String shown = view.get().record(e.sequence()).map(d -> vaultLeadView(d.payloadJson())).orElse("{}");
                out.add(entry(e, shown));
            } else {
                out.add(entry(e, detailVisible(c.person(), e.type())));
            }
        }
        return Reply.ok(JsonValue.object().put("entries", new JsonValue.JArray(out)).put("head", JsonValue.num(page.head()))
                .put("more", JsonValue.bool(page.more())).build());
    }

    private static Reply auditRecord(ConsoleServer s, Ctx c) {
        long seq = Long.parseLong(c.params.get(0));
        Optional<LabAudit> view = source(s, c);
        Optional<LabAudit.Detail> d = view.flatMap(v -> v.record(seq));
        // a vault record is, for anybody who may not read it, a record that does not exist
        if (d.isEmpty() || !listed(c.person(), d.get().entry().type())) {
            return Reply.error(404, "not found").audited("record " + seq);
        }
        if (isVault(d.get().entry().type())) {
            String shown = vaultLeadView(d.get().payloadJson());
            return Reply.ok(JsonValue.object().put("entry", entry(d.get().entry(), shown)).put("payload", JsonValue.str(shown))
                    .put("previousMac", d.get().previousMac()).build()).audited("record " + seq + " (vault)");
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
        Optional<LabAudit> view = source(s, c);
        if (view.isEmpty()) {
            return Reply.error(404, "not found");
        }
        LabAudit.Verified v = view.get().verify();
        return Reply.ok(JsonValue.object().put("intact", JsonValue.bool(v.intact())).put("records", JsonValue.num(v.records()))
                .put("firstBad", JsonValue.num(v.firstBad())).put("reason", v.reason())
                .put("anchoredSeq", v.anchoredSeq().<JsonValue>map(JsonValue::num).orElse(JsonValue.nul()))
                .put("anchorAgrees", JsonValue.bool(v.anchorAgrees())).put("checkedAt", s.wall.instant().toString()).build())
                .audited("verify: " + (v.intact() ? "intact" : "BROKEN at " + v.firstBad()) + ", " + v.records() + " records");
    }
}

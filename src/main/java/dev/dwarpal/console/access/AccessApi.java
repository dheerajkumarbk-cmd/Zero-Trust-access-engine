package dev.dwarpal.console.access;

import dev.dwarpal.console.ConsoleModule;
import dev.dwarpal.console.ConsoleModule.Response;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.console.lab.ModuleKit;
import dev.dwarpal.directory.Access;
import dev.dwarpal.directory.AccessGrant;
import dev.dwarpal.directory.AccessItem;
import dev.dwarpal.directory.AccessRequest;
import dev.dwarpal.directory.CredentialLifecycle;
import dev.dwarpal.directory.Directory;
import dev.dwarpal.directory.DirectoryPerson;
import dev.dwarpal.wire.JsonValue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * What the console says and does about the access process, shared by the two modules that show it: {@code access}
 * (a person's own access, HR's requests, a lead's approvals) and the administrator's section of {@code admin}. The
 * rules live in {@link Access}; this class only shapes requests and answers, refuses what a role may not do, writes
 * every grant, approval and removal into the audit trail, and ends a leaver's sessions.
 *
 * <p>Roles are checked strictly here: the host lets an administrator through a lead-level route, but an administrator
 * is not a lead, and a lead's approval is a lead's.
 */
public final class AccessApi {

    private static final Set<String> BODY_REQUEST = Set.of("items", "reason");
    private static final Set<String> BODY_JOINER = Set.of("id", "name", "department", "businessRole", "reason");
    private static final Set<String> BODY_LEAVER = Set.of("id", "reason");
    private static final Set<String> BODY_SAVE = Set.of("items");
    private static final Set<String> BODY_REASON = Set.of("reason");
    private static final Set<String> BODY_DECISION = Set.of("approve", "reason");

    private final Access access;
    private final Directory directory;
    private final CredentialLifecycle credentials;
    private volatile ConsoleModule.Host host;

    public AccessApi(Access access, Directory directory, CredentialLifecycle credentials) {
        this.access = Objects.requireNonNull(access, "access");
        this.directory = Objects.requireNonNull(directory, "directory");
        this.credentials = Objects.requireNonNull(credentials, "credentials");
    }

    /** The console gives the module its way to the audit trail and to ending sessions. */
    public void attach(ConsoleModule.Host h) {
        host = Objects.requireNonNull(h, "host");
    }

    // ---- reads ---------------------------------------------------------------------------------------------------------

    public Response catalog() {
        return ModuleKit.json(Map.of("items", access.catalog(), "templates", access.templates()));
    }

    /** A person's own access: what they hold, what they asked for, and what they could still ask for. */
    public Response mine(ConsoleModule.Request r) {
        String me = r.who().id();
        List<AccessGrant> grants = access.grantsOf(me);
        Set<String> held = new LinkedHashSet<>();
        for (AccessGrant g : grants) {
            if (g.state() == AccessGrant.State.ACTIVE || g.state() == AccessGrant.State.PENDING) {
                held.add(g.itemId());
            }
        }
        List<AccessItem> available = new ArrayList<>();
        for (AccessItem item : access.catalog()) {
            boolean roleHeld = item.consoleRole() != null && r.who().roles().stream().anyMatch(x -> x.name().equals(item.consoleRole()));
            if (!held.contains(item.id()) && !roleHeld) {
                available.add(item);
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("grants", grants);
        out.put("requests", access.requestsOf(me));
        out.put("available", available);
        out.put("catalog", access.catalog());
        out.put("roles", r.who().roles().stream().map(Enum::name).sorted().toList());
        return ModuleKit.json(out);
    }

    /** HR sees who can leave (active people other than themselves and the administrator) and their own requests. */
    public Response hrOverview(ConsoleModule.Request r) {
        requireRole(r, Role.HR);
        List<Map<String, String>> people = new ArrayList<>();
        for (DirectoryPerson p : directory.people()) {
            boolean admin = p.consoleRoles().contains("ADMIN");
            if (p.status() == DirectoryPerson.Status.ACTIVE && !admin && !p.id().equals(r.who().id())) {
                Map<String, String> m = new LinkedHashMap<>();
                m.put("id", p.id());
                m.put("name", p.displayName());
                m.put("department", p.department());
                m.put("businessRole", p.businessRole());
                people.add(m);
            }
        }
        List<AccessRequest> mine = access.requestsOf(r.who().id());
        return ModuleKit.json(Map.of("people", people, "requests", mine, "templates", access.templates(),
                "roles", access.templates().keySet().stream().sorted().toList()));
    }

    /** The grants waiting for a lead. Only a lead sees them (an administrator is not a lead). */
    public Response leadApprovals(ConsoleModule.Request r) {
        requireRole(r, Role.LEAD);
        return ModuleKit.json(Map.of("waiting", views(access.awaiting("LEAD"), r.who().id()), "catalog", access.catalog()));
    }

    /** The administrator's section: joiners to decide, hard grants waiting for the administrator, and recent history. */
    public Response adminQueue(ConsoleModule.Request r) {
        requireRole(r, Role.ADMIN);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("joiners", access.openJoiners());
        out.put("waiting", views(access.awaiting("ADMIN"), r.who().id()));
        out.put("recent", access.recent());
        out.put("catalog", access.catalog());
        out.put("templates", access.templates());
        return ModuleKit.json(out);
    }

    // ---- changes -------------------------------------------------------------------------------------------------------

    public Response requestMore(ConsoleModule.Request r) {
        JsonValue.JObject body = ModuleKit.body(r, BODY_REQUEST);
        Set<String> items = strings(body, "items");
        String reason = ModuleKit.string(body, "reason").orElse(null);
        return changed(() -> access.requestAccess(r.who().id(), items, reason));
    }

    public Response submitJoiner(ConsoleModule.Request r) {
        requireRole(r, Role.HR);
        JsonValue.JObject b = ModuleKit.body(r, BODY_JOINER);
        return changed(() -> access.submitJoiner(r.who().id(), ModuleKit.string(b, "id").orElse(null),
                ModuleKit.string(b, "name").orElse(null), ModuleKit.string(b, "department").orElse(null),
                ModuleKit.string(b, "businessRole").orElse(null), ModuleKit.string(b, "reason").orElse(null)));
    }

    public Response submitLeaver(ConsoleModule.Request r) {
        requireRole(r, Role.HR);
        JsonValue.JObject b = ModuleKit.body(r, BODY_LEAVER);
        String person = ModuleKit.string(b, "id").orElse(null);
        Response response = changed(() -> access.leaver(r.who().id(), person, ModuleKit.string(b, "reason").orElse(null)));
        if (response.status() == 200) {
            // the database says the person has left: now nothing of theirs can be used
            ConsoleModule.Host h = host;
            if (h != null) {
                h.closeAccount(person);
            }
            credentials.personRemoved(person);
        }
        return response;
    }

    public Response saveJoiner(ConsoleModule.Request r, String requestId) {
        requireRole(r, Role.ADMIN);
        Set<String> items = strings(ModuleKit.body(r, BODY_SAVE), "items");
        Response response = changed(() -> access.saveJoiner(r.who().id(), requestId, items));
        if (response.status() == 200) {
            access.request(requestId).ifPresent(q -> credentials.personCreated(q.subjectId()));
        }
        return response;
    }

    public Response rejectJoiner(ConsoleModule.Request r, String requestId) {
        requireRole(r, Role.ADMIN);
        JsonValue.JObject b = ModuleKit.body(r, BODY_REASON);
        return changed(() -> access.rejectJoiner(r.who().id(), requestId, ModuleKit.string(b, "reason").orElse(null)));
    }

    /** An approval as the administrator or as a lead: strictly the role asked for, never a higher one standing in. */
    public Response decide(ConsoleModule.Request r, String grantId, Role as) {
        requireRole(r, as);
        JsonValue.JObject b = ModuleKit.body(r, BODY_DECISION);
        boolean approve = ModuleKit.bool(b, "approve").orElseThrow(() -> new ModuleKit.Refusal(400, "say whether you approve"));
        return changed(() -> access.decide(r.who().id(), as.name(), grantId, approve, ModuleKit.string(b, "reason").orElse(null)));
    }

    // ---- helpers ---------------------------------------------------------------------------------------------------------

    private static void requireRole(ConsoleModule.Request r, Role role) {
        if (!r.who().has(role)) {
            throw new ModuleKit.Refusal(403, "not allowed for your role");
        }
    }

    private static Set<String> strings(JsonValue.JObject body, String key) {
        Set<String> out = new LinkedHashSet<>();
        JsonValue v = body.get(key).orElse(null);
        if (!(v instanceof JsonValue.JArray a)) {
            throw new ModuleKit.Refusal(400, key + " must be a list");
        }
        for (int i = 0; i < a.size(); i++) {
            if (!(a.get(i) instanceof JsonValue.JString s) || s.value().length() > 40) {
                throw new ModuleKit.Refusal(400, key + " must be a list of item names");
            }
            out.add(s.value());
        }
        return out;
    }

    private List<Map<String, Object>> views(List<Access.Awaiting> waiting, String viewer) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Access.Awaiting w : waiting) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("grant", w.grant());
            m.put("request", w.request());
            // the one who asked, and the person it is for, may see it but not decide it
            m.put("canDecide", !w.request().requestedBy().equals(viewer) && !w.grant().personId().equals(viewer));
            out.add(m);
        }
        return out;
    }

    /** Runs a change, writes its audit records (one per grant, approval and removal) and answers. */
    private Response changed(Supplier<Access.AccessResult> change) {
        Access.AccessResult result;
        try {
            result = change.get();
        } catch (Access.Refused refused) {
            int status = switch (refused.code()) {
                case INVALID -> 400;
                case NOT_FOUND -> 404;
                case FORBIDDEN -> 403;
                case CONFLICT -> 409;
            };
            return Response.error(status, refused.getMessage());
        }
        int failed = 0;
        ConsoleModule.Host h = host;
        for (Access.AccessEvent e : result.events()) {
            if (h == null || !h.audit(e.type(), e.actor(), e.fields())) {
                failed++;
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("request", result.request());
        out.put("grants", result.grants());
        // a record that could not be written is reported, never hidden
        out.put("auditFailures", failed);
        return ModuleKit.json(out);
    }
}

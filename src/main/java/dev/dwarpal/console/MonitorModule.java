package dev.dwarpal.console;

import dev.dwarpal.console.lab.ModuleKit;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The monitoring page (id {@code monitor}), read only. Two views over the audit trail, and neither can change it:
 * <pre>
 *   GET me      which views this person has
 *   GET admins  ADMIN only: what the OTHER administrators did (access decisions, elevations, sign-ins, changes; not plain page views)
 *   GET team    LEAD: team activity, filtered and paged (person, type, before); administrators see all but themself, other leads all non-administrators but themself
 *   GET vault   LEAD only: the limited vault log (who, when, on whom, what kind of action; never the secret)
 * </pre>
 * Each administrator watches the other one, and an administrator is never shown their own actions here as "the other's".
 * A person who may not use a view gets "not found" for it, as for any vault record elsewhere. A vault record of the other administrator shows
 * in their list as what it is (the action and on whom), never the reason or the secret; the vault view shows only those two
 * fields as well.
 */
public final class MonitorModule implements ConsoleModule {

    private static final int SHOWN = 200;
    private static final int SCANNED = 2_000;
    private static final int TEAM_PAGE = 100;
    /** Housekeeping fields that say nothing about what was done. */
    private static final Set<String> QUIET = Set.of("session", "source", "real", "scenario", "mac");

    private final Supplier<Set<String>> administrators;
    private final Supplier<Set<String>> people;
    private Host host;

    /** @param administrators the ids of the people who are administrators now (read at every call, so a change shows at once) */
    public MonitorModule(Supplier<Set<String>> administrators) {
        this(administrators, administrators);
    }

    /**
     * @param administrators the ids of the people who are administrators now
     * @param people the ids of the people (not machines) whose actions Team activity may show; fail closed: with the one-argument constructor only administrators
     */
    public MonitorModule(Supplier<Set<String>> administrators, Supplier<Set<String>> people) {
        this.administrators = administrators;
        this.people = people;
    }

    @Override
    public String id() {
        return "monitor";
    }

    @Override
    public String title() {
        return "Monitoring";
    }

    @Override
    public Role minimum() {
        return Role.LEAD;
    }

    @Override
    public void attach(Host h) {
        this.host = h;
    }

    @Override
    public void routes(Routes routes) {
        routes.get("me", Role.LEAD, ModuleKit.guard(Role.LEAD, (r, p) -> ModuleKit.json(Map.of(
                "admin", r.who().has(Role.ADMIN), "lead", r.who().has(Role.LEAD)))));
        routes.get("admins", Role.LEAD, ModuleKit.guard(Role.LEAD, this::admins));
        routes.get("vault", Role.LEAD, ModuleKit.guard(Role.LEAD, this::vault));
        routes.get("team", Role.LEAD, ModuleKit.guard(Role.LEAD, this::team));
    }

    /**
     * Team activity: what team members did, newest first, 100 rows a page, over the latest {@value #SCANNED} records.
     * An administrator sees every actor but themself; a lead who is not an administrator sees every actor who is neither an
     * administrator nor themself (the host has no way to tell analysts from other non-administrators). Plain page views are left out.
     */
    private Response team(Request r, List<String> p) {
        for (String k : r.query().keySet()) {
            if (!k.equals("person") && !k.equals("type") && !k.equals("before")) {
                return Response.error(400, "invalid request");
            }
        }
        String person = r.query().get("person");
        String type = r.query().get("type");
        String beforeText = r.query().get("before");
        if (person != null && !person.matches("[a-z][a-z0-9._-]{1,31}")) {
            return Response.error(400, "invalid request");
        }
        if (type != null && !type.matches("[A-Z_]{1,40}")) {
            return Response.error(400, "invalid request");
        }
        long before = Long.MAX_VALUE;
        if (beforeText != null) {
            if (!beforeText.matches("[0-9]{1,18}")) {
                return Response.error(400, "invalid request");
            }
            before = Long.parseLong(beforeText);
        }
        boolean admin = r.who().has(Role.ADMIN);
        Set<String> admins = administrators.get();
        Set<String> known = people.get();
        String me = r.who().id();
        java.util.TreeSet<String> persons = new java.util.TreeSet<>();
        java.util.TreeSet<String> types = new java.util.TreeSet<>();
        List<Map<String, Object>> rows = new ArrayList<>();
        boolean more = false;
        for (Host.AuditRow a : host.auditTail(SCANNED)) {
            String actor = a.actor();
            if (actor == null || !known.contains(actor) || actor.equals(me) || "CONSOLE_VIEW".equals(a.type()) || (!admin && admins.contains(actor))) {
                continue;
            }
            persons.add(actor);
            types.add(a.type());
            if (a.sequence() >= before || (person != null && !person.equals(actor)) || (type != null && !type.equals(a.type()))) {
                continue;
            }
            if (rows.size() == TEAM_PAGE) {
                more = true;
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("sequence", a.sequence());
            row.put("at", a.at().toString());
            row.put("actor", actor);
            row.put("type", a.type());
            row.put("what", ConsoleRoutes.isVault(a.type()) ? what(ConsoleRoutes.vaultLeadView(a.payloadJson())) : what(a.payloadJson()));
            rows.add(row);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("rows", rows);
        out.put("next", more ? rows.get(rows.size() - 1).get("sequence") : null);
        out.put("persons", persons);
        out.put("types", types);
        out.put("window", SCANNED);
        return ModuleKit.json(out);
    }

    private Response admins(Request r, List<String> p) {
        if (!r.who().has(Role.ADMIN)) {
            return Response.error(404, "not found");
        }
        Set<String> others = new java.util.TreeSet<>(administrators.get());
        others.remove(r.who().id());
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Host.AuditRow a : host.auditTail(SCANNED)) {
            if (rows.size() == SHOWN) {
                break;
            }
            if (!others.contains(a.actor()) || "CONSOLE_VIEW".equals(a.type())) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("sequence", a.sequence());
            row.put("at", a.at().toString());
            row.put("actor", a.actor());
            row.put("type", a.type());
            row.put("what", ConsoleRoutes.isVault(a.type()) ? what(ConsoleRoutes.vaultLeadView(a.payloadJson())) : what(a.payloadJson()));
            rows.add(row);
        }
        return ModuleKit.json(Map.of("administrators", others, "actions", rows));
    }

    private Response vault(Request r, List<String> p) {
        if (!r.who().has(Role.LEAD)) {
            return Response.error(404, "not found");
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Host.AuditRow a : host.auditTail(SCANNED)) {
            if (rows.size() == SHOWN) {
                break;
            }
            if (!ConsoleRoutes.isVault(a.type())) {
                continue;
            }
            Map<String, String> shown = fields(ConsoleRoutes.vaultLeadView(a.payloadJson()));
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("sequence", a.sequence());
            row.put("at", a.at().toString());
            row.put("who", a.actor());
            row.put("action", shown.getOrDefault("action", ""));
            row.put("target", shown.getOrDefault("target", ""));
            rows.add(row);
        }
        return ModuleKit.json(Map.of("events", rows));
    }

    private static Map<String, String> fields(String json) {
        Map<String, String> out = new LinkedHashMap<>();
        try {
            if (new JsonReader().read(json) instanceof JsonValue.JObject o) {
                for (String k : o.keys()) {
                    if (o.get(k).orElse(null) instanceof JsonValue.JString v) {
                        out.put(k, v.value());
                    }
                }
            }
        } catch (RuntimeException e) {
            return Map.of();
        }
        return out;
    }

    /** "key: value; key: value" for the fields that say what was done. */
    private static String what(String payloadJson) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : fields(payloadJson).entrySet()) {
            if (QUIET.contains(e.getKey()) || e.getValue().isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append(e.getKey()).append(": ").append(e.getValue());
        }
        return sb.toString();
    }
}

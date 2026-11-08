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
    /** Housekeeping fields that say nothing about what was done. */
    private static final Set<String> QUIET = Set.of("session", "source", "real", "scenario", "mac");

    private final Supplier<Set<String>> administrators;
    private Host host;

    /** @param administrators the ids of the people who are administrators now (read at every call, so a change shows at once) */
    public MonitorModule(Supplier<Set<String>> administrators) {
        this.administrators = administrators;
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

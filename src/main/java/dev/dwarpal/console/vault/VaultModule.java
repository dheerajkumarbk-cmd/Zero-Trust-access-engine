package dev.dwarpal.console.vault;

import dev.dwarpal.console.ConsoleModule;
import dev.dwarpal.console.lab.ModuleKit;
import dev.dwarpal.console.lab.ModuleKit.Refusal;
import dev.dwarpal.wire.JsonValue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The vault page and its calls (id {@code vault}). Administrators only, and for everybody else it does not exist: no menu
 * entry, no list, and a plain "not found" for its pages and calls (the host answers that, see {@link #hidden()}).
 *
 * <pre>
 *   GET  people                  the vault's list (who has an emergency password and where it stands, no password)
 *   POST people/{id}/reveal      shows that person's emergency password
 *   POST people/{id}/activate    switches it on (the person can then use it once, in the recovery) and shows it
 *   POST people/{id}/off         switches it off again
 *   POST people/{id}/set         the administrator types a password of their own choice for the person (kept as typed)
 *   GET  own                     whether the administrator's own password and PIN are kept
 *   POST own/reveal              shows them (only to their owner)
 *   POST own/save                keeps them
 * </pre>
 * Every call needs an open elevation (PIN, passkey and a reason, ten real minutes). Every call that shows or changes
 * something about a person also needs a fresh password and PIN and a passkey of its own (the host's step-up and
 * every-time passkey) and a reason in the body. An administrator never acts on their own emergency password: the OTHER
 * administrator does, which is how a locked-out administrator gets back in. Each call is written to the audit trail as a
 * {@code VAULT_} record (what and on whom, plus the reason, never a secret), and the other administrators and the leads
 * are sent a notice. Nobody has to approve: an emergency cannot wait.
 */
public final class VaultModule implements ConsoleModule {

    /** A person who can have an emergency password. */
    public record Person(String id, String name, String department) {
    }

    private final Vault vault;
    private final Supplier<List<Person>> people;
    private final Supplier<Set<String>> administrators;
    private final Supplier<Set<String>> leads;
    private Host host;

    /**
     * @param people         the people who exist now (active ones)
     * @param administrators the ids of the administrators now
     * @param leads          the ids of the leads now
     */
    public VaultModule(Vault vault, Supplier<List<Person>> people, Supplier<Set<String>> administrators, Supplier<Set<String>> leads) {
        this.vault = vault;
        this.people = people;
        this.administrators = administrators;
        this.leads = leads;
    }

    @Override
    public String id() {
        return "vault";
    }

    @Override
    public String title() {
        return "Vault";
    }

    @Override
    public Role minimum() {
        return Role.ADMIN;
    }

    @Override
    public boolean hidden() {
        return true;
    }

    @Override
    public void attach(Host h) {
        this.host = h;
        vault.onUsed(person -> {
            // the person set a new password and PIN with the emergency password: that is on the record and in the notices
            host.audit("VAULT_USED", person, fields("action", "emergency password used", "target", person));
            host.notify(person, "Your emergency password was used to set a new password and PIN. If that was not you, tell the Lead at once.");
            tell(person, person + " used an emergency password and set a new password and PIN.");
        });
    }

    @Override
    public void routes(Routes routes) {
        routes.get("people", Role.ADMIN, ModuleKit.guard(Role.ADMIN, this::list));
        routes.post("people/{}/reveal", Role.ADMIN, true, ModuleKit.guard(Role.ADMIN, (r, p) -> act(r, p.get(0), "reveal")));
        routes.post("people/{}/activate", Role.ADMIN, true, ModuleKit.guard(Role.ADMIN, (r, p) -> act(r, p.get(0), "activate")));
        routes.post("people/{}/off", Role.ADMIN, true, ModuleKit.guard(Role.ADMIN, (r, p) -> act(r, p.get(0), "off")));
        routes.post("people/{}/set", Role.ADMIN, true, ModuleKit.guard(Role.ADMIN, (r, p) -> act(r, p.get(0), "set")));
        routes.get("own", Role.ADMIN, ModuleKit.guard(Role.ADMIN, this::ownState));
        routes.post("own/reveal", Role.ADMIN, true, ModuleKit.guard(Role.ADMIN, (r, p) -> ownReveal(r)));
        routes.post("own/save", Role.ADMIN, true, ModuleKit.guard(Role.ADMIN, (r, p) -> ownSave(r)));
    }

    // ---- the list ---------------------------------------------------------------------------------------------------------

    private Response list(Request r, List<String> p) {
        gate(r);
        record(r, "VAULT_LIST", "open the list", "everybody", "");
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Person person : people.get()) {
            Vault.Credential c = vault.credential(person.id());
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", person.id());
            row.put("name", person.name());
            row.put("department", person.department());
            row.put("state", c.state().name());
            row.put("typed", c.typed());
            row.put("changedAt", c.changedAt().toString());
            row.put("activatedBy", c.activatedBy());
            row.put("activatedAt", c.activatedAt() == null ? "" : c.activatedAt().toString());
            row.put("self", person.id().equals(r.who().id()));
            rows.add(row);
        }
        return ModuleKit.json(Map.of("people", rows));
    }

    // ---- one person's emergency password ----------------------------------------------------------------------------------

    private Response act(Request r, String param, String what) {
        gate(r);
        String id = ModuleKit.id(param);
        JsonValue.JObject body = ModuleKit.body(r, "set".equals(what) ? Set.of("reason", "password") : Set.of("reason"));
        String reason = reason(body);
        if (id.equals(r.who().id())) {
            throw new Refusal(403, "the other administrator does that for you");
        }
        if (people.get().stream().noneMatch(x -> x.id().equals(id))) {
            throw new Refusal(404, "not found");
        }
        String actor = r.who().id();
        switch (what) {
            case "reveal" -> {
                record(r, "VAULT_REVEAL", "reveal emergency password", id, reason);
                Vault.Credential c = vault.credential(id);
                tell(actor, actor + " viewed the emergency password of " + id + " in the vault.");
                return shown(c);
            }
            case "activate" -> {
                record(r, "VAULT_ACTIVATE", "switch on emergency password", id, reason);
                Vault.Credential c = vault.activate(id, actor);
                host.notify(id, actor + " switched on an emergency password for your account. If you did not ask for this, tell the Lead.");
                tell(actor, actor + " switched on an emergency password for " + id + ".");
                return shown(c);
            }
            case "off" -> {
                record(r, "VAULT_OFF", "switch off emergency password", id, reason);
                Vault.Credential c = vault.switchOff(id);
                tell(actor, actor + " switched the emergency password of " + id + " off.");
                return shown(c);
            }
            default -> {
                String typed = ModuleKit.string(body, "password").orElseThrow(() -> new Refusal(400, "a password is required"));
                if (typed.length() < Vault.MIN_TYPED || typed.length() > Vault.MAX_TYPED) {
                    throw new Refusal(400, "a chosen emergency password is " + Vault.MIN_TYPED + " to " + Vault.MAX_TYPED + " characters");
                }
                record(r, "VAULT_SET", "set emergency password", id, reason);
                Vault.Credential c;
                try {
                    c = vault.setTyped(id, typed);
                } catch (IllegalArgumentException e) {
                    throw new Refusal(400, e.getMessage());
                }
                tell(actor, actor + " set a chosen emergency password for " + id + " in the vault.");
                return shown(c);
            }
        }
    }

    private static Response shown(Vault.Credential c) {
        return ModuleKit.json(Map.of("password", c.password(), "state", c.state().name(), "typed", c.typed()));
    }

    // ---- the administrator's own entry ------------------------------------------------------------------------------------

    private Response ownState(Request r, List<String> p) {
        gate(r);
        return ModuleKit.json(Map.of("saved", vault.own(r.who().id()).isPresent(),
                "savedAt", vault.own(r.who().id()).map(o -> o.savedAt().toString()).orElse("")));
    }

    private Response ownReveal(Request r) {
        gate(r);
        String reason = reason(ModuleKit.body(r, Set.of("reason")));
        Vault.Own o = vault.own(r.who().id()).orElseThrow(() -> new Refusal(404, "nothing is kept yet"));
        record(r, "VAULT_OWN_REVEAL", "view own entry", r.who().id(), reason);
        tell(r.who().id(), r.who().id() + " viewed their own entry in the vault.");
        return ModuleKit.json(Map.of("password", o.password(), "pin", o.pin(), "savedAt", o.savedAt().toString()));
    }

    private Response ownSave(Request r) {
        gate(r);
        JsonValue.JObject body = ModuleKit.body(r, Set.of("reason", "password", "pin"));
        String reason = reason(body);
        String password = ModuleKit.string(body, "password").orElseThrow(() -> new Refusal(400, "a password is required"));
        String pin = ModuleKit.string(body, "pin").orElseThrow(() -> new Refusal(400, "a PIN is required"));
        if (password.length() > 128 || pin.length() > 64) {
            throw new Refusal(400, "too long");
        }
        record(r, "VAULT_OWN_SAVE", "save own entry", r.who().id(), reason);
        vault.saveOwn(r.who().id(), password, pin);
        tell(r.who().id(), r.who().id() + " changed their own entry in the vault.");
        return ModuleKit.json(Map.of("saved", true));
    }

    // ---- the rules every call shares --------------------------------------------------------------------------------------

    /** Administrators only (anybody else is told the vault is not there), and only inside an open elevation. */
    private static void gate(Request r) {
        if (!r.who().has(Role.ADMIN)) {
            throw new Refusal(404, "not found");
        }
        if (!r.who().elevated()) {
            throw new Refusal(423, "elevation required");
        }
    }

    private static String reason(JsonValue.JObject body) {
        String reason = ModuleKit.string(body, "reason").map(String::strip).orElse("");
        if (reason.length() < 5 || reason.length() > 200) {
            throw new Refusal(400, "give a reason of 5 to 200 characters");
        }
        return reason;
    }

    /** The record comes first: if the trail cannot take it, nothing is shown or changed. Never a secret in it. */
    private void record(Request r, String type, String action, String target, String reason) {
        Map<String, String> f = fields("action", action, "target", target);
        if (!reason.isEmpty()) {
            f.put("reason", reason);
        }
        f.put("elevation", r.who().elevation().id());
        if (!host.audit(type, r.who().id(), f)) {
            throw new Refusal(503, "audit trail unavailable");
        }
    }

    /** A notice to the other administrators and the leads (not to the one who acted). */
    private void tell(String actor, String text) {
        Set<String> to = new LinkedHashSet<>(administrators.get());
        to.addAll(leads.get());
        to.remove(actor);
        to.forEach(p -> host.notify(p, text));
    }

    private static Map<String, String> fields(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put(kv[i], kv[i + 1]);
        }
        return m;
    }
}

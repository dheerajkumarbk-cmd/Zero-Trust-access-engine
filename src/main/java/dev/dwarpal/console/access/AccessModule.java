package dev.dwarpal.console.access;

import dev.dwarpal.console.ConsoleModule;
import dev.dwarpal.console.lab.ModuleKit;

import java.util.Objects;

/**
 * Access as a console module (id {@code access}): a person's own access and "request more access" (everybody who signs
 * in), HR's joiner and leaver requests (HR only) and a lead's approvals (a lead only). The administrator's side of the
 * same process is a section of the {@code admin} module. All the work is in {@link AccessApi}.
 *
 * <pre>
 *   GET  catalog                        USER  what can be given, and each role's usual set
 *   GET  mine                           USER  my grants, my requests, what I could still ask for
 *   POST request                        USER  {"items":[...],"reason":"..."}  ask for more access for myself
 *   GET  hr                             HR    people who could leave, my requests, the role names
 *   POST hr/joiner                      HR, step-up  {"id","name","department","businessRole","reason"}
 *   POST hr/leaver                      HR, step-up  {"id","reason"}  removes everything now
 *   GET  approvals                      LEAD  grants waiting for a lead (an administrator is not a lead)
 *   POST approvals/{grant}/decision     LEAD, elevation  {"approve":true|false,"reason":"..."}
 * </pre>
 */
public final class AccessModule implements ConsoleModule {

    private final AccessApi api;

    public AccessModule(AccessApi api) {
        this.api = Objects.requireNonNull(api, "api");
    }

    @Override
    public String id() {
        return "access";
    }

    @Override
    public String title() {
        return "Access";
    }

    @Override
    public Role minimum() {
        return Role.USER;
    }

    @Override
    public void attach(Host host) {
        api.attach(host);
    }

    @Override
    public void routes(Routes routes) {
        routes.get("catalog", Role.USER, ModuleKit.guard(Role.USER, (r, p) -> api.catalog()));
        routes.get("mine", Role.USER, ModuleKit.guard(Role.USER, (r, p) -> api.mine(r)));
        routes.post("request", Role.USER, false, ModuleKit.guard(Role.USER, (r, p) -> api.requestMore(r)));
        routes.get("hr", Role.HR, ModuleKit.guard(Role.HR, (r, p) -> api.hrOverview(r)));
        routes.post("hr/joiner", Role.HR, true, ModuleKit.guard(Role.HR, (r, p) -> api.submitJoiner(r)));
        routes.post("hr/leaver", Role.HR, true, ModuleKit.guard(Role.HR, (r, p) -> api.submitLeaver(r)));
        routes.get("approvals", Role.LEAD, ModuleKit.guard(Role.LEAD, (r, p) -> api.leadApprovals(r)));
        routes.post("approvals/{}/decision", Role.LEAD, false,
                ModuleKit.guard(Role.LEAD, (r, p) -> api.decide(r, ModuleKit.id(p.get(0)), Role.LEAD)));
    }
}

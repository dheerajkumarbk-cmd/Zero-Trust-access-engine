package dev.dwarpal.console.lab;

import dev.dwarpal.console.ConsoleModule;
import dev.dwarpal.lab.scenarios.ScenarioCatalog;
import dev.dwarpal.lab.scenarios.Walkthroughs;

import java.util.Map;

/**
 * The guided walkthroughs as a console module (id {@code guide}): read-only, for anyone who may use the console as an
 * analyst. The pages live under {@code console/modules/guide/}; this class serves the data they show.
 *
 * <pre>
 *   GET walkthroughs       every walkthrough
 *   GET walkthroughs/{id}  one, with its scenario (A1 to A9, L5, L6, QUIET)
 * </pre>
 */
public final class GuideModule implements ConsoleModule {

    @Override
    public String id() {
        return "guide";
    }

    @Override
    public String title() {
        return "Guide";
    }

    @Override
    public Role minimum() {
        return Role.ANALYST;
    }

    @Override
    public void routes(Routes routes) {
        routes.get("walkthroughs", Role.ANALYST, ModuleKit.guard(Role.ANALYST, (r, p) ->
                ModuleKit.json(Map.of("walkthroughs", Walkthroughs.all()))));
        routes.get("walkthroughs/{}", Role.ANALYST, ModuleKit.guard(Role.ANALYST, (r, p) -> {
            String id = ModuleKit.id(p.get(0));
            return Walkthroughs.byScenario(id).map(w -> ModuleKit.json(Map.of("walkthrough", w, "scenario",
                    ScenarioCatalog.byId(id).orElseThrow()))).orElseGet(() -> Response.error(404, "no such walkthrough"));
        }));
    }
}

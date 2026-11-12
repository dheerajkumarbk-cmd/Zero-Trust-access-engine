package dev.dwarpal.console.lab;

import dev.dwarpal.console.ConsoleModule;
import dev.dwarpal.console.ConsoleModule.Handler;
import dev.dwarpal.console.ConsoleModule.Principal;
import dev.dwarpal.console.ConsoleModule.Request;
import dev.dwarpal.console.ConsoleModule.Response;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A stand-in for the console host's route table: it records what a module registers and calls the handlers the way
 * the host would (matching {@code {}} segments), so a module can be tested before the host exists. Like the host it
 * checks the registered minimum role first, then the handler runs its own check.
 */
public final class FakeRoutes implements ConsoleModule.Routes {

    public record Route(String method, String pattern, Role minimum, boolean stepUp, Handler handler) {
    }

    public static final Principal ANALYST = new Principal("ana", Set.of(Role.ANALYST), false);
    public static final Principal LEAD = new Principal("cleo", Set.of(Role.ANALYST, Role.LEAD), false);
    public static final Principal ADMIN = new Principal("root", Set.of(Role.ADMIN), true);
    public static final Principal ADMIN_STALE = new Principal("root", Set.of(Role.ADMIN), false);
    public static final Principal USER = new Principal("u1", Set.of(Role.USER), false);

    private final List<Route> routes = new ArrayList<>();

    public static FakeRoutes of(ConsoleModule m) {
        FakeRoutes f = new FakeRoutes();
        m.routes(f);
        return f;
    }

    @Override
    public void get(String pattern, Role minimum, Handler handler) {
        routes.add(new Route("GET", pattern, minimum, false, handler));
    }

    @Override
    public void post(String pattern, Role minimum, boolean needsStepUp, Handler handler) {
        routes.add(new Route("POST", pattern, minimum, needsStepUp, handler));
    }

    public List<Route> all() {
        return routes;
    }

    public Route route(String method, String pattern) {
        return routes.stream().filter(r -> r.method().equals(method) && r.pattern().equals(pattern)).findFirst()
                .orElseThrow(() -> new AssertionError("no route " + method + " " + pattern));
    }

    /** Calls a route by concrete path ("launch/A8") the way the host would, without the role check of the host. */
    public Response call(String method, String path, Principal who, String body) {
        return call(method, path, who, body, Map.of());
    }

    public Response call(String method, String path, Principal who, String body, Map<String, String> query) {
        String[] parts = path.split("/", -1);
        for (Route r : routes) {
            if (!r.method().equals(method)) {
                continue;
            }
            String[] pat = r.pattern().split("/", -1);
            if (pat.length != parts.length) {
                continue;
            }
            List<String> params = new ArrayList<>();
            boolean ok = true;
            for (int i = 0; i < pat.length && ok; i++) {
                if (pat[i].equals("{}")) {
                    params.add(parts[i]);
                } else {
                    ok = pat[i].equals(parts[i]);
                }
            }
            if (ok) {
                try {
                    return r.handler().handle(new Request(who, method, path, query, body), params);
                } catch (Exception e) {
                    throw new AssertionError("handler threw instead of answering: " + e, e);
                }
            }
        }
        return Response.error(404, "no such route");
    }

    public static JsonValue.JObject json(Response r) {
        return (JsonValue.JObject) new JsonReader(new dev.dwarpal.wire.JsonLimits(8 << 20, 16, 1 << 20, 1024, 20_000, 32,
                500_000)).read(r.body());
    }

    public static String text(JsonValue v) {
        return ((JsonValue.JString) v).value();
    }
}

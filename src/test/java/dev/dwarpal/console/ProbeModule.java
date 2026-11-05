package dev.dwarpal.console;

import java.util.List;

/** A module for the tests: one route of each kind the host has to guard. */
final class ProbeModule implements ConsoleModule {

    @Override
    public String id() {
        return "probe";
    }

    @Override
    public String title() {
        return "Probe";
    }

    @Override
    public Role minimum() {
        return Role.ANALYST;
    }

    @Override
    public void routes(Routes r) {
        r.get("ping", Role.ANALYST, (q, p) -> Response.ok("{\"who\":\"" + q.who().id() + "\",\"stepUp\":" + q.who().stepUpFresh()
                + "}"));
        r.get("admin-only", Role.ADMIN, (q, p) -> Response.ok("{\"admin\":true}"));
        r.get("item/{}", Role.USER, (q, p) -> Response.ok("{\"item\":\"" + p.get(0) + "\"}"));
        r.get("boom", Role.ANALYST, (q, p) -> {
            throw new IllegalStateException("secret internal detail C:\\secret\\path");
        });
        r.post("change", Role.ANALYST, false, (q, p) -> Response.ok("{\"changed\":\"" + q.who().id() + "\",\"body\":"
                + (q.body().isEmpty() ? "null" : q.body()) + "}"));
        r.post("danger", Role.ANALYST, true, (q, p) -> Response.ok("{\"danger\":\"done by " + q.who().id() + "\"}"));
    }

    static List<ConsoleModule> only() {
        return List.of(new ProbeModule());
    }
}

package dev.dwarpal.console.lab;

import dev.dwarpal.console.ConsoleModule;
import dev.dwarpal.lab.LabRunner;
import dev.dwarpal.lab.LabWorld;
import dev.dwarpal.lab.scenarios.LabSession;
import dev.dwarpal.lab.scenarios.RuleSandbox;
import dev.dwarpal.lab.scenarios.RunExport;
import dev.dwarpal.lab.scenarios.Scenario;
import dev.dwarpal.lab.scenarios.ScenarioCatalog;
import dev.dwarpal.lab.scenarios.ScenarioRunner;
import dev.dwarpal.soar.CaseManager;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.wire.JsonValue;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The scenario lab as a console module (id {@code lab}): launch an attack on demand, control the scenario clock,
 * write a rule or a playbook in the sandbox, export a run. Every route checks the person's role again inside the
 * handler; the host adds the anti-forgery token, the step-up check and the audit record for every write.
 *
 * <pre>
 *   GET  scenarios                     what each scenario is (attacker, defender, techniques, expected results)
 *   POST launch/{id}                   ANALYST   start a scenario at the scenario clock's current time
 *   GET  launches, launches/{n}        ANALYST   the journal, and what one launch has produced so far
 *   GET  status                        ANALYST   clock state, speed, queue figures
 *   POST control/pause|resume          LEAD
 *   POST control/speed                 LEAD      {"speed": 1..3600}
 *   POST control/fastforward           LEAD      {"minutes": 1..720}
 *   POST control/reset                 ADMIN, step-up   back to day zero
 *   GET  sandbox/examples              ANALYST
 *   POST sandbox/rule                  ANALYST   {"yaml": "...", "run": true|false}
 *   POST sandbox/playbook              ANALYST   {"yaml": "..."}
 *   GET  export                        LEAD      the run as sanitised JSON
 * </pre>
 */
public final class LabModule implements ConsoleModule {

    public static final int MAX_FAST_FORWARD_MINUTES = 720;
    public static final double MAX_SPEED = 3_600;

    private final LabSession session;
    private final RuleSandbox sandbox;
    private final RunExport export;
    private final ReentrantLock heavy = new ReentrantLock();

    public LabModule(LabSession session) {
        this(session, new RuleSandbox(), new RunExport());
    }

    LabModule(LabSession session, RuleSandbox sandbox, RunExport export) {
        this.session = session;
        this.sandbox = sandbox;
        this.export = export;
    }

    @Override
    public String id() {
        return "lab";
    }

    @Override
    public String title() {
        return "Scenario lab";
    }

    @Override
    public Role minimum() {
        return Role.ANALYST;
    }

    @Override
    public void routes(Routes routes) {
        routes.get("scenarios", Role.ANALYST, ModuleKit.guard(Role.ANALYST, (r, p) ->
                ModuleKit.json(Map.of("scenarios", ScenarioCatalog.all()))));
        routes.post("launch/{}", Role.ANALYST, false, ModuleKit.guard(Role.ANALYST, this::launch));
        routes.get("launches", Role.ANALYST, ModuleKit.guard(Role.ANALYST, (r, p) ->
                ModuleKit.json(Map.of("launches", session.scenarios().journal()))));
        routes.get("launches/{}", Role.ANALYST, ModuleKit.guard(Role.ANALYST, this::launchReport));
        routes.get("status", Role.ANALYST, ModuleKit.guard(Role.ANALYST, (r, p) -> ModuleKit.json(status())));
        routes.post("control/pause", Role.LEAD, false, ModuleKit.guard(Role.LEAD, (r, p) -> {
            session.runner().pause();
            return ModuleKit.json(status());
        }));
        routes.post("control/resume", Role.LEAD, false, ModuleKit.guard(Role.LEAD, (r, p) -> {
            if (session.runner().state() == LabRunner.State.FAILED) {
                throw new ModuleKit.Refusal(409, "the scenario clock stopped after an error; reset the lab");
            }
            session.runner().resume();
            return ModuleKit.json(status());
        }));
        routes.post("control/speed", Role.LEAD, false, ModuleKit.guard(Role.LEAD, this::speed));
        routes.post("control/fastforward", Role.LEAD, false, ModuleKit.guard(Role.LEAD, this::fastForward));
        routes.post("control/reset", Role.ADMIN, false, ModuleKit.guard(Role.ADMIN, this::reset));
        routes.get("sandbox/examples", Role.ANALYST, ModuleKit.guard(Role.ANALYST, (r, p) ->
                ModuleKit.json(Map.of("examples", Examples.all()))));
        routes.post("sandbox/rule", Role.ANALYST, false, ModuleKit.guard(Role.ANALYST, this::sandboxRule));
        routes.post("sandbox/playbook", Role.ANALYST, false, ModuleKit.guard(Role.ANALYST, this::sandboxPlaybook));
        routes.get("export", Role.LEAD, ModuleKit.guard(Role.LEAD, this::export));
    }

    // ---- handlers ---------------------------------------------------------------------------------------

    private Response launch(Request request, List<String> params) {
        String id = ModuleKit.id(params.get(0));
        ModuleKit.body(request, Set.of());
        notResetting();
        LabRunner runner = session.runner();
        if (runner.state() == LabRunner.State.FAILED) {
            throw new ModuleKit.Refusal(409, "the scenario clock stopped after an error; reset the lab");
        }
        try {
            ScenarioRunner.Launch l = session.scenarios().launch(session.world(), id, request.who().id(),
                    runner.state() == LabRunner.State.RUNNING);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("launch", l);
            out.put("scenario", ScenarioCatalog.byId(id).orElseThrow());
            out.put("note", noteFor(runner.state(), l));
            return ModuleKit.json(out);
        } catch (ScenarioRunner.Refused refused) {
            return Response.error(refused.status(), refused.getMessage());
        }
    }

    private static String noteFor(LabRunner.State state, ScenarioRunner.Launch l) {
        return switch (state) {
            case RUNNING -> "Started. It plays out between scenario time " + l.startsAt() + " and " + l.endsAt()
                    + "; fast-forward to see the result sooner.";
            case PAUSED -> "Queued. The scenario clock is paused: it begins when time moves (resume, or fast-forward).";
            case FINISHED -> "Queued. The lab's own script has ended and the clock has stopped; fast-forward to play it.";
            case FAILED -> "The clock has stopped.";
        };
    }

    private Response launchReport(Request request, List<String> params) {
        long n;
        try {
            n = Long.parseLong(ModuleKit.id(params.get(0)));
        } catch (NumberFormatException e) {
            throw new ModuleKit.Refusal(400, "not a valid launch number");
        }
        return session.scenarios().report(session.world(), n).map(ModuleKit::json)
                .orElseGet(() -> Response.error(404, "no such launch"));
    }

    private Response speed(Request request, List<String> params) {
        JsonValue.JObject b = ModuleKit.body(request, Set.of("speed"));
        double v = ModuleKit.number(b, "speed").orElseThrow(() -> new ModuleKit.Refusal(400, "speed is required"));
        if (!(v >= 1 && v <= MAX_SPEED)) {
            throw new ModuleKit.Refusal(400, "speed is 1 to " + (long) MAX_SPEED + " (simulated seconds per second)");
        }
        session.runner().setSpeed(v);
        return ModuleKit.json(status());
    }

    private Response fastForward(Request request, List<String> params) {
        JsonValue.JObject b = ModuleKit.body(request, Set.of("minutes"));
        long m = ModuleKit.integer(b, "minutes").orElseThrow(() -> new ModuleKit.Refusal(400, "minutes is required"));
        if (m < 1 || m > MAX_FAST_FORWARD_MINUTES) {
            throw new ModuleKit.Refusal(400, "minutes is 1 to " + MAX_FAST_FORWARD_MINUTES);
        }
        notResetting();
        if (!heavy.tryLock()) {
            throw new ModuleKit.Refusal(429, "the lab is busy; try again in a moment");
        }
        try {
            session.fastForward(Duration.ofMinutes(m));
        } finally {
            heavy.unlock();
        }
        return ModuleKit.json(status());
    }

    private Response reset(Request request, List<String> params) throws IOException, InterruptedException {
        ModuleKit.body(request, Set.of());
        if (!request.who().elevated()) {
            throw new ModuleKit.Refusal(423, "elevation required");
        }
        if (!heavy.tryLock()) {
            throw new ModuleKit.Refusal(429, "the lab is busy; try again in a moment");
        }
        try {
            session.reset();
        } finally {
            heavy.unlock();
        }
        return ModuleKit.json(status());
    }

    private void notResetting() {
        if (session.resetting()) {
            throw new ModuleKit.Refusal(409, "the lab is being reset; try again in a few seconds");
        }
    }

    private Response sandboxRule(Request request, List<String> params) {
        JsonValue.JObject b = ModuleKit.body(request, Set.of("yaml", "run"));
        String yaml = ModuleKit.string(b, "yaml").orElseThrow(() -> new ModuleKit.Refusal(400, "yaml is required"));
        boolean run = ModuleKit.bool(b, "run").orElse(false);
        return ModuleKit.json(sandbox.rule(session.world(), request.who().id(), yaml, run));
    }

    private Response sandboxPlaybook(Request request, List<String> params) {
        JsonValue.JObject b = ModuleKit.body(request, Set.of("yaml"));
        String yaml = ModuleKit.string(b, "yaml").orElseThrow(() -> new ModuleKit.Refusal(400, "yaml is required"));
        return ModuleKit.json(sandbox.playbook(yaml));
    }

    private Response export(Request request, List<String> params) {
        try {
            return Response.ok(export.export(session.world(), session.scenarios().journal()));
        } catch (RunExport.Refused refused) {
            return Response.error(500, "the export was refused because it would have carried something it must not");
        }
    }

    // ---- status -----------------------------------------------------------------------------------------

    /** The clock and the queue in figures; the failure text never carries a stack trace. */
    public record Status(String state, double speed, Instant now, Instant scriptStart, Instant scriptEnd,
                         boolean scriptFinished, long generation, long requestsDecided, int alertsRaised,
                         Map<String, Integer> openByPriority, Optional<String> problem) {
        public Status {
            openByPriority = Map.copyOf(openByPriority);
        }
    }

    private Status status() {
        LabWorld w = session.world();
        LabRunner r = session.runner();
        CaseManager.Metrics m = w.cases.metrics();
        Map<String, Integer> open = new LinkedHashMap<>();
        for (Priority p : Priority.values()) {
            open.put(p.name(), m.openByPriority().getOrDefault(p, 0));
        }
        return new Status(r.state().name(), r.speed(), w.now(), w.scriptStart, w.scriptEnd, w.finished(),
                session.generation(), w.requestsDecided(), w.raised.size(), open,
                r.failure().map(f -> "the scenario clock stopped after an error"));
    }

    /** For other modules and tests: what the learner may do, by scenario. */
    static List<Scenario> scenarios() {
        return ScenarioCatalog.all();
    }
}

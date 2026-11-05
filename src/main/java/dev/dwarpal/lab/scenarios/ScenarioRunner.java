package dev.dwarpal.lab.scenarios;

import dev.dwarpal.lab.LabWorld;
import dev.dwarpal.lab.scenarios.Plans.Context;
import dev.dwarpal.lab.scenarios.Plans.Plan;
import dev.dwarpal.sim.SimOrganisation;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * Launches scenarios on a running lab. Every launch is checked before anything is injected:
 * <ul>
 *   <li>the scenario must exist (an unknown name is refused, nothing is built from it);</li>
 *   <li>one launch at a time per lab, and at least {@link #MIN_GAP_MILLIS} between launches;</li>
 *   <li>at most {@link #PER_PERSON} launches per person in {@link #PERSON_WINDOW_MILLIS} (a button held down is
 *       not a denial of service);</li>
 *   <li>a scenario still playing out cannot be launched again (they would stack up and hide each other);</li>
 *   <li>the world itself caps the injected items that wait to run.</li>
 * </ul>
 * The people a scenario is cast with rotate through those the simulation's own script uses in no attack and no
 * look-alike, never the CEO, so repeated launches hit different people and the SOC's quiet-for-a-window rules do
 * not swallow the second one.
 */
public final class ScenarioRunner {

    public static final long MIN_GAP_MILLIS = 1_000;
    public static final int PER_PERSON = 12;
    public static final long PERSON_WINDOW_MILLIS = 5 * 60_000L;
    public static final int JOURNAL = 200;

    /** What a launch did, for the screen and for the journal. */
    public record Launch(long number, String scenario, String by, String person, List<String> devices, Instant startsAt,
                         Instant endsAt, int items, boolean clockRunning) {
    }

    /** A launch that was refused, with a reason fit for the screen. */
    public static final class Refused extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final int status;

        Refused(int status, String message) {
            super(message);
            this.status = status;
        }

        public int status() {
            return status;
        }
    }

    private final LongSupplier wall;
    private final ArrayDeque<Launch> journal = new ArrayDeque<>();
    private final Map<String, ArrayDeque<Long>> perPerson = new HashMap<>();
    private final Map<String, Instant> playingUntil = new HashMap<>();
    private final Set<String> castBefore = new HashSet<>();
    private long launches;
    private long lastWall = Long.MIN_VALUE / 2;
    private int cursor;

    public ScenarioRunner() {
        this(System::currentTimeMillis);
    }

    ScenarioRunner(LongSupplier wallMillis) {
        this.wall = wallMillis;
    }

    /**
     * Starts a scenario at the world's current scenario time.
     *
     * @param by           the logged-in person (for the rate limit and the journal)
     * @param clockRunning whether the scenario clock is running; if not, the scenario waits until time moves
     * @throws Refused if the launch is not allowed
     */
    public synchronized Launch launch(LabWorld world, String scenarioId, String by, boolean clockRunning) {
        ScenarioCatalog.Def def = ScenarioCatalog.def(scenarioId)
                .orElseThrow(() -> new Refused(404, "unknown scenario"));
        long nowWall = wall.getAsLong();
        if (nowWall - lastWall < MIN_GAP_MILLIS) {
            throw new Refused(429, "one launch per second; wait a moment");
        }
        ArrayDeque<Long> mine = perPerson.computeIfAbsent(by, k -> new ArrayDeque<>());
        while (!mine.isEmpty() && nowWall - mine.peekFirst() > PERSON_WINDOW_MILLIS) {
            mine.pollFirst();
        }
        if (mine.size() >= PER_PERSON) {
            throw new Refused(429, "too many launches in five minutes; let the lab catch up");
        }
        Instant now = world.now();
        Instant busy = playingUntil.get(def.info().id());
        if (busy != null && busy.isAfter(now)) {
            throw new Refused(409, "this scenario is still playing out, until scenario time " + busy);
        }
        long number = ++launches;
        SimOrganisation.User target = pick(world, def.cast());
        int index = world.org.users.indexOf(target);
        Instant start = now.plusSeconds(30).truncatedTo(ChronoUnit.SECONDS);
        Set<String> keepOut = new HashSet<>(castBefore);
        keepOut.add(world.ceo);
        world.telemetry.cast().values().forEach(keepOut::addAll);
        Context ctx = new Context(world, start, number, new Random(world.config.seed() * 131 + number), target, index,
                keepOut);
        Plan plan = def.build().apply(ctx);
        try {
            world.inject(plan.items());
        } catch (IllegalStateException tooMany) {
            launches--;
            throw new Refused(429, "the lab is still busy with earlier scenarios");
        }
        lastWall = nowWall;
        mine.addLast(nowWall);
        playingUntil.put(def.info().id(), plan.until());
        String person = def.cast() == ScenarioCatalog.Cast.NOBODY ? "" : target.id();
        if (!person.isEmpty()) {
            castBefore.add(person);
        }
        Launch l = new Launch(number, def.info().id(), by, person, plan.devices(), plan.from(), plan.until(),
                plan.items().size(), clockRunning);
        journal.addLast(l);
        while (journal.size() > JOURNAL) {
            journal.pollFirst();
        }
        return l;
    }

    /** One decision of the access engine on a scenario's login request. */
    public record Decision(String requestId, Instant at, String outcome, String policy, String pAttack,
                           String signals, String reasons) {
    }

    /** One alert the SOC raised about the scenario's person or device, as the queue ranks it. */
    public record Seen(String alertId, String rule, String engine, String priority, boolean actionable, double score,
                       String summary, Instant raisedAt, List<String> reasons) {
    }

    /** What a launch has produced so far: the engine's decisions and the SOC's alerts. */
    public record Report(Launch launch, List<Decision> decisions, List<Seen> alerts) {
    }

    private static final dev.dwarpal.wire.JsonReader PAYLOAD = new dev.dwarpal.wire.JsonReader(
            new dev.dwarpal.wire.JsonLimits(1 << 20, 4, 1 << 16, 64, 8, 32, 512));

    /** What launch {@code number} has produced in {@code world} so far (decisions are read from the audit trail). */
    public Optional<Report> report(LabWorld world, long number) {
        Launch l;
        synchronized (this) {
            l = journal.stream().filter(x -> x.number() == number).findFirst().orElse(null);
        }
        if (l == null) {
            return Optional.empty();
        }
        List<Decision> decisions = new ArrayList<>();
        String prefix = "\"requestId\":\"lab" + number + "-";
        long last = world.org.sink.lastSequence();
        for (dev.dwarpal.audit.AuditRecord r : world.org.sink.after(Math.max(0, last - 50_000), 50_000)) {
            if (r.type().equals("ACCESS_DECISION") && r.payloadJson().contains(prefix)) {
                decisions.add(decision(r));
            }
        }
        List<Seen> seen = new ArrayList<>();
        for (LabWorld.Raised r : world.raised) {
            boolean mine = l.person().isEmpty() ? !r.alert().raisedAt().isBefore(l.startsAt())
                    : !r.alert().raisedAt().isBefore(l.startsAt()) && r.alert().entities().stream()
                    .anyMatch(e -> e.id().equals(l.person()) || l.devices().contains(e.id()));
            if (mine) {
                world.cases.ranked(r.alert().id()).ifPresent(ra -> seen.add(new Seen(r.alert().id(), r.alert().rule(),
                        r.engine(), ra.priority().name(), ra.actionable(), ra.score(), r.alert().summary(),
                        r.alert().raisedAt(), ra.reasons())));
            }
        }
        seen.sort(java.util.Comparator.comparing(Seen::priority).thenComparing(Seen::raisedAt));
        return Optional.of(new Report(l, decisions, seen.size() > 60 ? seen.subList(0, 60) : seen));
    }

    private static Decision decision(dev.dwarpal.audit.AuditRecord r) {
        dev.dwarpal.wire.JsonValue.JObject o = (dev.dwarpal.wire.JsonValue.JObject) PAYLOAD.read(r.payloadJson());
        return new Decision(text(o, "requestId"), r.at(), text(o, "outcome"), text(o, "policy"), text(o, "pAttack"),
                text(o, "signals"), text(o, "reasons"));
    }

    private static String text(dev.dwarpal.wire.JsonValue.JObject o, String k) {
        return o.get(k).filter(v -> v instanceof dev.dwarpal.wire.JsonValue.JString)
                .map(v -> ((dev.dwarpal.wire.JsonValue.JString) v).value()).orElse("");
    }

    /** Newest last. */
    public synchronized List<Launch> journal() {
        return new ArrayList<>(journal);
    }

    public synchronized Optional<Launch> last() {
        return Optional.ofNullable(journal.peekLast());
    }

    /** Forgets launches (after a reset). */
    public synchronized void clear() {
        journal.clear();
        perPerson.clear();
        playingUntil.clear();
        castBefore.clear();
        launches = 0;
        lastWall = Long.MIN_VALUE / 2;
        cursor = 0;
    }

    private SimOrganisation.User pick(LabWorld world, ScenarioCatalog.Cast cast) {
        Set<String> cast6 = new HashSet<>();
        world.telemetry.cast().values().forEach(cast6::addAll);
        List<SimOrganisation.User> pool = new ArrayList<>();
        for (SimOrganisation.User u : world.org.users) {
            String dept = world.telemetry.departments().get(u.id());
            boolean ok = switch (cast) {
                case ANYONE -> !cast6.contains(u.id()) && !u.id().equals(world.ceo);
                case FINANCE -> "finance".equals(dept) && !u.id().equals(world.ceo);
                case ADMIN -> world.telemetry.admins().contains(u.id());
                case NOBODY -> true;
            };
            if (ok) {
                pool.add(u);
            }
        }
        if (pool.isEmpty()) {
            pool = new ArrayList<>(world.org.users);
        }
        return pool.get(Math.floorMod(cursor++, pool.size()));
    }
}

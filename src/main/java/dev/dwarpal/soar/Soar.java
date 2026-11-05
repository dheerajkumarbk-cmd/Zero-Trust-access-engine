package dev.dwarpal.soar;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.response.Case;
import dev.dwarpal.response.CaseBook;
import dev.dwarpal.response.Enforcement;
import dev.dwarpal.response.Play;
import dev.dwarpal.response.Playbooks;
import dev.dwarpal.response.ResponseSettings;
import dev.dwarpal.response.SignalLedger;
import dev.dwarpal.response.VerdictGate;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Asset;
import dev.dwarpal.soc.AssetCatalog;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.InMemoryAssetCatalog;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.Verdict;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The SOAR: signed verdicts in, guard-railed action out. It runs part B's {@link Playbooks} with the installed
 * playbook file, and adds what part B does not do: the provenance rule, device isolation at the sensor,
 * notifications through connectors, and the case timeline.
 *
 * <ul>
 *   <li><b>Collected evidence never acts destructively.</b> A case is decided in one of two modes, chosen at its
 *       first accepted verdict from the ranked alert's {@code actionable} flag (computed by ranking from the
 *       evidence; unknown means not actionable): <i>full</i> (the installed plays) or <i>watch only</i> (the same
 *       plays with every revoke, deny and isolate removed). A true-positive verdict on a collected-only alert in a
 *       case already decided in full mode is refused, so a forged syslog line that joins a real case cannot ride on
 *       it.</li>
 *   <li><b>One playbook version per case.</b> A case stays with the playbook version (and mode) that first acted on
 *       it, so a second analyst confirms, and a false positive undoes, exactly what was done; installing new
 *       playbooks changes new cases only.</li>
 *   <li><b>Isolation</b> runs only after the play has run in full ({@code APPLIED}), in full mode, for the devices
 *       the alert names; it is released only when a false-positive verdict lifted the case's actions
 *       ({@code UNDONE}), which needs two analysts where two confirmed.</li>
 *   <li><b>Connectors</b> are told what happened with fixed templates; their failures are recorded, never fatal.</li>
 * </ul>
 */
public final class Soar {

    public static final String ACTOR = "soc-soar";
    /** At most one watch on collected evidence per entity in this time (red-team finding F-R1). */
    public static final Duration COLLECTED_WATCH_EVERY = Duration.ofDays(1);
    public static final int MAX_COLLECTED_WATCHES = 100_000;

    public enum Mode { FULL, WATCH_ONLY }

    /** The answer to a verdict: part B's status plus what the SOAR added. */
    public record Result(Playbooks.Status status, Optional<String> caseId, String message, int actions,
                         Optional<Mode> mode, List<String> isolated, List<String> released) {
        public Result {
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(caseId, "caseId");
            Objects.requireNonNull(message, "message");
            Objects.requireNonNull(mode, "mode");
            isolated = List.copyOf(isolated);
            released = List.copyOf(released);
        }
    }

    private record Generation(long sequence, PlaybookSet set, Playbooks full, Playbooks watchOnly) {
        Playbooks in(Mode m) {
            return m == Mode.FULL ? full : watchOnly;
        }
    }

    private record Route(Generation generation, Mode mode) {
    }

    /** A first verdict on an alert naming a protected person's device, waiting for a second analyst (F-R2). */
    private record DeviceWait(String alertId, String analystId, Instant at) {
    }

    private final ResponseSettings settings;
    private final CaseBook book;
    private final CaseManager cases;
    private final VerdictGate gate;
    private final SignalLedger ledger;
    private final Enforcement enforcement;
    private final AuditLog audit;
    private final Clock clock;
    private final DeviceIsolation isolation;
    private final Map<String, Connector> connectors;
    private final AssetCatalog assets;
    private final LinkedHashMap<String, Route> routes = new LinkedHashMap<>();
    private final LinkedHashMap<String, DeviceWait> deviceWaits = new LinkedHashMap<>();
    private final LinkedHashMap<String, Instant> collectedWatches = new LinkedHashMap<>();
    private Generation current;
    private long refused;
    private long notifyFailures;

    private Soar(Builder b) {
        this.settings = Objects.requireNonNull(b.settings, "settings");
        this.book = Objects.requireNonNull(b.book, "book");
        this.cases = Objects.requireNonNull(b.cases, "cases");
        this.gate = Objects.requireNonNull(b.gate, "gate");
        this.ledger = Objects.requireNonNull(b.ledger, "ledger");
        this.enforcement = Objects.requireNonNull(b.enforcement, "enforcement");
        this.audit = Objects.requireNonNull(b.audit, "audit");
        this.clock = Objects.requireNonNull(b.clock, "clock");
        this.isolation = Objects.requireNonNull(b.isolation, "isolation");
        this.assets = Objects.requireNonNull(b.assets, "assets");
        Map<String, Connector> m = new LinkedHashMap<>();
        for (Connector c : b.connectors) {
            if (m.putIfAbsent(c.name(), c) != null) {
                throw new IllegalArgumentException("two connectors named " + c.name());
            }
        }
        this.connectors = Map.copyOf(m);
        this.current = generation(new PlaybookInstaller.Installed(0, Objects.requireNonNull(b.initial, "initial")));
    }

    public static Builder builder(AuditLog audit, SignalLedger ledger) {
        return new Builder(audit, ledger);
    }

    /** The names of the configured connectors (for the playbook compiler). */
    public Set<String> connectorNames() {
        return connectors.keySet();
    }

    /** Makes an installed playbook set the one new cases use (called by {@link PlaybookInstaller}). */
    public synchronized void activate(PlaybookInstaller.Installed installed) {
        Objects.requireNonNull(installed, "installed");
        current = generation(installed);
    }

    public synchronized long playbookSequence() {
        return current.sequence();
    }

    public synchronized String playbookVersion() {
        return current.set().version();
    }

    /** Acts on one signed verdict. Never throws for a well-formed verdict. */
    public synchronized Result handle(Verdict v) {
        Objects.requireNonNull(v, "verdict");
        Optional<Case> c = book.caseOf(v.alertId());
        Optional<Alert> alert = book.alert(v.alertId());
        if (c.isPresent() && !cases.mayDecide(v.analystId(), c.get().id())) {
            return refuse(v, c.get().id(), "this analyst may not decide this case");
        }
        boolean actionable = cases.ranked(v.alertId()).map(RankedAlert::actionable).orElse(false);
        Route route = c.map(k -> routes.get(k.id())).orElse(null);
        if (route == null) {
            route = new Route(current, actionable ? Mode.FULL : Mode.WATCH_ONLY);
        }
        if (route.mode() == Mode.FULL && !actionable && v.outcome() == Verdict.Outcome.TRUE_POSITIVE
                && c.isPresent()) {
            return refuse(v, c.get().id(), "this alert rests on collected evidence only: it cannot confirm a"
                    + " destructive play");
        }
        List<String> collectedTargets = List.of();
        if (route.mode() == Mode.WATCH_ONLY && v.outcome() == Verdict.Outcome.TRUE_POSITIVE && c.isPresent()
                && alert.isPresent()) {
            collectedTargets = collectedTargets(route, alert.get());
            Optional<String> over = collectedBudget(collectedTargets);
            if (over.isPresent()) {
                return refuse(v, c.get().id(), over.get());
            }
        }
        if (route.mode() == Mode.FULL && c.isPresent() && alert.isPresent()) {
            Optional<Result> held = protectedDevices(v, c.get(), alert.get(), route);
            if (held.isPresent()) {
                return held.get();
            }
        }
        Playbooks.Result r = route.generation().in(route.mode()).handle(v);
        if (r.status() == Playbooks.Status.REFUSED || c.isEmpty() || alert.isEmpty()) {
            return new Result(r.status(), r.caseId(), r.message(), r.actions(), Optional.empty(), List.of(), List.of());
        }
        String caseId = c.get().id();
        if (r.status() == Playbooks.Status.APPLIED) {
            Instant now = clock.instant();
            collectedTargets.forEach(t -> collectedWatches.put(t, now));
        }
        remember(caseId, route);
        cases.awaitingSecond(caseId, r.status() == Playbooks.Status.AWAITING_SECOND_ANALYST);
        cases.record(caseId, CaseView.TimelineEntry.Kind.VERDICT, v.analystId(), v.outcome() + " on " + v.alertId()
                + ": " + r.status().name().toLowerCase(Locale.ROOT) + ", " + r.actions() + " action(s), "
                + route.mode().name().toLowerCase(Locale.ROOT) + " mode, playbooks " + route.generation().sequence());
        List<String> isolated = new ArrayList<>();
        List<String> released = new ArrayList<>();
        PlaybookSet set = route.mode() == Mode.FULL ? route.generation().set() : route.generation().set().watchOnly();
        PlaybookSet.Extras extras = set.extrasFor(alert.get().rule());
        Priority priority = cases.view(caseId).map(CaseView::priority).orElse(Priority.P2);
        switch (r.status()) {
            case APPLIED -> {
                if (v.outcome() == Verdict.Outcome.TRUE_POSITIVE && extras.isolate() && route.mode() == Mode.FULL) {
                    for (Entity e : alert.get().entities()) {
                        if (e.kind() == Entity.Kind.DEVICE) {
                            boolean ok = isolation.isolate(caseId, e.id(), v.analystId());
                            cases.record(caseId, CaseView.TimelineEntry.Kind.ISOLATION, v.analystId(),
                                    (ok ? "isolate command for " : "isolation refused for ") + e.id());
                            if (ok) {
                                isolated.add(e.id());
                            }
                        }
                    }
                    if (!isolated.isEmpty()) {
                        notify(extras, PlaybookSet.Template.DEVICE_ISOLATED, caseId, alert.get(), priority);
                    }
                }
                if (r.actions() > 0) {
                    notify(extras, PlaybookSet.Template.ACTION_TAKEN, caseId, alert.get(), priority);
                }
            }
            case AWAITING_SECOND_ANALYST ->
                    notify(extras, PlaybookSet.Template.NEEDS_SECOND_ANALYST, caseId, alert.get(), priority);
            case UNDONE -> {
                released.addAll(isolation.release(caseId, v.analystId()));
                for (String d : released) {
                    cases.record(caseId, CaseView.TimelineEntry.Kind.ISOLATION, v.analystId(), "release command for " + d);
                }
            }
            default -> {
                // CLOSED, PARTIAL: recorded on the timeline above
            }
        }
        return new Result(r.status(), r.caseId(), r.message(), r.actions(), Optional.of(route.mode()), isolated,
                released);
    }

    /** First verdicts waiting for a second analyst, across every playbook version still in use. */
    public synchronized List<Playbooks.Pending> pending() {
        List<Playbooks.Pending> all = new ArrayList<>();
        for (Generation g : generations()) {
            all.addAll(g.full().pending());
            all.addAll(g.watchOnly().pending());
        }
        return all;
    }

    /** Counters for the metrics endpoint. */
    public record Metrics(long playbookSequence, String playbookVersion, long refusedVerdicts, long heldBack,
                          int pending, int generationsInUse, long notifyFailures) {
    }

    public synchronized Metrics metrics() {
        long refusedAll = refused;
        long held = 0;
        List<Generation> gs = generations();
        for (Generation g : gs) {
            refusedAll += g.full().refusedVerdicts() + g.watchOnly().refusedVerdicts();
            held += g.full().heldBack() + g.watchOnly().heldBack();
        }
        return new Metrics(current.sequence(), current.set().version(), refusedAll, held,
                pending().size() + deviceWaits.size(), gs.size(), notifyFailures);
    }

    public DeviceIsolation isolation() {
        return isolation;
    }

    public CaseManager cases() {
        return cases;
    }

    // ---- internals ------------------------------------------------------------------------------------------

    private Generation generation(PlaybookInstaller.Installed installed) {
        PlaybookSet set = installed.set();
        return new Generation(installed.sequence(), set, playbooks(set), playbooks(set.watchOnly()));
    }

    private Playbooks playbooks(PlaybookSet set) {
        Playbooks.Builder b = Playbooks.builder(audit, ledger).settings(settings).cases(book).verdicts(gate)
                .enforcement(enforcement).clock(clock).defaultPlay(set.fallback());
        // The file is authoritative: part B's built-in plays are replaced, by the fallback where the file is silent.
        for (String rule : Playbooks.referencePlays().keySet()) {
            b.play(rule, set.fallback());
        }
        for (Map.Entry<String, Play> e : set.plays().entrySet()) {
            b.play(e.getKey(), e.getValue());
        }
        return b.build();
    }

    private List<Generation> generations() {
        Map<Generation, Boolean> seen = new IdentityHashMap<>();
        List<Generation> out = new ArrayList<>();
        seen.put(current, true);
        out.add(current);
        for (Route r : routes.values()) {
            if (seen.putIfAbsent(r.generation(), true) == null) {
                out.add(r.generation());
            }
        }
        return out;
    }

    private void remember(String caseId, Route route) {
        routes.putIfAbsent(caseId, route);
        if (routes.size() > settings.maxCases()) {
            routes.keySet().removeIf(id -> book.get(id).map(k -> k.state() == Case.State.CLOSED && !k.holdsActions())
                    .orElse(true));
        }
    }

    // ---- red-team fixes F-R1 and F-R2 -------------------------------------------------------------------------

    /** "KIND:id" of each entity a watch-only play would watch for this alert. */
    private static List<String> collectedTargets(Route route, Alert alert) {
        Set<Entity.Kind> watched = new java.util.HashSet<>();
        for (Play.Step s : route.generation().set().watchOnly().playFor(alert.rule()).steps()) {
            watched.add(s.target());
        }
        return alert.entities().stream().filter(e -> watched.contains(e.kind())).map(e -> e.kind() + ":" + e.id())
                .distinct().toList();
    }

    /** Why a collected-evidence watch is refused now (an entity watched on collected evidence today), if it is. */
    private Optional<String> collectedBudget(List<String> targets) {
        Instant now = clock.instant();
        collectedWatches.values().removeIf(at -> !now.isBefore(at.plus(COLLECTED_WATCH_EVERY)));
        for (String t : targets) {
            if (collectedWatches.containsKey(t)) {
                return Optional.of("an entity of this alert was already watched on collected evidence in the last day");
            }
        }
        if (collectedWatches.size() + targets.size() > MAX_COLLECTED_WATCHES) {
            return Optional.of("too many collected-evidence watches in force");
        }
        return Optional.empty();
    }

    /**
     * Part B asks for two analysts when an alert names a protected person; an alert naming only a protected person's
     * device (or a device of criticality 5) gets the same rule here, before part B sees the verdict. Empty when part B
     * may go ahead with this verdict; otherwise the answer.
     */
    private Optional<Result> protectedDevices(Verdict v, Case c, Alert a, Route route) {
        Instant now = clock.instant();
        DeviceWait wait = deviceWaits.get(c.id());
        if (wait != null && !now.isBefore(wait.at().plus(settings.secondAnalystWindow()))) {
            deviceWaits.remove(c.id());
            waitAudit("SOAR_PENDING_LAPSED", c.id(), wait.alertId(), wait.analystId(), now);
            cases.awaitingSecond(c.id(), false);
            wait = null;
        }
        if (v.outcome() != Verdict.Outcome.TRUE_POSITIVE) {
            if (wait != null) {
                deviceWaits.remove(c.id());
                waitAudit("SOAR_PENDING_CANCELLED", c.id(), wait.alertId(), v.analystId(), now);
                cases.awaitingSecond(c.id(), false);
            }
            return Optional.empty();
        }
        if (!protectedDevice(a) || protectedSubjectNamed(a, now)) {
            return Optional.empty();
        }
        if (wait == null) {
            if (c.concerns(v.analystId())) {
                return Optional.of(refuse(v, c.id(), "an analyst cannot decide a case about themselves"));
            }
            Optional<String> bad = gate.admit(v);
            if (bad.isPresent()) {
                return Optional.of(refuse(v, c.id(), bad.get()));
            }
            if (!waitAudit("SOAR_PENDING", c.id(), a.id(), v.analystId(), now)) {
                return Optional.of(refuse(v, c.id(), "audit trail unavailable"));
            }
            if (deviceWaits.size() >= settings.maxCases()) {
                deviceWaits.remove(deviceWaits.keySet().iterator().next());
            }
            deviceWaits.put(c.id(), new DeviceWait(a.id(), v.analystId(), now));
            remember(c.id(), route);
            cases.awaitingSecond(c.id(), true);
            cases.record(c.id(), CaseView.TimelineEntry.Kind.VERDICT, v.analystId(), v.outcome() + " on " + a.id()
                    + ": waits for a second analyst (a protected person's device)");
            notify(route.generation().set().extrasFor(a.rule()), PlaybookSet.Template.NEEDS_SECOND_ANALYST, c.id(), a,
                    cases.view(c.id()).map(CaseView::priority).orElse(Priority.P2));
            return Optional.of(new Result(Playbooks.Status.AWAITING_SECOND_ANALYST, Optional.of(c.id()),
                    "the alert names a protected person's device: destructive steps wait for a second analyst", 0,
                    Optional.of(route.mode()), List.of(), List.of()));
        }
        if (wait.analystId().equals(v.analystId())) {
            return Optional.of(refuse(v, c.id(), "the second verdict must come from another analyst"));
        }
        if (!wait.alertId().equals(v.alertId())) {
            return Optional.of(refuse(v, c.id(), "the second analyst must confirm the same alert"));
        }
        deviceWaits.remove(c.id());
        return Optional.empty();
    }

    private boolean protectedDevice(Alert a) {
        for (Entity e : a.entities()) {
            if (e.kind() != Entity.Kind.DEVICE) {
                continue;
            }
            try {
                Asset asset = assets.asset(e);
                if (asset.known() && (asset.criticality() >= 5 || settings.protectedSubjects().contains(asset.owner()))) {
                    return true;
                }
            } catch (RuntimeException ex) {
                return true;    // cannot tell: two analysts, never one
            }
        }
        return false;
    }

    /** Whether part B will itself ask for two analysts (the alert names a protected or privileged person). */
    private boolean protectedSubjectNamed(Alert a, Instant now) {
        for (Entity e : a.entities()) {
            if (e.kind() != Entity.Kind.SUBJECT) {
                continue;
            }
            if (settings.protectedSubjects().contains(e.id())) {
                return true;
            }
            try {
                if (enforcement.rolesOf(e.id(), now).stream().anyMatch(settings.privilegedRoles()::contains)) {
                    return true;
                }
            } catch (RuntimeException ex) {
                return true;    // part B treats an unknown as privileged too
            }
        }
        return false;
    }

    private boolean waitAudit(String type, String caseId, String alertId, String analyst, Instant now) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("case", caseId);
        f.put("alert", alertId);
        f.put("analyst", analyst);
        f.put("reason", "protected device");
        try {
            audit.append(type, ACTOR, now, f);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private void notify(PlaybookSet.Extras extras, PlaybookSet.Template template, String caseId, Alert alert,
                        Priority priority) {
        for (PlaybookSet.Notify n : extras.notifications()) {
            if (n.template() != template) {
                continue;
            }
            Connector c = connectors.get(n.connector());
            boolean ok;
            try {
                ok = c != null && c.send(new Connector.Notification(caseId, alert.id(), alert.rule(), priority, template,
                        title(template, caseId, alert), clock.instant()));
            } catch (RuntimeException e) {
                ok = false;
            }
            if (!ok) {
                notifyFailures++;
            }
            cases.record(caseId, CaseView.TimelineEntry.Kind.NOTIFIED, ACTOR, n.connector() + " " + template.key()
                    + (ok ? " sent" : " not sent"));
        }
    }

    private static String title(PlaybookSet.Template t, String caseId, Alert a) {
        return switch (t) {
            case ACTION_TAKEN -> "Response actions taken on " + caseId + " (" + a.rule() + ")";
            case DEVICE_ISOLATED -> "Device isolation requested on " + caseId + " (" + a.rule() + ")";
            case NEEDS_SECOND_ANALYST -> "Second analyst needed on " + caseId + " (" + a.rule() + ")";
        };
    }

    private Result refuse(Verdict v, String caseId, String why) {
        refused++;
        Map<String, String> f = new LinkedHashMap<>();
        f.put("case", caseId);
        f.put("alert", v.alertId());
        f.put("claimedAnalyst", v.analystId());
        f.put("outcome", v.outcome().name());
        f.put("reason", Sanitize.text(why, 200));
        try {
            audit.append("SOAR_VERDICT_REFUSED", Validate.id(ACTOR, "actor"), clock.instant(), f);
        } catch (RuntimeException e) {
            // refusing changes nothing; the counter still shows it
        }
        return new Result(Playbooks.Status.REFUSED, Optional.of(caseId), why, 0, Optional.empty(), List.of(), List.of());
    }

    public static final class Builder {
        private final AuditLog audit;
        private final SignalLedger ledger;
        private ResponseSettings settings = ResponseSettings.defaults();
        private CaseBook book;
        private CaseManager cases;
        private VerdictGate gate;
        private Enforcement enforcement;
        private Clock clock = Clock.systemUTC();
        private DeviceIsolation isolation;
        private Collection<Connector> connectors = List.of();
        private PlaybookSet initial;
        private AssetCatalog assets = new InMemoryAssetCatalog(List.of());

        private Builder(AuditLog audit, SignalLedger ledger) {
            this.audit = audit;
            this.ledger = ledger;
        }

        public Builder settings(ResponseSettings v) {
            settings = v;
            return this;
        }

        /** The case book and the case manager on top of it (which must wrap this book). */
        public Builder cases(CaseBook b, CaseManager m) {
            book = b;
            cases = m;
            return this;
        }

        public Builder verdicts(VerdictGate v) {
            gate = v;
            return this;
        }

        public Builder enforcement(Enforcement v) {
            enforcement = v;
            return this;
        }

        public Builder clock(Clock v) {
            clock = v;
            return this;
        }

        public Builder isolation(DeviceIsolation v) {
            isolation = v;
            return this;
        }

        public Builder connectors(Collection<Connector> v) {
            connectors = List.copyOf(v);
            return this;
        }

        /**
         * Who owns which device and how critical it is: devices of protected people and devices of criticality 5
         * need two analysts. Default: an empty catalogue (no device is protected beyond part B's rules).
         */
        public Builder assets(AssetCatalog v) {
            assets = v;
            return this;
        }

        /** The playbook set in force before any bundle is installed (sequence 0). */
        public Builder playbooks(PlaybookSet v) {
            initial = v;
            return this;
        }

        public Soar build() {
            return new Soar(this);
        }
    }
}

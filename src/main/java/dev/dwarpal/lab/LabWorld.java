package dev.dwarpal.lab;

import dev.dwarpal.analytics.DataSource;
import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.edge.DevPki;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.engine.DenyListGate;
import dev.dwarpal.engine.HoneytokenGate;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.response.CaseBook;
import dev.dwarpal.response.Enforcement;
import dev.dwarpal.response.ResponseSettings;
import dev.dwarpal.response.SignalLedger;
import dev.dwarpal.response.VerdictGate;
import dev.dwarpal.response.WatchlistScorer;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.risk.RiskScorer;
import dev.dwarpal.risk.scorers.StandardScorers;
import dev.dwarpal.siem.DetectionEngine;
import dev.dwarpal.siem.HeadAnchor;
import dev.dwarpal.siem.platform.CloudCollector;
import dev.dwarpal.siem.platform.CorrelationEngine;
import dev.dwarpal.siem.platform.EndpointCollector;
import dev.dwarpal.siem.platform.EventStore;
import dev.dwarpal.siem.platform.FirewallCollector;
import dev.dwarpal.siem.platform.Ingestor;
import dev.dwarpal.siem.platform.RuleBook;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.sim.SimRequests;
import dev.dwarpal.sim.SimTelemetry;
import dev.dwarpal.soar.Analyst;
import dev.dwarpal.soar.CaseManager;
import dev.dwarpal.soar.CaseSettings;
import dev.dwarpal.soar.Connector;
import dev.dwarpal.soar.DeviceIsolation;
import dev.dwarpal.soar.FileConnector;
import dev.dwarpal.soar.PlaybookCompiler;
import dev.dwarpal.soar.RuleCatalogue;
import dev.dwarpal.soar.SimulatedSensor;
import dev.dwarpal.soar.Soar;
import dev.dwarpal.socapi.Delegation;
import dev.dwarpal.socapi.SocApiServer;
import dev.dwarpal.socapi.SocApiSettings;
import dev.dwarpal.socapi.SocCaller;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertSink;
import dev.dwarpal.soc.Asset;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.InMemoryAssetCatalog;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.Technique;
import dev.dwarpal.soc.Verdict;
import dev.dwarpal.ueba.PeerGroups;
import dev.dwarpal.ueba.SocReport;
import dev.dwarpal.ueba.TechniqueMap;
import dev.dwarpal.ueba.Ueba;
import dev.dwarpal.ueba.UebaRisk;
import dev.dwarpal.ueba.UebaSettings;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The whole Layer 5 and 5.2 SOC on one simulated organisation, wired the way a deployment is wired and running
 * behind the real SOC API (mutual TLS). This is the composition root of the lab: the console server, the scenario
 * controls and the launcher all work through this class and never build SOC parts themselves.
 *
 * <pre>
 *   scenario script (traffic, firewall, endpoint, cloud) --time--> collectors --> Ingestor --> keyed audit chain
 *   chain --A DetectionEngine / D CorrelationEngine / E Ueba--> alerts --> E ranking --> F CaseManager (queue)
 *   analyst's signed verdict --> F Soar --> signal feed, revocation, device isolation --> sensor acknowledgement
 * </pre>
 *
 * <p><b>Threading.</b> One thread moves scenario time ({@link #advanceTo}); the SOC API serves analysts on its own
 * threads. Parts D and F lock themselves, part E is reached only through {@link LockedUeba}.
 *
 * <p><b>State.</b> Everything lives in memory for now; the chain is the source of truth and a later step rebuilds
 * the SOC state from it (see docs/layer-6-plan.md, part 0b).
 */
public final class LabWorld implements AutoCloseable {

    /** An action the playbooks asked the enforcement point to take. */
    public record Revocation(String kind, String id, String actor, Instant at) {
    }

    /** One alert as it reached the shared pipeline, with the engine that raised it (A, D or E). */
    public record Raised(Alert alert, String engine) {
    }

    /** Where the scenario stands. */
    public record Progress(Instant now, int itemsRun, int itemsLeft, int newAlerts, boolean finished) {
    }

    public static final Analyst ANA = new Analyst("ana", Analyst.Role.ANALYST);
    public static final Analyst BEN = new Analyst("ben", Analyst.Role.ANALYST);
    public static final Analyst CLEO = new Analyst("cleo", Analyst.Role.LEAD);
    public static final List<Analyst> ANALYSTS = List.of(ANA, BEN, CLEO);

    /** Certificates the lab makes: the SOC API, the console server, and one per analyst. */
    public static final List<String> CERTIFICATES = List.of("soc-api", "console", "ana", "ben", "cleo");

    private record Timed(Instant at, Object item, boolean injected) {
        Timed(Instant at, Object item) {
            this(at, item, false);
        }
    }

    public final LabConfig config;
    public final SimOrganisation org;
    public final SimTelemetry telemetry;
    public final FirewallCollector firewall;
    public final EndpointCollector endpoint;
    public final CloudCollector cloud;
    public final Ingestor ingestor;
    public final EventStore store;
    public final RuleBook rules;
    public final LockedUeba ueba;
    public final CaseBook book;
    public final CaseManager cases;
    public final VerdictGate gate;
    public final SimulatedSensor sensor;
    public final DeviceIsolation isolation;
    public final Soar soar;
    public final PolicyEngine engine;
    public final DecisionPoint pdp;
    public final InMemoryAssetCatalog assets;
    public final DevPki pki;
    public final HeadAnchor anchor;
    public final LabAudit auditView;
    public final SocApiServer socApi;
    public final String ceo;
    public final Instant scriptStart;
    public final Instant scriptEnd;
    public final List<Revocation> revocations = new CopyOnWriteArrayList<>();
    public final List<Raised> raised = new CopyOnWriteArrayList<>();

    private final Map<String, SecurityEvent.Provenance> datasets = Map.of("firewall", SecurityEvent.Provenance.COLLECTED,
            "endpoint", SecurityEvent.Provenance.SIGNED_SENSOR, "cloud", SecurityEvent.Provenance.COLLECTED);
    private final List<Alert> uebaAlerts = new ArrayList<>();
    private final List<Timed> script = new ArrayList<>();
    private final List<SimOrganisation.Step> traffic;
    private final DetectionEngine detection;
    private final CorrelationEngine correlation;
    private final AuditCursor correlationCursor;
    private final AuditCursor uebaCursor;
    private final List<Raised> pending = new ArrayList<>();
    private final AtomicLong requests = new AtomicLong();
    private final Object lock = new Object();
    private int next;
    private boolean flushed;
    private final Map<String, Long> batchNumbers = new java.util.HashMap<>();
    private int injectedPending;
    private long anchored;

    private LabWorld(LabConfig config, DevPki pki) throws IOException {
        this.config = config;
        this.pki = pki;
        Files.createDirectories(config.dir().resolve("connectors"));
        org = SimOrganisation.create(config.seed(), config.users());
        // the chain starts again with every lab (state is not persisted yet), so the anchor of an earlier run goes
        Path anchorFile = config.dir().resolve("audit.anchor");
        Files.deleteIfExists(anchorFile);
        anchor = new HeadAnchor(anchorFile, org.auditKey, org.clock);
        auditView = new LabAudit(org.sink, org.auditKey, anchor);
        traffic = org.traffic();
        telemetry = SimTelemetry.of(org, traffic);

        // the CEO is somebody the script casts in no attack and no look-alike
        Set<String> cast = new HashSet<>();
        telemetry.cast().values().forEach(cast::addAll);
        ceo = org.users.stream().map(SimOrganisation.User::id).filter(u -> !cast.contains(u)).findFirst()
                .orElseThrow(() -> new IllegalStateException("every user is cast in an attack; use more users"));
        ResponseSettings settings = ResponseSettings.defaults().withProtected(Set.of(ceo, "ana", "ben"), Set.of());

        // ---- part D: collectors into the chain
        firewall = new FirewallCollector("lab", telemetry.leases());
        endpoint = new EndpointCollector("lab", org.keys);
        cloud = new CloudCollector("lab", telemetry.leases());
        ingestor = new Ingestor(org.audit, List.of(
                new Ingestor.Registration(firewall, SecurityEvent.Provenance.COLLECTED, 100_000, 100_000),
                new Ingestor.Registration(endpoint, SecurityEvent.Provenance.SIGNED_SENSOR, 100_000, 100_000),
                new Ingestor.Registration(cloud, SecurityEvent.Provenance.COLLECTED, 100_000, 100_000)),
                Ingestor.Settings.defaults());
        store = new EventStore(AuditCursor.fromStart(org.sink, org.auditKey), 500_000);
        rules = RuleBook.defaults(datasets);

        // ---- assets: the CEO's laptop is the crown jewel, admins' laptops matter more than the rest
        List<Asset> list = new ArrayList<>();
        Set<String> admins = Set.copyOf(telemetry.admins());
        for (SimOrganisation.User u : org.users) {
            String dept = telemetry.departments().get(u.id());
            int c = u.id().equals(ceo) ? 5 : admins.contains(u.id()) ? 4 : 3;
            list.add(new Asset(Entity.subject(u.id()), c, u.id(), Set.of(dept), true));
            list.add(new Asset(Entity.device(u.laptop()), c, u.id(), Set.of(dept, "laptop"), true));
        }
        assets = new InMemoryAssetCatalog(list);

        // ---- part E: UEBA, with D's rule techniques registered so MITRE coverage is complete
        TechniqueMap.Builder techniques = TechniqueMap.standard();
        for (RuleBook.Rule r : rules.rules()) {
            techniques.rule(r.id(), r.techniques().toArray(new Technique[0]));
        }
        ueba = new LockedUeba(new Ueba(UebaSettings.reference(), UebaRisk.Settings.reference(),
                PeerGroups.of(telemetry.departments(), assets), assets, techniques, uebaAlerts::add));

        // ---- parts B and F: an engine that reads the signal feed, cases, playbooks, isolation
        engine = PolicyEngine.builder().policySet(SimRequests.defaultPolicies()).directory(org.directory)
                .keyRing(org.keys).gate(new HoneytokenGate()).gate(new DenyListGate())
                .scorers(withWatchlist(org))
                .aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                .costModel(new CostModel(1000, 1, 20, 0.05)).build();
        pdp = org.pipeline(engine);
        book = new CaseBook(settings, org.audit, org.clock);
        cases = new CaseManager(book, ueba, org.audit, org.clock, CaseSettings.defaults(), ANALYSTS);
        gate = new VerdictGate(org.keys, org.clock);
        sensor = new SimulatedSensor(org.clock);
        for (SimOrganisation.User u : org.users) {
            sensor.enrol(u.laptop(), "agent-" + u.laptop(), u.laptopKey().getPrivate());
        }
        isolation = new DeviceIsolation(org.keys, sensor, org.audit, org.clock, Duration.ofMinutes(10), 1_000);
        PlaybookCompiler.Compilation c = new PlaybookCompiler(RuleCatalogue.reference(), settings,
                Set.of("ticket", "chat"), true).compileReference();
        if (c.set().isEmpty()) {
            throw new IllegalStateException("the shipped playbooks do not compile: " + c.findings());
        }
        Path connectors = config.dir().resolve("connectors");
        soar = Soar.builder(org.audit, new SignalLedger(org.signals, org.clock)).settings(settings).cases(book, cases)
                .verdicts(gate).enforcement(enforcement()).clock(org.clock).isolation(isolation)
                .connectors(List.of(new FileConnector("ticket", Connector.Kind.TICKET, connectors, 1_000, org.clock),
                        new FileConnector("chat", Connector.Kind.CHAT, connectors, 1_000, org.clock)))
                .playbooks(c.set().get()).assets(assets).build();

        // ---- the engines that read the chain, kept between calls so each one reads only what is new
        detection = new DetectionEngine(org.sink, org.auditKey, a -> pending.add(new Raised(a, "A")), Optional::empty,
                DetectionEngine.Settings.defaults());
        correlation = new CorrelationEngine(rules, a -> pending.add(new Raised(a, "D")),
                CorrelationEngine.Settings.defaults());
        correlationCursor = AuditCursor.fromStart(org.sink, org.auditKey);
        uebaCursor = AuditCursor.fromStart(org.sink, org.auditKey);

        // ---- the script: Dwarpal's own traffic and the raw telemetry, in time order
        traffic.forEach(s -> script.add(new Timed(s.at(), s)));
        telemetry.items().forEach(i -> script.add(new Timed(i.at(), i)));
        script.sort(Comparator.comparing(Timed::at));
        scriptStart = script.getFirst().at();
        scriptEnd = script.getLast().at();

        // ---- the SOC API, over mutual TLS, for the console
        try {
            socApi = SocApiServer.builder(org.audit, soar)
                    .tls(TlsContexts.create(pki.keyStore("soc-api"), pki.password(), pki.trustStore(), pki.password()))
                    .address(new InetSocketAddress(InetAddress.getLoopbackAddress(), config.port()))
                    .clock(org.clock)
                    .delegation(TlsContexts.component("console").getName(javax.security.auth.x500.X500Principal.RFC2253),
                            new Delegation.Verifier(org.keys, org.clock, 100_000))
                    .callers(ANALYSTS.stream().map(a -> SocCaller.component(a.id(), a)).toList())
                    .settings(SocApiSettings.defaults()).search(store).risk(ueba)
                    .reports((name, now) -> name.equals("daily") ? Optional.of(dailyReport().text()) : Optional.empty())
                    .build().start();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("the lab certificates do not load", e);
        }
    }

    /** Makes (or reuses) the lab certificates and builds the world; nothing runs until {@link #advanceTo}. */
    public static LabWorld create(LabConfig config) throws IOException, InterruptedException {
        DevPki pki = LabPki.ensure(config.dir(), CERTIFICATES, Instant.now());
        return new LabWorld(config, pki);
    }

    private static List<RiskScorer> withWatchlist(SimOrganisation org) {
        List<RiskScorer> all = new ArrayList<>(StandardScorers.all(org.history, org.trust, org.failures,
                () -> org.threatIntel));
        all.add(new WatchlistScorer(org.signals, org.clock));
        return all;
    }

    private Enforcement enforcement() {
        return new Enforcement() {
            @Override
            public int revokeSession(String s, String a, String r) {
                revocations.add(new Revocation("session", s, a, org.clock.instant()));
                return 0;
            }

            @Override
            public int revokeSubject(String s, String a, String r) {
                revocations.add(new Revocation("subject", s, a, org.clock.instant()));
                return 0;
            }

            @Override
            public int revokeDevice(String s, String a, String r) {
                revocations.add(new Revocation("device", s, a, org.clock.instant()));
                return 0;
            }

            @Override
            public Set<String> rolesOf(String s, Instant n) {
                return org.directory.subject(s).map(x -> x.roles()).orElse(Set.of());
            }
        };
    }

    // ---- scenario time ----------------------------------------------------------------------------------

    /** The scenario's current time. */
    public Instant now() {
        return org.clock.instant();
    }

    public boolean finished() {
        synchronized (lock) {
            return next >= script.size();
        }
    }

    /**
     * Runs every scripted item up to {@code target}, then the detectors on what the chain gained, then moves new
     * alerts through ranking into cases. Calling it with an earlier time than now only runs the detectors.
     */
    public Progress advanceTo(Instant target) {
        synchronized (lock) {
            return advance(target);
        }
    }

    private Progress advance(Instant target) {
        int run = 0;
        while (next < script.size() && !script.get(next).at().isAfter(target)) {
            Timed t = script.get(next++);
            if (t.injected()) {
                injectedPending--;
            }
            runItem(t);
            run++;
        }
        if (target.isAfter(org.clock.instant())) {
            org.clock.set(target);
        }
        boolean ended = next >= script.size();
        int alerts = run > 0 || (ended && !flushed) ? detectAndTriage(ended) : 0;
        processSensor();
        anchorHead();
        return new Progress(org.clock.instant(), run, script.size() - next, alerts, next >= script.size());
    }

    /** Most injected items (see {@link #inject}) that may wait to run at once. */
    public static final int MAX_INJECTED_PENDING = 50_000;
    public static final int MAX_INJECTED_PER_CALL = 20_000;

    /**
     * Adds scripted items to run at their own time (not before {@link #now()}), merged into the script in time order:
     * the scenario lab's way to start an attack "now" through the real collectors.
     */
    public int inject(List<Object> items) {
        if (items.isEmpty() || items.size() > MAX_INJECTED_PER_CALL) {
            throw new IllegalArgumentException("1 to " + MAX_INJECTED_PER_CALL + " items");
        }
        synchronized (lock) {
            List<Timed> add = new ArrayList<>(items.size());
            Instant now = org.clock.instant();
            for (Object o : items) {
                Instant at = switch (o) {
                    case SimOrganisation.Step s -> s.at();
                    case SimTelemetry.Item i -> i.at();
                    default -> throw new IllegalArgumentException("not a scripted item");
                };
                if (at.isBefore(now)) {
                    throw new IllegalArgumentException("an item dated before the scenario's current time");
                }
                add.add(new Timed(at, o, true));
            }
            if (injectedPending + add.size() > MAX_INJECTED_PENDING) {
                throw new IllegalStateException("too many injected items are still waiting to run");
            }
            injectedPending += add.size();
            List<Timed> tail = new ArrayList<>(script.subList(next, script.size()));
            tail.addAll(add);
            tail.sort(Comparator.comparing(Timed::at));
            script.subList(next, script.size()).clear();
            script.addAll(tail);
            flushed = false;
            return add.size();
        }
    }

    /** Runs the first {@code days} simulated days of the script at once (the warm-up before going live). */
    public Progress warmUp(int days) {
        return advanceTo(scriptStart.plus(Duration.ofDays(days)));
    }

    private void runItem(Timed t) {
        switch (t.item()) {
            case SimOrganisation.Step s -> {
                requests.addAndGet(org.run(pdp, List.of(s)).size());
            }
            case SimTelemetry.RawLine r -> {
                org.clock.set(t.at());
                if (r.source() == SimTelemetry.Source.FIREWALL) {
                    firewall.offer(r.text(), r.at());
                } else {
                    cloud.offer(r.text(), r.at());
                }
                pump(t.at());
            }
            case SimTelemetry.EndpointBatch b -> {
                org.clock.set(t.at());
                endpoint.offer(renumbered(b), b.at());
                pump(t.at());
            }
            default -> throw new IllegalStateException("unknown script item");
        }
    }

    /** The batch with the next number for its device, signed by that device's agent key (see {@link #inject}). */
    private EndpointCollector.Batch renumbered(SimTelemetry.EndpointBatch b) {
        SimOrganisation.User u = org.users.stream().filter(x -> x.laptop().equals(b.deviceId())).findFirst()
                .orElseThrow(() -> new IllegalStateException("endpoint batch for an unknown device"));
        long number = batchNumbers.merge(b.deviceId(), 1L, Long::sum);
        byte[] msg = dev.dwarpal.crypto.SignedMessages.endpointTelemetry(b.deviceId(), number, b.at(),
                dev.dwarpal.crypto.Digests.sha256Hex(b.body()));
        return new EndpointCollector.Batch(b.deviceId(), b.keyId(), number, b.at(), b.body(),
                dev.dwarpal.crypto.Ed25519.sign(u.laptopKey().getPrivate(), msg));
    }

    private void pump(Instant at) {
        Ingestor.Report rep = ingestor.pump(at, 10_000);
        if (rep.problem().isPresent()) {
            throw new IllegalStateException("ingestion stopped: " + rep.problem().get());
        }
    }

    /** Detectors read only what is new; alerts go to E's risk, then F's cases, in time order. */
    private int detectAndTriage(boolean ended) {
        pending.clear();
        int before = uebaAlerts.size();
        while (detection.poll().events() > 0) {
            // read what the chain gained
        }
        if (ended && !flushed) {
            // the script is over: close the windows that no later event will ever close
            detection.flush();
            flushed = true;
        }
        while (correlation.run(correlationCursor, 10_000).read() > 0) {
            if (correlation.broken().isPresent()) {
                throw new IllegalStateException("correlation stopped: " + correlation.broken().get());
            }
        }
        while (ueba.poll(uebaCursor, 5_000) > 0) {
            // E judges every new event against its baselines
        }
        for (Alert u : uebaAlerts.subList(before, uebaAlerts.size())) {
            pending.add(new Raised(u, "E"));
        }
        store.refresh(100_000);
        List<Raised> fresh = new ArrayList<>(pending);
        fresh.sort(Comparator.comparing((Raised r) -> r.alert().raisedAt()));
        for (Raised r : fresh) {
            if (r.alert().raisedAt().isAfter(org.clock.instant())) {
                org.clock.set(r.alert().raisedAt());
            }
            if (!r.engine().equals("E")) {
                ueba.raise(r.alert());
            }
            cases.raise(r.alert());
            raised.add(r);
        }
        return fresh.size();
    }

    /** The chain's head is written to the anchor whenever it moves; a reader compares the chain with it. */
    private void anchorHead() {
        AuditLog.Head head = org.audit.head();
        if (head.sequence() > anchored) {
            anchor.anchor(head);
            anchored = head.sequence();
        }
    }

    /** The simulated sensor's signed acknowledgements go back to the isolation tracker; unacknowledged commands are resent. */
    private void processSensor() {
        for (var ack : sensor.drain()) {
            isolation.acknowledge(ack);
        }
        isolation.redeliver();
    }

    // ---- what the console and the scenario controls need ------------------------------------------------

    /** Ranked alerts as the case manager holds them. */
    public List<RankedAlert> rankedNow() {
        return cases.all().stream().flatMap(v -> v.alerts().stream()).toList();
    }

    /** Requests the engine has decided since the lab started. */
    public long requestsDecided() {
        return requests.get();
    }

    /** The daily report for the scenario's current day (every figure states where its data came from). */
    public SocReport dailyReport() {
        LocalDate day = LocalDate.ofInstant(org.clock.instant(), ZoneOffset.UTC);
        long days = Math.max(1, Duration.between(scriptStart, scriptEnd).toDays() + 1);
        return SocReport.daily(DataSource.simulated(config.seed(), config.users(), (int) days, requests.get()), day,
                rankedNow(), ueba.unlocked(), List.of(), ueba.unlocked().techniques());
    }

    /**
     * A verdict signed by an analyst with the lab's own analyst key. This is the lab's stand-in for the analyst's
     * hardware-bound key (see the console contract): only "ana" and "ben" have signing keys, leads sign none.
     */
    public Verdict signVerdict(String analystId, String alertId, Verdict.Outcome outcome) {
        return org.verdict(analystId, alertId, outcome, org.clock.instant());
    }

    /**
     * What the console server signs its calls with: one short assertion per call naming the analyst it acts for.
     * Hold it in the console process only.
     */
    public Delegation.Issuer delegationIssuer() {
        return new Delegation.Issuer(org.consoleKey.getPrivate(), SimOrganisation.CONSOLE_KEY_ID, org.clock);
    }

    /** The https address of the SOC API. */
    public String socApiUrl() {
        return "https://localhost:" + socApi.port();
    }

    @Override
    public void close() {
        socApi.close();
    }
}

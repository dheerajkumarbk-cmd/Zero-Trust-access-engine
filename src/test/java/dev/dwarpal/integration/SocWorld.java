package dev.dwarpal.integration;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.engine.DenyListGate;
import dev.dwarpal.engine.HoneytokenGate;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.engine.PolicyEngineTest;
import dev.dwarpal.response.CaseBook;
import dev.dwarpal.response.Enforcement;
import dev.dwarpal.response.ResponseSettings;
import dev.dwarpal.response.SignalLedger;
import dev.dwarpal.response.VerdictGate;
import dev.dwarpal.response.WatchlistScorer;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.siem.DetectionEngine;
import dev.dwarpal.siem.platform.CloudCollector;
import dev.dwarpal.siem.platform.CorrelationEngine;
import dev.dwarpal.siem.platform.EndpointCollector;
import dev.dwarpal.siem.platform.EventStore;
import dev.dwarpal.siem.platform.FirewallCollector;
import dev.dwarpal.siem.platform.Ingestor;
import dev.dwarpal.siem.platform.RuleBook;
import dev.dwarpal.sim.SimOrganisation;
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
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertSink;
import dev.dwarpal.soc.Asset;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.InMemoryAssetCatalog;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.Technique;
import dev.dwarpal.ueba.PeerGroups;
import dev.dwarpal.ueba.TechniqueMap;
import dev.dwarpal.ueba.Ueba;
import dev.dwarpal.ueba.UebaRisk;
import dev.dwarpal.ueba.UebaSettings;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The whole Layer 5 + 5.2 SOC on one simulated organisation (seed 7, 60 users), wired the way a deployment would
 * be, so a test can follow one attack from a raw syslog line to a closed case:
 *
 * <pre>
 *   raw lines / signed batches --D collectors--> Ingestor --> keyed audit chain (SECURITY_EVENT records)
 *   chain --A DetectionEngine / D CorrelationEngine / E Ueba.poll--> alerts
 *   alerts --E risk + ranker--> F CaseManager (priority, SLA) --> analyst queue
 *   analyst signed verdict --> F Soar (B playbooks + gate) --> signal feed, revocation, device isolation
 *   signal feed --> engine decisions (watch list, deny list)
 * </pre>
 *
 * Nothing here is mocked except the sensor (a simulator that signs like a device agent) and the enforcement point
 * (it records revocations; the simulated organisation has no live sessions).
 */
final class SocWorld {

    /** An action the playbooks asked the enforcement point to take. */
    record Revocation(String kind, String id, String actor) {
    }

    /** One alert as it reached the shared pipeline, with the engine that raised it (A, D or E). */
    record Raised(Alert alert, String engine) {
    }

    static final Analyst ANA = new Analyst("ana", Analyst.Role.ANALYST);
    static final Analyst BEN = new Analyst("ben", Analyst.Role.ANALYST);
    /** A lead reads the reports; she signs no verdicts in these tests. */
    static final Analyst CLEO = new Analyst("cleo", Analyst.Role.LEAD);

    final SimOrganisation org;
    final SimTelemetry telemetry;
    final List<SimOrganisation.Step> traffic;
    final Map<String, SecurityEvent.Provenance> datasets = Map.of("firewall", SecurityEvent.Provenance.COLLECTED,
            "endpoint", SecurityEvent.Provenance.SIGNED_SENSOR, "cloud", SecurityEvent.Provenance.COLLECTED);
    final FirewallCollector firewall;
    final EndpointCollector endpoint;
    final CloudCollector cloud;
    final Ingestor ingestor;
    final EventStore store;
    final RuleBook rules;
    final Ueba ueba;
    final CaseBook book;
    final CaseManager cases;
    final VerdictGate gate;
    final VerdictGate uebaGate;
    final SimulatedSensor sensor;
    final DeviceIsolation isolation;
    final Soar soar;
    final PolicyEngine engine;
    final DecisionPoint pdp;
    final InMemoryAssetCatalog assets;
    final String ceo;
    final List<Revocation> revocations = new CopyOnWriteArrayList<>();
    final List<Raised> raised = new ArrayList<>();
    final List<Alert> uebaAlerts = new ArrayList<>();
    final List<SimOrganisation.Result> results = new ArrayList<>();
    final ResponseSettings settings;
    AuditCursor uebaCursor;
    private long forgedSeq = 9_000_000;

    SocWorld(Path connectorDir) {
        org = SimOrganisation.create(7, 60);
        traffic = org.traffic();
        telemetry = SimTelemetry.of(org, traffic);

        // the CEO is somebody the telemetry script casts in no attack and no look-alike
        Set<String> cast = new HashSet<>();
        telemetry.cast().values().forEach(cast::addAll);
        ceo = org.users.stream().map(SimOrganisation.User::id).filter(u -> !cast.contains(u)).findFirst().orElseThrow();
        settings = ResponseSettings.defaults().withProtected(Set.of(ceo, "ana", "ben"), Set.of());

        // ---- part D: collectors into the chain
        firewall = new FirewallCollector("e2e", telemetry.leases());
        endpoint = new EndpointCollector("e2e", org.keys);
        cloud = new CloudCollector("e2e", telemetry.leases());
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
        ueba = new Ueba(UebaSettings.reference(), UebaRisk.Settings.reference(),
                PeerGroups.of(telemetry.departments(), assets), assets, techniques, uebaAlerts::add);

        // ---- parts B and F: an engine that reads the signal feed, cases, playbooks, isolation
        engine = PolicyEngine.builder().policySet(PolicyEngineTest.POLICIES).directory(org.directory).keyRing(org.keys)
                .gate(new HoneytokenGate()).gate(new DenyListGate())
                .scorers(withWatchlist(org))
                .aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                .costModel(new CostModel(1000, 1, 20, 0.05)).build();
        pdp = org.pipeline(engine);
        book = new CaseBook(settings, org.audit, org.clock);
        cases = new CaseManager(book, ueba, org.audit, org.clock, CaseSettings.defaults(), List.of(ANA, BEN, CLEO));
        gate = new VerdictGate(org.keys, org.clock);
        uebaGate = new VerdictGate(org.keys, org.clock);
        sensor = new SimulatedSensor(org.clock);
        for (SimOrganisation.User u : org.users) {
            sensor.enrol(u.laptop(), "agent-" + u.laptop(), u.laptopKey().getPrivate());
        }
        isolation = new DeviceIsolation(org.keys, sensor, org.audit, org.clock, Duration.ofMinutes(10), 1_000);
        PlaybookCompiler.Compilation c = new PlaybookCompiler(RuleCatalogue.reference(), settings,
                Set.of("ticket", "chat"), true).compileReference();
        assertTrue(c.set().isPresent(), "the shipped playbooks compile strictly: " + c.findings());
        soar = Soar.builder(org.audit, new SignalLedger(org.signals, org.clock)).settings(settings).cases(book, cases)
                .verdicts(gate).enforcement(enforcement()).clock(org.clock).isolation(isolation)
                .connectors(List.of(new FileConnector("ticket", Connector.Kind.TICKET, connectorDir, 1_000, org.clock),
                        new FileConnector("chat", Connector.Kind.CHAT, connectorDir, 1_000, org.clock)))
                .playbooks(c.set().get()).assets(assets).build();
    }

    private static List<dev.dwarpal.risk.RiskScorer> withWatchlist(SimOrganisation org) {
        List<dev.dwarpal.risk.RiskScorer> all = new ArrayList<>(dev.dwarpal.risk.scorers.StandardScorers.all(org.history,
                org.trust, org.failures, () -> org.threatIntel));
        all.add(new WatchlistScorer(org.signals, org.clock));
        return all;
    }

    private Enforcement enforcement() {
        return new Enforcement() {
            @Override
            public int revokeSession(String s, String a, String r) {
                revocations.add(new Revocation("session", s, a));
                return 0;
            }

            @Override
            public int revokeSubject(String s, String a, String r) {
                revocations.add(new Revocation("subject", s, a));
                return 0;
            }

            @Override
            public int revokeDevice(String s, String a, String r) {
                revocations.add(new Revocation("device", s, a));
                return 0;
            }

            @Override
            public Set<String> rolesOf(String s, Instant n) {
                return org.directory.subject(s).map(x -> x.roles()).orElse(Set.of());
            }
        };
    }

    // ---- running ----------------------------------------------------------------------------------------

    /** Dwarpal's own traffic and the raw telemetry, in time order, into the one keyed chain. */
    void collectEverything() {
        record Timed(Instant at, Object item) {
        }
        List<Timed> all = new ArrayList<>();
        traffic.forEach(s -> all.add(new Timed(s.at(), s)));
        telemetry.items().forEach(i -> all.add(new Timed(i.at(), i)));
        all.sort(Comparator.comparing(Timed::at));
        for (Timed t : all) {
            switch (t.item()) {
                case SimOrganisation.Step s -> results.addAll(org.run(pdp, List.of(s)));
                case SimTelemetry.RawLine r -> {
                    if (r.source() == SimTelemetry.Source.FIREWALL) {
                        firewall.offer(r.text(), r.at());
                    } else {
                        cloud.offer(r.text(), r.at());
                    }
                }
                case SimTelemetry.EndpointBatch b -> endpoint.offer(new EndpointCollector.Batch(b.deviceId(), b.keyId(),
                        b.batch(), b.at(), b.body(), b.signature()), b.at());
                default -> throw new IllegalStateException();
            }
            if (!(t.item() instanceof SimOrganisation.Step)) {
                org.clock.set(t.at());
                Ingestor.Report rep = ingestor.pump(t.at(), 10_000);
                assertTrue(rep.problem().isEmpty(), rep.problem().toString());
            }
        }
        while (store.refresh(10_000).read() > 0) {
            // index the whole chain for search
        }
    }

    /**
     * Runs the three detectors on the chain and feeds every alert, in time order, to E's risk and then to F's case
     * manager (which asks E to rank it). UEBA's own alerts go to cases only (they already count in its risk).
     */
    void detectAndTriage() {
        List<Raised> buffer = new ArrayList<>();
        AlertSink fromA = a -> buffer.add(new Raised(a, "A"));
        AlertSink fromD = a -> buffer.add(new Raised(a, "D"));
        DetectionEngine a = new DetectionEngine(org.sink, org.auditKey, fromA, Optional::empty,
                DetectionEngine.Settings.defaults());
        while (a.poll().events() > 0) {
            // read the whole chain
        }
        a.flush();
        assertEquals(Optional.empty(), a.stopped());
        CorrelationEngine d = new CorrelationEngine(rules, fromD, CorrelationEngine.Settings.defaults());
        AuditCursor dc = AuditCursor.fromStart(org.sink, org.auditKey);
        while (d.run(dc, 10_000).read() > 0) {
            assertTrue(d.broken().isEmpty());
        }
        uebaCursor = AuditCursor.fromStart(org.sink, org.auditKey);
        AuditCursor ec = uebaCursor;
        while (ueba.poll(ec, 5_000) > 0) {
            // E judges every event against its baselines
        }
        for (Alert u : uebaAlerts) {
            buffer.add(new Raised(u, "E"));
        }
        buffer.sort(Comparator.comparing((Raised r) -> r.alert().raisedAt()));
        for (Raised r : buffer) {
            if (r.alert().raisedAt().isAfter(org.clock.instant())) {
                org.clock.set(r.alert().raisedAt());
            }
            if (!r.engine().equals("E")) {
                ueba.raise(r.alert());
            }
            cases.raise(r.alert());
            raised.add(r);
        }
    }

    List<RankedAlert> rankedNow() {
        return cases.all().stream().flatMap(v -> v.alerts().stream()).toList();
    }

    /** The audit records of one type, for assertions on what was written. */
    List<AuditRecord> records(String type) {
        return org.sink.snapshot().stream().filter(r -> r.type().equals(type)).toList();
    }

    // ---- helpers for tests ------------------------------------------------------------------------------

    /** Every event on the chain, by sequence number, read through the keyed cursor (malformed records skipped). */
    java.util.Map<Long, dev.dwarpal.soc.ChainedEvent> chainEvents() {
        java.util.Map<Long, dev.dwarpal.soc.ChainedEvent> out = new java.util.LinkedHashMap<>();
        AuditCursor c = AuditCursor.fromStart(org.sink, org.auditKey);
        for (AuditCursor.Batch b = c.next(5_000); !b.events().isEmpty(); b = c.next(5_000)) {
            assertEquals(Optional.empty(), b.problem(), "the chain is intact");
            for (var e : b.events()) {
                try {
                    out.put(e.sequence(), dev.dwarpal.soc.SecurityEvents.fromAudit(e));
                } catch (IllegalArgumentException ignored) {
                    // not an event record (a case, a playbook step, a verdict)
                }
            }
        }
        return out;
    }

    Alert alertOf(String rule, String entityId) {
        return raised.stream().map(Raised::alert).filter(a -> a.rule().equals(rule)
                && a.entities().stream().anyMatch(e -> e.id().equals(entityId))).findFirst()
                .orElseThrow(() -> new AssertionError("no " + rule + " alert about " + entityId));
    }

    List<Alert> alertsOf(String rule) {
        return raised.stream().map(Raised::alert).filter(a -> a.rule().equals(rule)).toList();
    }

    RankedAlert ranked(Alert a) {
        return cases.ranked(a.id()).orElseThrow(() -> new AssertionError("alert not in a case: " + a.id()));
    }

    /** Analysts sign a verdict now; a second analyst follows if the playbook asks for one. */
    dev.dwarpal.soar.Soar.Result decide(String alertId, dev.dwarpal.soc.Verdict.Outcome outcome) {
        Instant now = org.clock.instant();
        dev.dwarpal.soar.Soar.Result r = soar.handle(org.verdict("ana", alertId, outcome, now));
        if (r.status() == dev.dwarpal.response.Playbooks.Status.AWAITING_SECOND_ANALYST) {
            r = soar.handle(org.verdict("ben", alertId, outcome, now));
        }
        return r;
    }

    /** The first request a person made in the simulation (to ask the engine again after a response). */
    dev.dwarpal.domain.AccessRequest requestOf(String userId) {
        return traffic.stream().filter(s -> s instanceof SimOrganisation.RequestStep).map(s -> (SimOrganisation.RequestStep) s)
                .filter(r -> r.labelled().userId().equals(userId)).findFirst().orElseThrow().labelled().request();
    }

    // ---- attacker's tools (tests only) --------------------------------------------------------------------

    String addressOf(String laptop) {
        return telemetry.leases().entrySet().stream().filter(e -> e.getValue().equals(laptop)).map(Map.Entry::getKey)
                .findFirst().orElseThrow();
    }

    /** A syslog line anybody on the network could send: nothing in it proves who sent it. */
    String syslogFlow(Instant t, String src, String dst, int dport) {
        return "<134>1 " + t + " fw01 dwfw " + (++forgedSeq) + " - - action=allow src=" + src + " sport=50000 dst=" + dst
                + " dport=" + dport + " proto=tcp bytes=400 rule=out-any";
    }

    String cloudDownload(Instant t, String user, String address, long bytes) {
        return "{\"time\":\"" + t + "\",\"app\":\"drive\",\"user\":\"" + user + "\",\"ip\":\"" + address
                + "\",\"op\":\"file.download\",\"object\":\"/finance/forged-" + (++forgedSeq)
                + ".zip\",\"bytes\":" + bytes + ",\"share\":\"none\"}";
    }

    /**
     * Runs D's rules and E's detectors over what was added since {@code cutoff} and sends every new alert through
     * E's risk and F's case manager, like {@link #detectAndTriage}. Returns the new alerts.
     */
    List<Raised> triageNew(Instant cutoff) {
        List<Raised> fresh = new ArrayList<>();
        CorrelationEngine d = new CorrelationEngine(rules, a -> {
            if (a.raisedAt().isAfter(cutoff)) {
                fresh.add(new Raised(a, "D"));
            }
            return true;
        }, CorrelationEngine.Settings.defaults());
        AuditCursor dc = AuditCursor.fromStart(org.sink, org.auditKey);
        while (d.run(dc, 10_000).read() > 0) {
            assertTrue(d.broken().isEmpty());
        }
        int before = uebaAlerts.size();
        while (ueba.poll(uebaCursor, 5_000) > 0) {
            // E judges only the new records
        }
        for (Alert u : uebaAlerts.subList(before, uebaAlerts.size())) {
            fresh.add(new Raised(u, "E"));
        }
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
        return fresh;
    }
}

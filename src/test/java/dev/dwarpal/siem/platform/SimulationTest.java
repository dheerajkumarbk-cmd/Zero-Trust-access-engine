package dev.dwarpal.siem.platform;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.siem.DetectionEngine;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.sim.SimTelemetry;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EventSearch;
import dev.dwarpal.soc.SecurityEvent;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Part D end to end on the simulated organisation (seed 7, 60 people): raw syslog lines, signed endpoint batches
 * and cloud JSON go through the collectors into the same audit chain as Dwarpal's own decisions; the event store
 * and the correlation rules read it back through the keyed cursor. The generator and the rules are written by
 * the same team: these results show consistency with the threat model, not real-world accuracy.
 */
class SimulationTest {

    private static SimOrganisation org;
    private static SimTelemetry telemetry;
    private static Fx.Alerts alerts;
    private static Fx.Alerts partA;
    private static CorrelationEngine engine;
    private static EventStore store;
    private static Ingestor ingestor;
    private static final List<SimOrganisation.Result> RESULTS = new ArrayList<>();

    @BeforeAll
    static void run() {
        org = SimOrganisation.create(7, 60);
        List<SimOrganisation.Step> traffic = org.traffic();
        telemetry = SimTelemetry.of(org, traffic);
        FirewallCollector fw = new FirewallCollector("sim", telemetry.leases());
        EndpointCollector ep = new EndpointCollector("sim", org.keys);
        CloudCollector cl = new CloudCollector("sim", telemetry.leases());
        ingestor = new Ingestor(org.audit, List.of(
                new Ingestor.Registration(fw, SecurityEvent.Provenance.COLLECTED, 100_000, 100_000),
                new Ingestor.Registration(ep, SecurityEvent.Provenance.SIGNED_SENSOR, 100_000, 100_000),
                new Ingestor.Registration(cl, SecurityEvent.Provenance.COLLECTED, 100_000, 100_000)),
                Ingestor.Settings.defaults());
        DecisionPoint pdp = org.pipeline(org.engine());

        record Timed(Instant at, Object item) {
        }
        List<Timed> all = new ArrayList<>();
        traffic.forEach(s -> all.add(new Timed(s.at(), s)));
        telemetry.items().forEach(i -> all.add(new Timed(i.at(), i)));
        all.sort(Comparator.comparing(Timed::at));
        for (Timed t : all) {
            switch (t.item()) {
                case SimOrganisation.Step s -> RESULTS.addAll(org.run(pdp, List.of(s)));
                case SimTelemetry.RawLine r -> {
                    if (r.source() == SimTelemetry.Source.FIREWALL) {
                        fw.offer(r.text(), r.at());
                    } else {
                        cl.offer(r.text(), r.at());
                    }
                }
                case SimTelemetry.EndpointBatch b -> ep.offer(new EndpointCollector.Batch(b.deviceId(), b.keyId(),
                        b.batch(), b.at(), b.body(), b.signature()), b.at());
                default -> throw new IllegalStateException();
            }
            if (!(t.item() instanceof SimOrganisation.Step)) {
                org.clock.set(t.at());
                Ingestor.Report rep = ingestor.pump(t.at(), 10_000);
                assertTrue(rep.problem().isEmpty(), rep.problem().toString());
            }
        }
        alerts = new Fx.Alerts();
        engine = new CorrelationEngine(RuleBook.defaults(Map.of("firewall", SecurityEvent.Provenance.COLLECTED,
                "endpoint", SecurityEvent.Provenance.SIGNED_SENSOR, "cloud", SecurityEvent.Provenance.COLLECTED)),
                alerts, CorrelationEngine.Settings.defaults());
        AuditCursor cursor = AuditCursor.fromStart(org.sink, org.auditKey);
        while (engine.run(cursor, 10_000).read() > 0) {
            assertTrue(engine.broken().isEmpty());
        }
        store = new EventStore(AuditCursor.fromStart(org.sink, org.auditKey), 500_000);
        while (store.refresh(10_000).read() > 0) {
            // read the whole trail
        }
        partA = new Fx.Alerts();
        DetectionEngine a = new DetectionEngine(org.sink, org.auditKey, partA, Optional::empty,
                DetectionEngine.Settings.defaults());
        while (a.poll().events() > 0) {
            // read the whole trail
        }
        a.flush();
    }

    private static Set<String> about(String rule, Entity.Kind kind) {
        return alerts.of(rule).stream().flatMap(a -> a.entities().stream()).filter(e -> e.kind() == kind)
                .map(Entity::id).collect(Collectors.toCollection(java.util.TreeSet::new));
    }

    private static String laptop(String user) {
        return "laptop-" + user;
    }

    @Test
    void everythingWasIngestedAndNothingRefusedButTheNoise() {
        assertEquals(Map.of("firewall", Map.of(), "endpoint", Map.of(), "cloud", Map.of()), ingestor.refusals());
        assertEquals(0, engine.malformed());
        assertEquals(0, engine.ignoredAhead());
        assertEquals(0, store.malformed());
        Instant from = SimOrganisation.DAY_ZERO.minus(Duration.ofDays(1));
        Instant to = SimOrganisation.DAY_ZERO.plus(Duration.ofDays(10));
        EventSearch.Result failures = store.search("action = parse.failure", from, to, 100);
        assertEquals(4, failures.matched(), "the four noise lines, kept, not dropped");
        EventStore.Counts byDataset = store.counts("* | count by dataset", from, to);
        assertEquals(4, byDataset.groups().size());
        assertTrue(store.search("dataset = endpoint and provenance = signed_sensor", from, to, 1).matched() > 2_000);
    }

    @Test
    void a6TheStolenLaptopAtHomeIsCaughtByCorrelationNotByChangingTheEngine() {
        Set<String> a6Devices = new java.util.TreeSet<>();
        Set<String> a6Allowed = new java.util.TreeSet<>();
        for (SimOrganisation.Result r : RESULTS) {
            if (r.labelled().scenario() == SimOrganisation.Scenario.A6_STOLEN_LAPTOP_AT_HOME) {
                a6Devices.add(r.labelled().request().device().id());
                Decision d = r.decision();
                if (d.outcome() == Outcome.ALLOW) {
                    a6Allowed.add(r.labelled().request().device().id());
                }
            }
        }
        assertFalse(a6Allowed.isEmpty(), "the engine still allows the stolen laptop: the blind spot is real");
        assertEquals(a6Devices, about("stolen-laptop-collection", Entity.Kind.DEVICE), "every A6 laptop");
        assertEquals(a6Allowed, about("stolen-laptop-access", Entity.Kind.DEVICE), "every A6 laptop that got in");
        assertEquals(a6Devices, about("encoded-powershell", Entity.Kind.DEVICE));
        for (String admin : telemetry.admins()) {
            assertFalse(about("encoded-powershell", Entity.Kind.SUBJECT).contains(admin) && !a6Devices.contains(laptop(admin)),
                    "L6: an administrator's signed script is not encoded PowerShell");
        }
        assertTrue(engine.recent().stream().filter(r -> r.alert().rule().equals("stolen-laptop-access"))
                .allMatch(CorrelationEngine.Raised::actionable), "signed and verified evidence: actionable");
    }

    @Test
    void a8BeaconingIsSeenByTheFirewallAndAcrossEndpointAndFirewall() {
        Set<String> beaconing = telemetry.cast().get(SimTelemetry.Activity.A8_BEACONING).stream()
                .map(SimulationTest::laptop).collect(Collectors.toCollection(java.util.TreeSet::new));
        assertEquals(beaconing, about("beacon-regular-destination", Entity.Kind.DEVICE));
        assertEquals(Set.of(SimTelemetry.C2_ADDRESS), about("beacon-regular-destination", Entity.Kind.IP)
                .stream().filter(ip -> !ip.startsWith("10.")).collect(Collectors.toSet()));
        assertEquals(beaconing, about("beacon-from-document-process", Entity.Kind.DEVICE));
        assertTrue(alerts.of("beacon-regular-destination").stream()
                .allMatch(a -> a.summary().startsWith(CorrelationEngine.COLLECTED_ONLY)), "firewall only: collected");
        assertTrue(alerts.of("beacon-from-document-process").stream()
                .noneMatch(a -> a.summary().startsWith(CorrelationEngine.COLLECTED_ONLY)), "signed endpoint evidence");
    }

    @Test
    void a9CloudExfiltrationIsCaughtAndTheQuarterEndDownloadIsNot() {
        Set<String> exfil = telemetry.cast().get(SimTelemetry.Activity.A9_CLOUD_EXFIL);
        Set<String> quarterEnd = telemetry.cast().get(SimTelemetry.Activity.L5_BIG_LEGIT_DOWNLOAD);
        assertEquals(exfil, about("cloud-download-volume", Entity.Kind.SUBJECT));
        assertEquals(exfil, about("cloud-bulk-download-then-external-share", Entity.Kind.SUBJECT));
        assertTrue(about("cloud-download-volume", Entity.Kind.SUBJECT).stream().noneMatch(quarterEnd::contains));
        assertTrue(alerts.of("cloud-bulk-download-then-external-share").stream()
                .allMatch(a -> a.summary().startsWith(CorrelationEngine.COLLECTED_ONLY)),
                "a cloud export proves nothing about who wrote it: watch and rank, never act alone");
    }

    @Test
    void partARulesExpressedInTheLanguageAgreeWithPartAOnTheSameTrail() {
        Set<String> theirs = partA.list.stream().filter(a -> a.rule().equals("deny-storm-ip"))
                .flatMap(a -> a.entities().stream()).filter(e -> e.kind() == Entity.Kind.IP).map(Entity::id)
                .collect(Collectors.toCollection(java.util.TreeSet::new));
        Set<String> ours = new java.util.TreeSet<>(about("cr-deny-storm-ip", Entity.Kind.IP));
        ours.addAll(about("cr-spray-ip", Entity.Kind.IP));
        assertFalse(theirs.isEmpty());
        assertEquals(theirs, ours);
        Set<String> theirMfa = partA.list.stream().filter(a -> a.rule().equals("mfa-fatigue"))
                .flatMap(a -> a.entities().stream()).filter(e -> e.kind() == Entity.Kind.SUBJECT).map(Entity::id)
                .collect(Collectors.toSet());
        assertTrue(about("cr-mfa-fatigue", Entity.Kind.SUBJECT).containsAll(theirMfa));
    }

    @Test
    void noRuleFiresOnEverydayActivity() {
        Map<String, Integer> byRule = new TreeMap<>();
        alerts.list.forEach(a -> byRule.merge(a.rule(), 1, Integer::sum));
        assertFalse(byRule.containsKey(CorrelationEngine.FLOOD_RULE), byRule.toString());
        assertFalse(byRule.containsKey(CorrelationEngine.STATE_FULL_RULE));
        assertFalse(byRule.containsKey("telemetry-refused"));
        assertFalse(byRule.containsKey("telemetry-gap"));
        assertFalse(byRule.containsKey("collector-flooded"));
        Set<String> attackers = new java.util.TreeSet<>();
        telemetry.cast().get(SimTelemetry.Activity.A8_BEACONING).forEach(u -> attackers.add(laptop(u)));
        for (String rule : List.of("beacon-regular-destination", "beacon-from-document-process")) {
            for (Alert a : alerts.of(rule)) {
                assertTrue(a.entities().stream().anyMatch(e -> attackers.contains(e.id())), rule);
            }
        }
        System.out.println("part D alerts on the simulation by rule: " + byRule);
        System.out.println("silent rules: " + engine.silentRules());
    }
}

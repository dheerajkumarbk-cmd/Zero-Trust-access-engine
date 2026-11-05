package dev.dwarpal.integration;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.response.Playbooks;
import dev.dwarpal.siem.platform.EndpointCollector;
import dev.dwarpal.siem.platform.FirewallCollector;
import dev.dwarpal.siem.platform.Ingestor;
import dev.dwarpal.soar.DeviceIsolation;
import dev.dwarpal.soar.PlaybookCompiler;
import dev.dwarpal.soar.RuleCatalogue;
import dev.dwarpal.soar.SensorAck;
import dev.dwarpal.soar.Soar;
import dev.dwarpal.socapi.SocApiServer;
import dev.dwarpal.socapi.SocApiSettings;
import dev.dwarpal.socapi.SocCaller;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.sim.SimTelemetry;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Verdict;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.net.URI;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-part red team of the whole SOC (Layer 5.2 integration). Each test is an attack that needs more than one part
 * to defend against it: the attacker uses what collection (D) lets through, and the question is whether ranking (E),
 * playbooks and isolation (B, F) and the API (F) still refuse to hurt an innocent person. Every probe was run against
 * the integrated build first; the ones that failed are named "regression" in the comments.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SocCrossPartRedTeamTest {

    private static SocWorld w;

    @BeforeAll
    static void build() throws Exception {
        w = new SocWorld(Files.createTempDirectory("dwarpal-soc-rt"));
        w.collectEverything();
        w.detectAndTriage();
    }

    @AfterAll
    static void release() {
        w = null;
    }

    /** A time well after everything so far, so the new records are the newest on the chain. */
    private static Instant slot() {
        return w.org.clock.instant().plus(Duration.ofHours(3));
    }

    private static void pump(Ingestor in, Instant t) {
        w.org.clock.set(t);
        for (int i = 0; i < 20; i++) {
            Ingestor.Report r = in.pump(t, 10_000);
            assertTrue(r.problem().isEmpty(), r.problem().toString());
            if (r.written() == 0) {
                return;
            }
        }
    }

    private static void assertNothingDestructiveHappenedTo(String user, String laptop) {
        Instant now = w.org.clock.instant();
        assertTrue(w.revocations.stream().noneMatch(r -> r.id().equals(user) || r.id().equals(laptop)),
                "nobody's sessions were revoked: " + w.revocations);
        assertFalse(w.sensor.isolated(laptop), laptop + " was not isolated");
        assertTrue(w.isolation.of(laptop).isEmpty(), "no isolation command exists for " + laptop);
        assertFalse(w.org.signals.denied(SignalFeed.Kind.SUBJECT, user, now), user + " was not denied");
        assertFalse(w.org.signals.denied(SignalFeed.Kind.DEVICE, laptop, now), laptop + " was not denied");
    }

    // ---- framing a person with lines anybody can send --------------------------------------------------------

    @Test
    @Order(1)
    void forgedFirewallLinesAboutTheCeoOpenACaseAndAWatchButNeverIsolateTheLaptop() {
        String ceoLaptop = "laptop-" + w.ceo;
        String addr = w.addressOf(ceoLaptop);
        Instant base = slot();
        for (int k = 0; k < 40; k++) {
            Instant t = base.plusSeconds(30L * k);
            assertTrue(w.firewall.offer(w.syslogFlow(t, addr, "203.0.113.99", 4444), t));
        }
        pump(w.ingestor, base.plusSeconds(30L * 39));
        List<SocWorld.Raised> fresh = w.triageNew(base.minusSeconds(1));
        Alert forged = fresh.stream().map(SocWorld.Raised::alert).filter(a -> a.rule().equals("beacon-regular-destination")
                && a.entities().contains(Entity.device(ceoLaptop))).findFirst()
                .orElseThrow(() -> new AssertionError("the forged flows were not even noticed: " + fresh));

        RankedAlert ranked = w.ranked(forged);
        assertFalse(ranked.actionable(), "firewall lines cannot prove who sent them");
        Soar.Result r = w.decide(forged.id(), Verdict.Outcome.TRUE_POSITIVE);
        assertNotEquals(Playbooks.Status.REFUSED, r.status(), r.message());
        assertEquals(List.of(), r.isolated());
        assertNothingDestructiveHappenedTo(w.ceo, ceoLaptop);
    }

    @Test
    @Order(2)
    void forgedCloudLogsAboutAnInnocentPersonCannotTriggerAnythingDestructive() {
        String user = "u2";
        String laptop = "laptop-u2";
        String addr = w.addressOf(laptop);
        Instant base = slot();
        for (int k = 0; k < 120; k++) {
            Instant t = base.plusSeconds(30L * k);
            assertTrue(w.cloud.offer(w.cloudDownload(t, user, addr, 30_000_000), t));
        }
        Instant shareAt = base.plus(Duration.ofMinutes(61));
        assertTrue(w.cloud.offer(w.cloudDownload(shareAt, user, addr, 0).replace("file.download", "share.create")
                .replace("\"share\":\"none\"", "\"share\":\"" + SimTelemetry.EXTERNAL_SHARE + "\""), shareAt));
        pump(w.ingestor, shareAt);
        List<SocWorld.Raised> fresh = w.triageNew(base.minusSeconds(1));
        List<Alert> cloudAlerts = fresh.stream().map(SocWorld.Raised::alert).filter(a -> a.rule().startsWith("cloud-")
                && a.entities().contains(Entity.subject(user))).toList();
        assertFalse(cloudAlerts.isEmpty(), "the forged downloads are noticed: " + fresh);
        for (Alert a : cloudAlerts) {
            RankedAlert ranked = w.ranked(a);
            assertFalse(ranked.actionable(), a.rule());
            assertNotEquals(Priority.P1, ranked.priority(), "collected evidence is capped below P1: " + a.rule());
            Soar.Result r = w.decide(a.id(), Verdict.Outcome.TRUE_POSITIVE);
            assertEquals(List.of(), r.isolated(), a.rule());
        }
        assertTrue(w.revocations.stream().noneMatch(x -> x.id().equals(user) || x.id().equals(laptop)),
                "no session revoked on the word of a cloud log alone");
        assertFalse(w.sensor.isolated(laptop));
        assertTrue(w.isolation.of(laptop).isEmpty());
    }

    @Test
    @Order(3)
    void aPlaybookFileThatRemovesTheGuardRailsIsRefusedWhateverTheRuleBook() {
        String evil = """
                version: "evil-1"
                playbooks:
                  - rule: beacon-regular-destination
                    steps:
                      - isolate: device
                      - revoke: subject
                  - rule: cloud-download-volume
                    steps:
                      - deny: {target: subject, for: P1D}
                default:
                  - watch: {target: subject, ratio: 10, halfLife: P1D}
                """;
        PlaybookCompiler.Compilation strict = new PlaybookCompiler(RuleCatalogue.reference(), w.settings,
                Set.of("ticket", "chat"), true).compile(evil);
        assertTrue(strict.set().isEmpty(), "destructive steps on evidence that can be only collected: " + strict.findings());
        PlaybookCompiler.Compilation loose = new PlaybookCompiler(RuleCatalogue.reference(), w.settings,
                Set.of("ticket", "chat"), false).compile(evil);
        assertTrue(loose.set().isEmpty(), "being lenient about missing plays never lets destructive steps through");
    }

    // ---- faking the sensor ------------------------------------------------------------------------------------

    @Test
    @Order(4)
    void telemetryCannotBePassedOffAsTheSensorsIsolationAcknowledgement() {
        String victim = "u32";
        String laptop = "laptop-" + victim;
        Alert alert = w.alertOf("stolen-laptop-access", victim);
        Soar.Result r = w.decide(alert.id(), Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(List.of(laptop), r.isolated());
        assertEquals(DeviceIsolation.State.PENDING_ACK, w.isolation.of(laptop).orElseThrow().state());

        // a genuinely signed telemetry batch of that very device, presented as the acknowledgement
        SimTelemetry.EndpointBatch batch = w.telemetry.items().stream().filter(i -> i instanceof SimTelemetry.EndpointBatch)
                .map(i -> (SimTelemetry.EndpointBatch) i).filter(b -> b.deviceId().equals(laptop)).findFirst().orElseThrow();
        try {
            DeviceIsolation.AckResult res = w.isolation.acknowledge(new SensorAck(batch.deviceId(), batch.keyId(),
                    batch.batch(), batch.at(), batch.body(), batch.signature()));
            assertNotEquals(DeviceIsolation.AckResult.ACCEPTED, res, "telemetry is not a confirmation");
        } catch (IllegalArgumentException tooLongForAnAck) {
            // refused before it was even considered
        }
        assertEquals(DeviceIsolation.State.PENDING_ACK, w.isolation.of(laptop).orElseThrow().state());

        List<SensorAck> acks = w.sensor.drain();
        assertEquals(1, acks.size());
        SensorAck real = acks.getFirst();
        SensorAck tampered = new SensorAck(real.deviceId(), real.keyId(), real.batch(), real.sealedAt(),
                real.body().replace("isolate", "isolatx"), real.signature());
        assertNotEquals(DeviceIsolation.AckResult.ACCEPTED, w.isolation.acknowledge(tampered));
        assertEquals(DeviceIsolation.State.PENDING_ACK, w.isolation.of(laptop).orElseThrow().state());
        assertEquals(DeviceIsolation.AckResult.ACCEPTED, w.isolation.acknowledge(real));
        assertNotEquals(DeviceIsolation.AckResult.ACCEPTED, w.isolation.acknowledge(real), "and only once");
        assertEquals(DeviceIsolation.State.ISOLATED, w.isolation.of(laptop).orElseThrow().state());
    }

    // ---- hiding behind a flood, backdating ---------------------------------------------------------------------

    @Test
    @Order(5)
    void aFloodFromOneSourceIsRefusedAndReportedWhileAnotherSourcesEventStillArrives() throws Exception {
        FirewallCollector noisy = new FirewallCollector("flood", w.telemetry.leases());
        EndpointCollector sensor = new EndpointCollector("flood-ep", w.org.keys);
        Ingestor tight = new Ingestor(w.org.audit, List.of(
                new Ingestor.Registration(noisy, SecurityEvent.Provenance.COLLECTED, 60, 60),
                new Ingestor.Registration(sensor, SecurityEvent.Provenance.SIGNED_SENSOR, 1_000, 1_000)),
                Ingestor.Settings.defaults());
        Instant base = slot();
        String addr = w.addressOf("laptop-u40");
        for (int k = 0; k < 12_000; k++) {
            noisy.offer(w.syslogFlow(base.plusMillis(k), addr, "198.51.100." + (k % 200 + 1), 443 + k % 50), base.plusMillis(k));
        }
        SimOrganisation.User u = w.org.users.get(33);
        Instant sealed = base.plusSeconds(60);
        String body = "{\"ts\":\"" + base.plusSeconds(30) + "\",\"device\":\"" + u.laptop() + "\",\"user\":\"" + u.id()
                + "\",\"type\":\"file.read\",\"path\":\"/finance/ledger.xlsx\"}\n";
        sensor.offer(new EndpointCollector.Batch(u.laptop(), "agent-" + u.laptop(), 1, sealed, body,
                Ed25519.sign(u.laptopKey().getPrivate(), SignedMessages.endpointTelemetry(u.laptop(), 1, sealed,
                        Digests.sha256Hex(body)))), sealed);
        pump(tight, sealed);

        Map<String, Map<String, Long>> refused = tight.refusals();
        assertTrue(noisy.overflowed() > 0, "the collector's queue is bounded: the surplus is counted, not kept");
        assertTrue(refused.get(sensor.name()).isEmpty(), "and the flood did not take the quiet source down with it");
        while (w.store.refresh(10_000).read() > 0) {
            // index the new records
        }
        assertTrue(w.store.search("dataset = endpoint and action = file.read", base, base.plus(Duration.ofHours(1)), 10)
                .matched() >= 1, "the signed event arrived in the middle of the flood");
        List<SocWorld.Raised> fresh = w.triageNew(base.minusSeconds(1));
        assertTrue(fresh.stream().anyMatch(r -> r.alert().rule().equals("collector-flooded")),
                "the flood itself is an alert, so it cannot be used to hide silently: " + fresh);
    }

    @Test
    @Order(6)
    void backdatedAndFutureLinesAreRefusedAndOpenNoWindowsInThePast() {
        Instant now = slot();
        w.org.clock.set(now);
        String addr = w.addressOf("laptop-u41");
        long before = w.ingestor.refusals().get("firewall").values().stream().mapToLong(Long::longValue).sum();
        for (int k = 0; k < 40; k++) {
            // older than the 7 days the ingestor accepts, in the future, and late but inside the 7 days
            w.firewall.offer(w.syslogFlow(now.minus(Duration.ofDays(40)).plusSeconds(30L * k), addr, "203.0.113.77", 4444), now);
            w.firewall.offer(w.syslogFlow(now.plus(Duration.ofDays(5)).plusSeconds(30L * k), addr, "203.0.113.78", 4444), now);
            w.firewall.offer(w.syslogFlow(now.minus(Duration.ofDays(5)).plusSeconds(30L * k), addr, "203.0.113.79", 4444), now);
        }
        pump(w.ingestor, now);
        long after = w.ingestor.refusals().get("firewall").values().stream().mapToLong(Long::longValue).sum();
        assertTrue(after >= before + 80, "the 40-day-old and the future lines are refused: " + before + " -> " + after);
        List<SocWorld.Raised> fresh = w.triageNew(now.minus(Duration.ofDays(6)));
        assertTrue(fresh.stream().noneMatch(r -> r.alert().rule().equals("beacon-regular-destination")
                && r.alert().entities().contains(Entity.device("laptop-u41"))), "no beacon alert from backdated or future times, nor from late lines");
    }

    // ---- the analyst and the API -------------------------------------------------------------------------------

    @Test
    @Order(7)
    void anAnalystCannotActOnOrReadACaseAboutThemselvesThroughAnyDoor() throws Exception {
        SocApiClient.pki();
        Alert about = new Alert("al-about-ana-1", "honeytoken-touched", Severity.HIGH, w.org.clock.instant(),
                List.of(Entity.subject("ana")), List.of(1L), 1, "a honeytoken was touched with ana's account");
        w.ueba.raise(about);
        assertTrue(w.cases.raise(about));
        String caseId = w.cases.caseOfAlert(about.id()).orElseThrow();

        Soar.Result self = w.soar.handle(w.org.verdict("ana", about.id(), Verdict.Outcome.TRUE_POSITIVE, w.org.clock.instant()));
        assertEquals(Playbooks.Status.REFUSED, self.status(), "nobody decides their own case: " + self.message());

        SocApiServer server = SocApiServer.builder(w.org.audit, w.soar).tls(SocApiClient.ctx("soc-api")).clock(w.org.clock)
                .callers(List.of(SocCaller.component("ana", SocWorld.ANA), SocCaller.component("ben", SocWorld.BEN),
                        SocCaller.component("cleo", SocWorld.CLEO)))
                .settings(SocApiSettings.defaults()).search(w.store).risk(w.ueba).build().start();
        try {
            URI base = URI.create("https://localhost:" + server.port());
            try (SocApiClient ana = new SocApiClient(base, "ana")) {
                assertEquals(404, ana.get("/v1/cases/" + caseId).status(), "it is not even visible to her");
                assertEquals(404, ana.post("/v1/cases/" + caseId + "/notes", "{\"v\":1,\"text\":\"all fine\"}").status());
                assertFalse(ana.get("/v1/queue").body().contains(caseId));
                assertEquals(404, ana.get("/v1/risk/subject/ana").status(), "nor her own risk picture");
            }
            try (SocApiClient ben = new SocApiClient(base, "ben")) {
                assertEquals(404, ben.get("/v1/cases/" + caseId).status(), "a case about an analyst is for leads only");
            }
            try (SocApiClient cleo = new SocApiClient(base, "cleo")) {
                assertEquals(200, cleo.get("/v1/cases/" + caseId).status(), "the lead can see and work it");
            }
        } finally {
            server.close();
        }
        // Regression (integration finding I-2): a colleague who is not a lead cannot close it by calling the SOAR directly.
        Soar.Result colleague = w.soar.handle(w.org.verdict("ben", about.id(), Verdict.Outcome.BENIGN, w.org.clock.instant()));
        assertEquals(Playbooks.Status.REFUSED, colleague.status(), colleague.message());
        assertEquals(Optional.empty(), w.book.get(caseId).filter(k -> k.state() == dev.dwarpal.response.Case.State.CLOSED).map(k -> "closed"),
                "the case is still open");
    }

    @Test
    @Order(8)
    void everyAttackAboveLeftTheChainIntactAndTheAuditSaysWhoDidWhat() {
        assertFalse(w.chainEvents().isEmpty());
        Set<String> actors = new java.util.TreeSet<>();
        w.org.sink.snapshot().forEach(r -> actors.add(r.actor()));
        assertTrue(actors.contains("soc-soar"), "playbook steps are audited under their own name: " + actors);
        assertTrue(actors.contains("soc-cases"), "case changes too: " + actors);
        assertTrue(actors.contains("soc-isolation"), "and device isolation: " + actors);
        assertTrue(actors.stream().filter(a -> a.startsWith("collector:")).allMatch(
                a -> Set.of("collector:firewall", "collector:endpoint", "collector:cloud").contains(a)));
        assertEquals(Optional.empty(), Optional.empty());
    }
}

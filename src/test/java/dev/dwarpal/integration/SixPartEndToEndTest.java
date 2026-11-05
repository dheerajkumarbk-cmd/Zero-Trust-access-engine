package dev.dwarpal.integration;

import dev.dwarpal.analytics.AuditDecisions;
import dev.dwarpal.analytics.DataSource;
import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.response.Playbooks;
import dev.dwarpal.siem.platform.EventStore;
import dev.dwarpal.soar.DeviceIsolation;
import dev.dwarpal.soar.SensorAck;
import dev.dwarpal.soar.Soar;
import dev.dwarpal.socapi.SocApiServer;
import dev.dwarpal.socapi.SocApiSettings;
import dev.dwarpal.socapi.SocCaller;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.ChainedEvent;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EventSearch;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.Verdict;
import dev.dwarpal.ueba.SocReport;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Layer 5 and 5.2 together: all six SOC parts (A detection, B response, C analytics, D SIEM platform, E UEBA and
 * prioritisation, F SOAR, cases and SOC API) on one simulated organisation (seed 7, 60 users), from raw syslog
 * lines to a signed verdict and the engine's next decision. The generator and the rules are written by the same
 * team: these results show that the parts agree with each other and with the threat model, not real-world
 * accuracy.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SixPartEndToEndTest {

    private static SocWorld w;
    private static Map<Long, ChainedEvent> chain;

    @BeforeAll
    static void build() throws Exception {
        w = new SocWorld(Files.createTempDirectory("dwarpal-soc-connectors"));
        w.collectEverything();
        w.detectAndTriage();
        chain = w.chainEvents();
    }

    @AfterAll
    static void release() {
        // the world holds the whole simulated trail: let it go, so later test classes in the same JVM are not slowed
        // by garbage collection (the API latency probe is sensitive to it)
        w = null;
        chain = null;
    }

    private static Set<String> datasetsOf(Alert a) {
        Set<String> s = new TreeSet<>();
        for (long q : a.evidence()) {
            ChainedEvent e = chain.get(q);
            assertTrue(e != null, "evidence " + q + " of " + a.id() + " is on the chain");
            s.add(e.event().dataset());
        }
        return s;
    }

    // ---- D: collection ------------------------------------------------------------------------------------

    @Test
    @Order(1)
    void everySourceLandsInTheOneKeyedChainAndOnlyTheNoiseIsRefused() {
        assertEquals(Map.of("firewall", Map.of(), "endpoint", Map.of(), "cloud", Map.of()), w.ingestor.refusals());
        Set<String> actors = new TreeSet<>();
        for (var r : w.records("SECURITY_EVENT")) {
            actors.add(r.actor());
        }
        assertEquals(Set.of("collector:firewall", "collector:endpoint", "collector:cloud"), actors,
                "each collector writes under its own name: nobody can write as Dwarpal's own pipeline");
        assertFalse(w.records("ACCESS_DECISION").isEmpty(), "Dwarpal's own decisions are on the same chain");
        Set<String> datasets = new TreeSet<>();
        chain.values().forEach(e -> datasets.add(e.event().dataset()));
        assertEquals(Set.of("firewall", "endpoint", "cloud", "dwarpal.audit"), datasets);
    }

    @Test
    @Order(2)
    void provenanceFollowsTheSourceAndCannotBeUpgradedByTheLine() {
        for (ChainedEvent c : chain.values()) {
            SecurityEvent e = c.event();
            switch (e.dataset()) {
                case "endpoint" -> assertEquals(SecurityEvent.Provenance.SIGNED_SENSOR, e.provenance());
                case "firewall", "cloud" -> assertEquals(SecurityEvent.Provenance.COLLECTED, e.provenance());
                default -> assertEquals(SecurityEvent.Provenance.VERIFIED_AUDIT, e.provenance());
            }
        }
    }

    @Test
    @Order(3)
    void theEventStoreSearchesTheSameChain() {
        Instant from = SimOrganisation.DAY_ZERO.minus(Duration.ofDays(1));
        Instant to = SimOrganisation.DAY_ZERO.plus(Duration.ofDays(12));
        EventStore.Counts byDataset = w.store.counts("* | count by dataset", from, to);
        assertEquals(4, byDataset.groups().size());
        assertTrue(w.store.search("dataset = endpoint and provenance = signed_sensor", from, to, 1).matched() > 2_000);
        EventSearch.Result forged = w.store.search("dataset = firewall and provenance = signed_sensor", from, to, 1);
        assertEquals(0, forged.matched(), "no firewall line is ever signed-sensor evidence");
    }

    // ---- A + D + E: detection and prioritisation -------------------------------------------------------------

    @Test
    @Order(4)
    void everyAlertCitesRecordsThatReallyAreOnTheChain() {
        long head = w.org.sink.snapshot().getLast().sequence();
        for (SocWorld.Raised r : w.raised) {
            Alert a = r.alert();
            assertFalse(a.evidence().isEmpty(), a.id());
            for (long q : a.evidence()) {
                assertTrue(q >= 1 && q <= head, "evidence " + q + " of " + a.id());
            }
        }
    }

    @Test
    @Order(5)
    void theStolenLaptopOfEveryUserBecomesAnActionableP1() {
        for (SimOrganisation.User u : w.org.users) {
            RankedAlert access = w.ranked(w.alertOf("stolen-laptop-access", u.id()));
            assertEquals(Priority.P1, access.priority(), u.id());
            assertTrue(access.actionable(), "signed sensor evidence and the user's own sign-in: " + u.id());
        }
    }

    @Test
    @Order(6)
    void beaconingIsP1ThroughTheDocumentProcessAndOnlyAWatchThroughTheFirewallAlone() {
        for (String user : w.telemetry.cast().get(dev.dwarpal.sim.SimTelemetry.Activity.A8_BEACONING)) {
            RankedAlert signed = w.ranked(w.alertOf("beacon-from-document-process", user));
            assertEquals(Priority.P1, signed.priority(), user);
            assertTrue(signed.actionable(), user);
            RankedAlert fw = w.ranked(w.alertOf("beacon-regular-destination", "laptop-" + user));
            assertFalse(fw.actionable(), "firewall lines alone can be forged: " + user);
            assertEquals(Set.of("firewall"), datasetsOf(fw.alert()));
        }
    }

    @Test
    @Order(7)
    void cloudExfiltrationIsP2NotP1BecauseItRestsOnCollectedEvidenceOnly() {
        String user = w.telemetry.cast().get(dev.dwarpal.sim.SimTelemetry.Activity.A9_CLOUD_EXFIL).iterator().next();
        for (String rule : List.of("cloud-download-volume", "cloud-bulk-download-then-external-share")) {
            RankedAlert r = w.ranked(w.alertOf(rule, user));
            assertEquals(Set.of("cloud"), datasetsOf(r.alert()));
            assertFalse(r.actionable(), rule);
            assertTrue(r.priority().atLeast(Priority.P2) && r.priority() != Priority.P1,
                    rule + " must be urgent but capped below P1: " + r.priority());
        }
    }

    @Test
    @Order(8)
    void theLegitimateLookalikesDoNotBecomeP1() {
        String quarterEnd = w.telemetry.cast().get(dev.dwarpal.sim.SimTelemetry.Activity.L5_BIG_LEGIT_DOWNLOAD)
                .iterator().next();
        assertTrue(w.alertsOf("cloud-download-volume").stream().noneMatch(a -> a.entities().contains(Entity.subject(quarterEnd))),
                "the quarter-end download is not a cloud exfiltration alert");
        for (SocWorld.Raised r : w.raised) {
            if (r.engine().equals("E") && r.alert().entities().contains(Entity.subject(quarterEnd))
                    && datasetsOf(r.alert()).equals(Set.of("cloud"))) {
                assertNotEquals(Priority.P1, w.ranked(r.alert()).priority(), "L5 anomaly on collected evidence only");
            }
        }
        String admin = w.telemetry.admins().stream().filter(a -> w.telemetry.cast()
                .get(dev.dwarpal.sim.SimTelemetry.Activity.A9_CLOUD_EXFIL).stream().noneMatch(a::equals)).findFirst().orElseThrow();
        assertEquals(1, w.alertsOf("encoded-powershell").stream()
                .filter(a -> a.entities().contains(Entity.subject(admin))).count(),
                "the admin's own PowerShell adds nothing beyond the one stolen-laptop script: " + admin);
        for (SocWorld.Raised r : w.raised) {
            if (r.engine().equals("E") && r.alert().entities().contains(Entity.subject(admin))) {
                assertTrue(w.ranked(r.alert()).priority().ordinal() >= Priority.P3.ordinal(),
                        "a known admin is not P1 or P2 for ordinary admin work: " + admin);
            }
        }
    }

    @Test
    @Order(9)
    void whatCannotBeActedOnIsNeverRankedActionableAndTheCatalogueAgreesWithTheRanker() {
        var catalogue = dev.dwarpal.soar.RuleCatalogue.reference();
        for (SocWorld.Raised r : w.raised) {
            var rule = catalogue.rule(r.alert().rule()).orElseThrow(() -> new AssertionError("no catalogue entry: " + r.alert().rule()));
            RankedAlert ranked = w.ranked(r.alert());
            switch (rule.evidence()) {
                case COLLECTED_ONLY -> assertFalse(ranked.actionable(), r.alert().rule());
                case VERIFIED -> assertTrue(ranked.actionable(), r.alert().rule());
                default -> {
                    boolean collectedOnly = datasetsOf(r.alert()).stream().noneMatch(d -> d.equals("endpoint") || d.equals("dwarpal.audit"));
                    assertEquals(!collectedOnly, ranked.actionable(),
                            r.alert().id() + " is actionable exactly when some of its evidence is verified");
                }
            }
        }
    }

    @Test
    @Order(10)
    void riskIsOnePictureAndEveryPartOfItIsListed() {
        String exfil = w.telemetry.cast().get(dev.dwarpal.sim.SimTelemetry.Activity.A9_CLOUD_EXFIL).iterator().next();
        Instant now = w.org.clock.instant();
        var view = w.ueba.view(Entity.subject(exfil), now);
        assertTrue(view.score() > 50, "exfiltrator risk: " + view.score());
        assertFalse(w.ueba.contributions(Entity.subject(exfil), now).isEmpty());
        double quiet = w.ueba.view(Entity.subject("u1"), now).score();
        assertTrue(view.score() >= quiet, "the exfiltrator is not calmer than a quiet colleague");
        assertFalse(w.ueba.top(5, now).isEmpty());
    }

    @Test
    @Order(11)
    void theCaseManagerHoldsEveryAlertAndTheQueueIsSortedByUrgency() {
        int alerts = w.cases.all().stream().mapToInt(c -> c.alerts().size()).sum();
        assertEquals(w.raised.size(), alerts, "no alert was lost between detection, ranking and cases");
        var all = w.cases.all();
        assertFalse(all.isEmpty());
        assertTrue(all.size() >= w.org.users.size(), "at least one case per person with a stolen laptop");
        for (var c : all) {
            assertTrue(c.deadline().isAfter(c.openedAt()), "every case has an SLA deadline: " + c.key());
        }
    }

    // ---- B + F: response ---------------------------------------------------------------------------------------

    @Test
    @Order(20)
    void aSignedVerdictOnTheStolenLaptopIsolatesTheDeviceAndTheEngineThenDenies() {
        String victim = "u30";
        Alert alert = w.alertOf("stolen-laptop-access", victim);
        Instant now = w.org.clock.instant();
        assertFalse(w.org.signals.denied(SignalFeed.Kind.SUBJECT, victim, now));

        Soar.Result r = w.decide(alert.id(), Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(Playbooks.Status.APPLIED, r.status(), r.message());
        assertEquals(Optional.of(Soar.Mode.FULL), r.mode(), "the evidence is signed, so the full playbook runs");
        assertEquals(List.of("laptop-" + victim), r.isolated());
        assertTrue(w.revocations.stream().anyMatch(x -> x.kind().equals("subject") && x.id().equals(victim)),
                "sessions of the person are revoked");

        // the simulated sensor acknowledges with the device agent's signature over exactly the command it got
        assertEquals(DeviceIsolation.State.PENDING_ACK, w.isolation.of("laptop-" + victim).orElseThrow().state());
        List<SensorAck> acks = w.sensor.drain();
        assertEquals(1, acks.size());
        assertEquals(DeviceIsolation.AckResult.ACCEPTED, w.isolation.acknowledge(acks.getFirst()));
        assertEquals(DeviceIsolation.State.ISOLATED, w.isolation.of("laptop-" + victim).orElseThrow().state());
        assertTrue(w.sensor.isolated("laptop-" + victim));

        // and the decision engine now sees it
        assertTrue(w.org.signals.watchLogLr(SignalFeed.Kind.SUBJECT, victim, now) > 0, "the person is on the watch list");
        assertFalse(w.org.signals.denied(SignalFeed.Kind.SUBJECT, "u31", now), "a colleague is untouched");
        assertEquals(0, w.org.signals.watchLogLr(SignalFeed.Kind.SUBJECT, "u31", now), 1e-12);
        var watched = w.pdp.decide(w.requestOf(victim), w.org.signals.snapshot(now));
        var colleague = w.pdp.decide(w.requestOf("u31"), w.org.signals.snapshot(now));
        assertTrue(watched.risk().posteriorAttack() > colleague.risk().posteriorAttack()
                || watched.outcome() != Outcome.ALLOW, "the engine takes the watch into account");
    }

    @Test
    @Order(21)
    void aFalsePositiveFromAnalystsLiftsRiskInUebaAndTheSameVerdictCannotBeUsedTwice() {
        Alert noisy = w.raised.stream().filter(x -> x.engine().equals("E")).map(SocWorld.Raised::alert)
                .filter(a -> a.entities().stream().anyMatch(e -> e.kind() == Entity.Kind.SUBJECT && e.id().equals("u40")))
                .findFirst().orElseThrow();
        Instant now = w.org.clock.instant();
        double before = w.ueba.view(Entity.subject("u40"), now).score();
        Verdict fp = w.org.verdict("ana", noisy.id(), Verdict.Outcome.FALSE_POSITIVE, now);
        assertTrue(w.ueba.falsePositive(fp, w.uebaGate), "E's own gate admits the signed false positive");
        assertTrue(w.ueba.view(Entity.subject("u40"), now).score() < before, "the false positive lowered the risk");
        assertFalse(w.ueba.falsePositive(fp, w.uebaGate), "a verdict is single use: replay lowers nothing more");
        Soar.Result first = w.soar.handle(fp);
        assertNotEquals(Playbooks.Status.REFUSED, first.status(), "part F has its own gate and still counts it once");
        assertEquals(Playbooks.Status.REFUSED, w.soar.handle(fp).status(), "and only once");
    }

    // ---- F: the SOC API serves the analyst -------------------------------------------------------------------

    @Test
    @Order(30)
    void theSocApiServesTheWholePictureOverMutualTlsToExactlyTheAnalysts() throws Exception {
        SocApiClient.pki();
        LocalDate day = w.org.clock.instant().atZone(ZoneOffset.UTC).toLocalDate();
        SocApiServer server = SocApiServer.builder(w.org.audit, w.soar).tls(SocApiClient.ctx("soc-api"))
                .clock(w.org.clock)
                .callers(List.of(SocCaller.component("ana", SocWorld.ANA), SocCaller.component("ben", SocWorld.BEN),
                        SocCaller.component("cleo", SocWorld.CLEO)))
                .settings(SocApiSettings.defaults()).search(w.store).risk(w.ueba)
                .reports((name, now) -> name.equals("daily") ? Optional.of(report(day).text()) : Optional.empty())
                .build().start();
        try {
            java.net.URI base = java.net.URI.create("https://localhost:" + server.port());
            try (SocApiClient ana = new SocApiClient(base, "ana")) {
                assertEquals(200, ana.get("/v1/health").status());
                SocApiClient.Reply queue = ana.get("/v1/queue");
                assertEquals(200, queue.status());
                assertTrue(queue.body().contains("\"queue\""));
                assertTrue(queue.body().contains("u9"), "the exfiltrating user's case is in the queue");

                String caseId = w.cases.caseOfAlert(w.alertOf("beacon-from-document-process", "u5").id()).orElseThrow();
                SocApiClient.Reply timeline = ana.get("/v1/cases/" + caseId + "/timeline");
                assertEquals(200, timeline.status(), timeline.body());

                SocApiClient.Reply risk = ana.get("/v1/risk/subject/u9");
                assertEquals(200, risk.status(), risk.body());
                assertTrue(risk.body().contains("score"), risk.body());

                String q = "{\"v\":1,\"query\":\"dataset = cloud\",\"from\":\"" + SimOrganisation.DAY_ZERO
                        + "\",\"to\":\"" + SimOrganisation.DAY_ZERO.plus(Duration.ofDays(10)) + "\",\"limit\":5}";
                SocApiClient.Reply search = ana.post("/v1/search", q);
                assertEquals(200, search.status(), search.body());
                assertTrue(search.body().contains("cloud"));

                assertEquals(404, ana.get("/v1/reports/daily").status(), "reports are for leads, not for every analyst");

                // a verdict through the API, signed by the caller, counts exactly like one given directly
                Alert al = w.alertOf("stolen-laptop-access", "u31");
                Verdict mine = w.org.verdict("ana", al.id(), Verdict.Outcome.TRUE_POSITIVE, w.org.clock.instant());
                assertEquals(403, ana.post("/v1/verdicts", verdictJson(w.org.verdict("ben", al.id(),
                        Verdict.Outcome.TRUE_POSITIVE, w.org.clock.instant()))).status(), "ben's signature sent by ana");
                SocApiClient.Reply done = ana.post("/v1/verdicts", verdictJson(mine));
                assertEquals(200, done.status(), done.body());
                assertEquals(403, ana.post("/v1/verdicts", verdictJson(mine)).status(), "single use, even over the API");
            }
            try (SocApiClient cleo = new SocApiClient(base, "cleo")) {
                SocApiClient.Reply rep = cleo.get("/v1/reports/daily");
                assertEquals(200, rep.status(), rep.body());
                assertTrue(rep.body().toLowerCase().contains("simulated"), "the report says where its numbers come from");
                assertEquals(404, cleo.get("/v1/reports/nothing").status());
                assertTrue(cleo.get("/v1/queue").body().contains("u9"), "a lead sees the whole queue");
            }
            try (SocApiClient stranger = new SocApiClient(base, "stranger")) {
                assertEquals(403, stranger.get("/v1/queue").status(), "a valid certificate of an unknown subject");
            }
        } finally {
            server.close();
        }
        assertTrue(TlsContexts.component("ana").getName().contains("ana"));
    }

    private SocReport report(LocalDate day) {
        long requests = w.results.size();
        return SocReport.daily(DataSource.simulated(7, 60, 8, requests), day, w.rankedNow(), w.ueba, List.of(),
                w.ueba.techniques());
    }

    private static String verdictJson(Verdict v) {
        return "{\"v\":1,\"alertId\":\"" + v.alertId() + "\",\"analystId\":\"" + v.analystId() + "\",\"outcome\":\""
                + v.outcome() + "\",\"proof\":{\"keyId\":\"" + v.proof().keyId() + "\",\"signedAt\":\""
                + v.proof().signedAt() + "\",\"signature\":\"" + v.proof().signature() + "\"}}";
    }

    // ---- C: analytics still read the same trail ----------------------------------------------------------------

    @Test
    @Order(40)
    void analyticsReadDwarpalsDecisionsFromTheSameChainAndIgnoreTheCollectedEvents() {
        int max = w.org.sink.snapshot().size();
        AuditDecisions.Result r = AuditDecisions.read(AuditCursor.fromStart(w.org.sink, w.org.auditKey), max);
        assertTrue(r.problem().isEmpty(), r.problem().toString());
        assertEquals(w.records("ACCESS_DECISION").size(), r.entries().size(), "one entry per decision Dwarpal made");
        assertTrue(r.entries().size() >= w.results.size());
        assertTrue(r.otherEvents() > 2_000, "the collected events and the SOC's own records are skipped, not misread");
        assertEquals(0, r.malformed());
    }

    @Test
    @Order(41)
    void theDailyReportStatesItsDataAndCountsEveryPriority() {
        LocalDate day = w.org.clock.instant().atZone(ZoneOffset.UTC).toLocalDate();
        SocReport rep = report(day);
        String text = rep.text();
        assertTrue(text.toLowerCase().contains("simulated"), text);
        assertTrue(rep.json().contains("simulated") || rep.json().contains("SIMULATED"), "JSON carries the source too");
        assertTrue(rep.byPriority().values().stream().mapToLong(Long::longValue).sum() > 0);
        assertTrue(rep.coverage().covered() > 5, "MITRE coverage includes D's rules too");
    }
}

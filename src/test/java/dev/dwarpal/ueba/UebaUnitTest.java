package dev.dwarpal.ueba;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import dev.dwarpal.analytics.DataSource;
import dev.dwarpal.response.VerdictGate;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertRanker;
import dev.dwarpal.soc.Asset;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EntityRisk;
import dev.dwarpal.soc.InMemoryAssetCatalog;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.SecurityEvent.Provenance;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Technique;
import dev.dwarpal.soc.Techniques;
import dev.dwarpal.soc.Verdict;

/** The detectors, the risk arithmetic, ranking, the queue and the reports, each checked against a hand calculation. */
class UebaUnitTest {

    static final Entity U = Entity.subject("u1");

    static Alert alert(String id, String rule, Severity s, Instant at, Entity e, long seq) {
        return new Alert(id, rule, s, at, List.of(e), List.of(seq), 1, "test");
    }

    // ---- risk arithmetic ------------------------------------------------------------------------------------

    @Test
    void riskIsBayesWithABaseRateAndHalfLivesByHand() {
        UebaFixtures f = new UebaFixtures();
        f.index.put(1, Provenance.VERIFIED_AUDIT);
        Instant t = UebaFixtures.at(1, 9, 0);
        f.risk.raise(alert("al-1", "honeytoken-touched", Severity.CRITICAL, t, U, 1));
        // Sum ln 1000, prior 0.001: z = ln(0.001/0.999) + ln 1000 = ln(1000/999), p = 0.50025, score 49.975
        EntityRisk.RiskView v = f.risk.view(U, t);
        assertEquals(49.975, v.score(), 0.001);
        assertEquals(EntityRisk.Level.MEDIUM, v.level());
        // After one half-life (14 days for CRITICAL): weight ln 1000 / 2
        EntityRisk.RiskView later = f.risk.view(U, t.plus(Duration.ofDays(14)));
        assertEquals(Math.log(1000) / 2, later.contributions().get(0).weight(), 1e-6);
        // Before the alert it does not count yet (replays give the same answer).
        assertEquals(0, f.risk.view(U, t.minusSeconds(1)).score());
        assertEquals(EntityRisk.Level.NONE, f.risk.view(Entity.subject("nobody"), t).level());
        // Ten copies of one rule are one piece of evidence.
        for (int i = 2; i < 12; i++) {
            f.risk.raise(alert("al-" + i, "honeytoken-touched", Severity.CRITICAL, t, U, 1));
        }
        EntityRisk.RiskView same = f.risk.view(U, t);
        assertEquals(49.975, same.score(), 0.001);
        assertTrue(same.contributions().get(0).reason().endsWith("(x11)"));
    }

    @Test
    void collectedOnlyEvidenceIsScaledAndSaysSo() {
        UebaFixtures f = new UebaFixtures();
        Instant t = UebaFixtures.at(1, 9, 0);
        f.index.put(2, Provenance.COLLECTED);
        f.risk.raise(alert("al-a", "fw-a", Severity.CRITICAL, t, U, 2));
        f.risk.raise(alert("al-b", "fw-b", Severity.CRITICAL, t, U, 2));
        List<EntityRisk.Contribution> c = f.risk.contributions(U, t);
        assertEquals(Math.log(1000), c.stream().mapToDouble(EntityRisk.Contribution::weight).sum(), 1e-9);
        assertTrue(c.get(0).reason().contains("collected only, x0.50"));
        // Verified evidence adds on top.
        f.index.put(3, Provenance.VERIFIED_AUDIT);
        f.risk.raise(alert("al-c", "pam-refused", Severity.HIGH, t, U, 3));
        assertTrue(f.risk.view(U, t).score() > 90);
    }

    @Test
    void moreThanTwentyContributionsAreSummedIntoOneLineAndNoneIsLost() {
        UebaFixtures f = new UebaFixtures();
        Instant t = UebaFixtures.at(1, 9, 0);
        for (int i = 0; i < 30; i++) {
            f.risk.watch(U, "watch:w" + i, new UebaRisk.Weight(0.1 + i * 0.01, Duration.ofDays(1)), t, List.of(), "w" + i);
        }
        EntityRisk.RiskView v = f.risk.view(U, t);
        assertEquals(EntityRisk.RiskView.MAX_CONTRIBUTIONS, v.contributions().size());
        assertEquals("ueba:other", v.contributions().get(19).source());
        double all = f.risk.contributions(U, t).stream().mapToDouble(EntityRisk.Contribution::weight).sum();
        assertEquals(all, v.contributions().stream().mapToDouble(EntityRisk.Contribution::weight).sum(), 1e-9);
        assertThrows(IllegalArgumentException.class, () -> f.risk.top(0, t));
        assertEquals(1, f.risk.top(5, t).size());
    }

    @Test
    void riskSettingsAreValidated() {
        var ref = UebaRisk.Settings.reference();
        assertThrows(IllegalArgumentException.class, () -> new UebaRisk.Settings(0, 1, 1, Duration.ofDays(1),
                ref.severity(), 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new UebaRisk.Settings(0.1, -1, 1, Duration.ofDays(1),
                ref.severity(), 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new UebaRisk.Settings(0.1, 1, 1, Duration.ofDays(1),
                Map.of(), 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new UebaRisk.Settings(0.1, 1, 1, Duration.ofDays(1),
                ref.severity(), 0, 1));
        assertThrows(IllegalArgumentException.class, () -> new UebaRisk.Weight(0, Duration.ofDays(1)));
        assertThrows(IllegalArgumentException.class, () -> new UebaRisk.Weight(1, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new UebaRisk.Weight(1, Duration.ofDays(400)));
    }

    // ---- detectors -------------------------------------------------------------------------------------------

    @Test
    void volumeAndDataVolumeByHand() {
        UebaFixtures f = new UebaFixtures();
        f.ordinaryDays(U, 0, 3, 2);
        f.engine.flush();
        List<Anomaly> found = new ArrayList<>();
        for (int i = 0; i < 60; i++) {
            found.addAll(f.see(UebaFixtures.at(4, 10, i * 50), "file.download", Provenance.COLLECTED, U,
                    "bytes", "5000000"));
        }
        Anomaly vol = found.stream().filter(a -> a.detector() == Anomaly.Detector.VOLUME).findFirst().orElseThrow();
        // lambda = 2 per active hour; first k with k >= 10 and z = (k - 2) / sqrt 2 >= 4 is k = 10 (z = 5.66);
        // Poisson LR with f = 10: 10 ln 10 - 9 x 2 = 5.03, capped at ln 100 = 4.61.
        assertTrue(vol.reason().startsWith("10 x file.download"), vol.reason());
        assertEquals(Math.log(100), vol.weight(), 1e-9);
        Anomaly bytes = found.stream().filter(a -> a.detector() == Anomaly.Detector.DATA_VOLUME).findFirst().orElseThrow();
        assertEquals(vol.group(), bytes.group(), "count and bytes of one burst are one piece of evidence");
        assertEquals(Techniques.EXFIL_TO_CLOUD_STORAGE, bytes.technique());
        // In risk, only the stronger of the two counts.
        assertEquals(1, f.risk.contributions(U, UebaFixtures.at(4, 11, 0)).stream()
                .filter(c -> c.source().startsWith("ueba:volume") || c.source().startsWith("ueba:data_volume")).count());
    }

    @Test
    void firstSeenUsesTheRuleOfSuccession() {
        UebaFixtures f = new UebaFixtures();
        f.ordinaryDays(U, 0, 3, 1);
        f.engine.flush();
        List<Anomaly> found = f.see(UebaFixtures.at(4, 10, 0), "process.start", Provenance.SIGNED_SENSOR, U,
                "process", "mimikatz.exe");
        Anomaly a = found.stream().filter(x -> x.group().startsWith("new:process")).findFirst().orElseThrow();
        // 24 process observations of 4 values: k = 4, w = 24, P = 5 / 26, l = ln(0.5 / (5/26)) = 0.956
        assertEquals(Math.log(0.5 / (5.0 / 26.0)), a.weight(), 1e-9);
        assertTrue(a.actionable());
        assertTrue(a.reason().contains("(k+1)/(w+2)"));
        assertEquals(Techniques.OBFUSCATED_FILES, a.technique());
        assertTrue(f.see(UebaFixtures.at(4, 10, 1), "process.start", Provenance.SIGNED_SENSOR, U, "process", "code.exe")
                .isEmpty(), "known values are quiet");
    }

    @Test
    void peersStrengthenARareValue() {
        Map<String, String> g = Map.of("a", "hr", "b", "hr", "c", "hr", "d", "hr", "e", "hr");
        InMemoryAssetCatalog cat = new InMemoryAssetCatalog(List.of(new Asset(Entity.device("pc-a"), 2, "a", Set.of(),
                true)));
        PeerGroups peers = PeerGroups.of(g, cat);
        assertEquals("hr", peers.group(Entity.device("pc-a")).orElseThrow());
        assertTrue(peers.group(Entity.device("pc-x")).isEmpty());
        assertTrue(peers.group(Entity.ip("10.0.0.1")).isEmpty());
        assertTrue(PeerGroups.of(g).group(Entity.device("pc-a")).isEmpty());
        assertEquals(5, peers.size("hr"));
        UebaFixtures f = new UebaFixtures(UebaSettings.reference(), peers);
        Entity a = Entity.subject("a");
        f.ordinaryDays(a, 0, 3, 1);
        f.engine.flush();
        Anomaly x = f.see(UebaFixtures.at(4, 10, 0), "process.start", Provenance.SIGNED_SENSOR, a, "process", "nmap.exe")
                .stream().filter(y -> y.group().startsWith("new:process")).findFirst().orElseThrow();
        assertEquals(Math.log(0.5 / (5.0 / 26.0)) + Math.log(2), x.weight(), 1e-9);
        assertTrue(x.reason().contains("rare in hr (0 of 5)"));
        assertThrows(IllegalArgumentException.class, () -> PeerGroups.of(Map.of("bad id!", "x")));
    }

    @Test
    void timeOfDayBeaconAndDrift() {
        UebaFixtures f = new UebaFixtures();
        f.ordinaryDays(U, 0, 4, 1);
        f.engine.flush();
        List<Anomaly> night = f.see(UebaFixtures.at(5, 3, 0), "file.download", Provenance.COLLECTED, U, "bytes", "1");
        Anomaly t = night.stream().filter(a -> a.detector() == Anomaly.Detector.TIME_OF_DAY).findFirst().orElseThrow();
        assertTrue(t.reason().contains("03:00 UTC"), t.reason());
        assertTrue(t.weight() >= Math.log(10));

        List<Anomaly> beacon = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            beacon.addAll(f.see(UebaFixtures.at(5, 10, 60 * i), "network.flow", Provenance.COLLECTED, U,
                    "dst", "203.0.113.9"));
        }
        Anomaly b = beacon.stream().filter(a -> a.detector() == Anomaly.Detector.BEACON).findFirst().orElseThrow();
        assertTrue(b.reason().contains("every 60 s"), b.reason());
        assertEquals(Math.log(100), b.weight(), 1e-9);
        assertEquals(1, beacon.stream().filter(a -> a.detector() == Anomaly.Detector.BEACON).count(), "once per hour");
        // Irregular connections are not a beacon.
        List<Anomaly> human = new ArrayList<>();
        int[] gaps = {5, 300, 40, 900, 12, 600, 75, 30, 1200, 8, 400, 66};
        int s = 0;
        for (int g : gaps) {
            s += g;
            human.addAll(f.see(UebaFixtures.at(6, 10, s), "network.flow", Provenance.COLLECTED, U, "dst", "198.51.100.7"));
        }
        assertTrue(human.stream().noneMatch(a -> a.detector() == Anomaly.Detector.BEACON));
    }

    @Test
    void techniquesOfValuesAndActions() {
        assertEquals(Techniques.EXFIL_OVER_USB, UebaEngine.technique("usb.mount"));
        assertEquals(Techniques.EXFIL_TO_CLOUD_STORAGE, UebaEngine.technique("share.create"));
        assertEquals(Techniques.DATA_FROM_NETWORK_SHARE, UebaEngine.technique("file.read"));
        assertEquals(Techniques.APPLICATION_LAYER_PROTOCOL, UebaEngine.technique("network.connect"));
        assertEquals(Techniques.VALID_ACCOUNTS, UebaEngine.technique("access.decision"));
        assertEquals(Techniques.POWERSHELL, UebaEngine.techniqueOfValue("parent", "PowerShell.exe"));
        assertEquals(Techniques.ARCHIVE_COLLECTED_DATA, UebaEngine.techniqueOfValue("process", "7z.exe"));
        assertEquals(Techniques.APPLICATION_LAYER_PROTOCOL, UebaEngine.techniqueOfValue("dport", "4444"));
        assertEquals(Techniques.EXFIL_TO_CLOUD_STORAGE, UebaEngine.techniqueOfValue("share", "x.example"));
        assertEquals(Techniques.EXFIL_OVER_USB, UebaEngine.techniqueOfValue("vendor", "v"));
        assertEquals(Techniques.VALID_ACCOUNTS, UebaEngine.techniqueOfValue("country", "RU"));
        assertEquals(Techniques.OBFUSCATED_FILES, UebaEngine.techniqueOfValue("process", "x.exe"));
    }

    @Test
    void ueba_alertsEscalateAndASignedFalsePositiveTeachesTheBaseline() {
        SimOrganisation org = SimOrganisation.create(7, 6);
        List<Alert> raised = new ArrayList<>();
        Ueba ueba = Ueba.reference(PeerGroups.none(), new InMemoryAssetCatalog(List.of()), raised::add);
        UebaEngine e = ueba.engine();
        long[] seq = {0};
        java.util.function.BiFunction<Instant, String, List<Anomaly>> proc = (t, p) -> e.observe(
                new dev.dwarpal.soc.ChainedEvent(++seq[0], t, UebaFixtures.event("e" + seq[0], t, "process.start",
                        Provenance.SIGNED_SENSOR, List.of(U), "process", p, "parent", "explorer.exe")));
        for (int i = 0; i < 30; i++) {
            proc.apply(UebaFixtures.at(0, 9, i * 600), "app" + (i % 3) + ".exe");
        }
        e.flush();
        for (int i = 0; i < 6; i++) {
            proc.apply(UebaFixtures.at(2, 9, i * 60), "tool" + i + ".exe");
        }
        assertFalse(raised.isEmpty());
        assertTrue(raised.get(raised.size() - 1).severity().atLeast(raised.get(0).severity()));
        Alert last = raised.get(raised.size() - 1);
        assertEquals(UebaEngine.RULE, last.rule());
        assertFalse(e.techniques(last.id()).isEmpty());
        assertFalse(ueba.techniques().of(last).isEmpty());
        assertTrue(ueba.risk().view(U, last.raisedAt()).score() > 0);
        assertTrue(ueba.ranker().rank(last, last.raisedAt()).actionable());

        Instant now = last.raisedAt().plusSeconds(60);
        org.clock.set(now);
        assertTrue(ueba.falsePositive(org.verdict("ana", last.id(), Verdict.Outcome.FALSE_POSITIVE, now),
                new VerdictGate(org.keys, org.clock)));
        assertTrue(e.anomaliesOf(last.id()).isEmpty());
        assertTrue(proc.apply(UebaFixtures.at(2, 12, 0), "tool0.exe").stream()
                .noneMatch(a -> a.group().startsWith("new:process")), "the analyst taught the value");
        assertTrue(e.stats().alerts() >= 1);
    }

    // ---- ranking and queue -----------------------------------------------------------------------------------

    @Test
    void rankingPointsByHandAndUnknownAssets() {
        UebaFixtures f = new UebaFixtures();
        f.index.put(1, Provenance.VERIFIED_AUDIT);
        Instant t = UebaFixtures.at(1, 9, 0);
        Entity cfo = Entity.subject("cfo");
        InMemoryAssetCatalog cat = new InMemoryAssetCatalog(List.of(new Asset(cfo, 5, "cfo", Set.of("executive"), true)));
        RiskRanker r = new RiskRanker(f.risk, cat, f.index, TechniqueMap.standard().build());
        Alert a = alert("al-1", "mfa-fatigue", Severity.HIGH, t, cfo, 1);
        f.risk.raise(a);
        RankedAlert ra = r.rank(a, t);
        // 40 (HIGH) + 0.3 x risk(ln 100: 100 (p - 0.001)/0.999 with p = 0.0910) + 3.75 x 4
        double p = 1 / (1 + Math.exp(-(Math.log(0.001 / 0.999) + Math.log(100))));
        double score = 40 + 0.3 * 100 * (p - 0.001) / 0.999 + 15;
        assertEquals(score, ra.score(), 1e-6);
        assertEquals(Priority.P2, ra.priority());
        assertEquals(List.of(Techniques.MFA_REQUEST_GENERATION), ra.techniques());
        assertTrue(ra.actionable());

        Alert unknown = new Alert("al-2", "new-rule", Severity.CRITICAL, t, List.of(Entity.device("pc-new"), cfo),
                List.of(99L), 1, "x");
        RankedAlert ru = r.rank(unknown, t);
        assertFalse(ru.actionable(), "evidence the index never saw is not actionable");
        assertTrue(ru.reasons().stream().anyMatch(s -> s.contains("not verifiable")));
        assertTrue(ru.reasons().stream().anyMatch(s -> s.contains("not in the asset catalogue")));
        assertTrue(ru.techniques().isEmpty());
        RankedAlert lone = r.rank(new Alert("al-3", "x", Severity.LOW, t, List.of(Entity.device("pc-new")), List.of(1L),
                1, "x"), t);
        assertEquals(Priority.P4, lone.priority());
        assertTrue(lone.reasons().stream().anyMatch(s -> s.contains("unknown asset, catalogue default")));
    }

    @Test
    void theQueueFoldsCopiesAndOrdersByPriority() {
        AlertRanker byRule = (a, now) -> new RankedAlert(a, a.severity() == Severity.CRITICAL ? Priority.P1 : Priority.P3,
                a.severity() == Severity.CRITICAL ? 90 : 40, List.of(), a.rule().startsWith("ok"), List.of());
        TriageQueue q = new TriageQueue(byRule, 3);
        Instant t = UebaFixtures.at(1, 9, 0);
        assertTrue(q.raise(alert("al-1", "ok-a", Severity.LOW, t, U, 1)));
        assertTrue(q.raise(alert("al-2", "ok-a", Severity.LOW, t, U, 1)));
        assertEquals(1, q.size());
        assertEquals(2, q.head(1).get(0).alerts());
        q.raise(alert("al-3", "ok-b", Severity.CRITICAL, t, U, 1));
        q.raise(alert("al-4", "no-c", Severity.LOW, t, U, 1));
        assertEquals("al-3", q.head(3).get(0).ranked().alert().id());
        assertEquals("al-4", q.head(3).get(2).ranked().alert().id(), "not actionable after actionable");
        assertFalse(q.raise(alert("al-5", "no-d", Severity.LOW, t.plusSeconds(1), U, 1)), "full: nothing more urgent");
        assertEquals(1, q.refused());
        assertTrue(q.raise(alert("al-6", "ok-e", Severity.CRITICAL, t, U, 1)));
        assertEquals(1, q.evicted());
        assertThrows(IllegalArgumentException.class, () -> new TriageQueue(byRule, 0));
        assertThrows(IllegalArgumentException.class, () -> q.head(0));
    }

    // ---- techniques, coverage, report -----------------------------------------------------------------------

    @Test
    void techniqueMapAndCoverage() {
        TechniqueMap m = TechniqueMap.standard().rule("fw-beacon", Techniques.APPLICATION_LAYER_PROTOCOL).build();
        assertTrue(m.rules().containsKey("fw-beacon"));
        assertThrows(IllegalArgumentException.class, () -> TechniqueMap.builder().rule("x",
                new Technique("T9999", "Invented", "impact")));
        assertThrows(IllegalArgumentException.class, () -> TechniqueMap.builder().rule("bad id!", Techniques.POWERSHELL));
        MitreCoverage c = MitreCoverage.of(m, List.of());
        assertEquals(Techniques.all().size(), c.total());
        assertTrue(c.covered() >= 15, c.text());
        assertTrue(c.text().contains("NOT COVERED") || c.covered() == c.total());
        assertTrue(c.json().startsWith("{\"covered\":"));
        Alert many = new Alert("al-1", UebaEngine.RULE, Severity.LOW, UebaFixtures.T0, List.of(U), List.of(1L), 1, "x");
        assertEquals(RankedAlert.MAX_TECHNIQUES, m.of(many).size());
    }

    @Test
    void dailyReportStatesItsDataAndAddsUp() {
        UebaFixtures f = new UebaFixtures();
        f.index.put(1, Provenance.VERIFIED_AUDIT);
        f.index.put(2, Provenance.COLLECTED);
        LocalDate day = LocalDate.parse("2026-10-02");
        Instant t = UebaFixtures.at(1, 9, 0);
        RiskRanker r = new RiskRanker(f.risk, new InMemoryAssetCatalog(List.of()), f.index, TechniqueMap.standard().build());
        List<RankedAlert> ranked = new ArrayList<>();
        Alert a1 = alert("al-1", "mfa-fatigue", Severity.HIGH, t, U, 1);
        Alert a2 = alert("al-2", "deny-storm-ip", Severity.MEDIUM, t, Entity.ip("198.51.100.1"), 2);
        Alert other = alert("al-3", "mfa-fatigue", Severity.HIGH, t.plus(Duration.ofDays(3)), U, 1);
        for (Alert a : List.of(a1, a2, other)) {
            f.risk.raise(a);
            ranked.add(r.rank(a, a.raisedAt()));
        }
        List<SocReport.VerdictRecord> v = List.of(
                new SocReport.VerdictRecord("al-1", "mfa-fatigue", t, t.plus(Duration.ofMinutes(30)),
                        Verdict.Outcome.FALSE_POSITIVE),
                new SocReport.VerdictRecord("al-2", "deny-storm-ip", t, t.plus(Duration.ofMinutes(90)),
                        Verdict.Outcome.TRUE_POSITIVE),
                new SocReport.VerdictRecord("al-3", "mfa-fatigue", t, t.plus(Duration.ofDays(3)),
                        Verdict.Outcome.BENIGN));
        DataSource src = DataSource.simulated(7, 60, 8, 3);
        SocReport rep = SocReport.daily(src, day, ranked, f.risk, v, TechniqueMap.standard().build());
        assertEquals(2, rep.byPriority().values().stream().mapToLong(Long::longValue).sum());
        String text = rep.text();
        assertTrue(text.startsWith("Data: " + src.statement()), text);
        assertTrue(text.contains("mean time to verdict: 60 min"), text);
        assertTrue(text.contains("of which 1 backed only by collected evidence"), text);
        assertEquals(2, rep.rates().size());
        assertEquals((1 + 1.0) / (1 + 2.0), rep.rates().stream().filter(x -> x.rule().equals("mfa-fatigue"))
                .findFirst().orElseThrow().estimate(), 1e-9);
        assertFalse(rep.top().isEmpty());
        assertTrue(rep.coverage().lines().stream().anyMatch(l -> l.observed() > 0));
        String json = rep.json();
        assertTrue(json.startsWith("{\"dataSource\":{\"kind\":\"SIMULATED\""), json);
        assertTrue(json.contains("\"meanTimeToVerdictMinutes\":60"));
        assertTrue(json.contains("\"alertsByPriority\":{\"P1\":"));

        SocReport empty = SocReport.daily(src, day.plusDays(10), List.of(), f.risk, List.of(),
                TechniqueMap.standard().build());
        assertTrue(empty.text().contains("no verdicts"));
        assertTrue(empty.json().contains("\"meanTimeToVerdictMinutes\":\"none\""));
        assertThrows(IllegalArgumentException.class, () -> new SocReport.VerdictRecord("a", "r", t, t.minusSeconds(1),
                Verdict.Outcome.BENIGN));
    }

    @Test
    void jsonEscapesEverythingHostile() {
        JsonOut j = new JsonOut();
        j.open('[').value("q\"b\\n\nr\rt\t\u0001\u2028\u202E\u2066ok").value(Double.NaN).value(true).value(1.5).close(']');
        assertEquals("[\"q\\\"b\\\\n\\nr\\rt\\t\\u0001\\u2028\\u202e\\u2066ok\",null,true,1.5000]", j.toString());
    }

    // ---- small parts -----------------------------------------------------------------------------------------

    @Test
    void evidenceIndexIsARing() {
        EvidenceIndex i = new EvidenceIndex(4);
        i.put(1, Provenance.SIGNED_SENSOR);
        i.put(3, Provenance.COLLECTED);
        assertTrue(i.provenance(2).isEmpty());
        assertEquals(Provenance.SIGNED_SENSOR, i.provenance(1).orElseThrow());
        i.put(9, Provenance.COLLECTED);
        assertTrue(i.provenance(1).isEmpty(), "too old");
        assertTrue(i.provenance(10).isEmpty());
        assertTrue(i.provenance(0).isEmpty());
        i.put(2, Provenance.VERIFIED_AUDIT);
        assertTrue(i.provenance(2).isEmpty(), "older than the ring: ignored");
        i.put(8, Provenance.VERIFIED_AUDIT);
        assertTrue(i.anyActionable(List.of(9L, 8L)));
        assertFalse(i.anyActionable(List.of(9L, 7L)));
        assertEquals(1, i.unknown(List.of(9L, 7L)));
        assertThrows(IllegalArgumentException.class, () -> new EvidenceIndex(0));
    }

    @Test
    void settingsAndAnomaliesAreValidated() {
        UebaSettings r = UebaSettings.reference();
        assertEquals(200_000, r.maxProfiles());
        assertThrows(IllegalArgumentException.class, () -> r.withMaxProfiles(0));
        assertThrows(IllegalArgumentException.class, () -> new UebaSettings(Set.of(), 1, 1, 2, 1, 1, 1, 2, 1, 0,
                List.of(), 2, 1, 1, 0.5, 0, 1, 0, 1, 1, 2, 0.1, 0, Duration.ZERO, 1, 1, Duration.ofHours(1), 1, 2, 3,
                3, 0.1, 1, 2));
        assertThrows(IllegalArgumentException.class, () -> new UebaSettings(r.baselined(), 1, 1, 2, 1, 1, 1, 1, 1, 0,
                List.of(), 2, 1, 1, 0.5, 0, 1, 0, 1, 1, 2, 0.1, 0, Duration.ZERO, 1, 1, Duration.ofHours(1), 1, 2, 3,
                3, 0.1, 1, 2));
        assertThrows(IllegalArgumentException.class, () -> new UebaSettings(r.baselined(), 1, 1, 2, 1, 1, 1, 2, 1, 0,
                List.of(), 2, 1, 1, 0.5, 0, 1, 0, 1, 1, 2, 0.1, 0, Duration.ZERO, 1, 1, Duration.ofHours(1), 3, 2, 1,
                3, 0.1, 1, 2));
        assertThrows(IllegalArgumentException.class, () -> new UebaSettings(r.baselined(), 1, 1, 2, 1, 1, 1, 2, 1, 0,
                List.of("bad name!"), 2, 1, 1, 0.5, 0, 1, 0, 1, 1, 2, 0.1, 0, Duration.ZERO, 1, 1, Duration.ofHours(1), 1,
                2, 3, 3, 0.1, 1, 2));
        assertThrows(IllegalArgumentException.class, () -> new UebaSettings(r.baselined(), 1, 1, 2, 1, 1, 1, 2, 1, 0,
                List.of(), 2, 1, 1, 0.5, 0, 1, 0, 1, 1, 2, 0.1, 0, Duration.ofDays(8), 1, 1, Duration.ofHours(1), 1,
                2, 3, 3, 0.1, 1, 2));
        assertThrows(IllegalArgumentException.class, () -> new UebaSettings(r.baselined(), 1, 1, 2, 1, 1, 1, 2, 1, 0,
                List.of(), 2, 1, 1, 0.5, 0, 1, 0, 1, 1, 2, 0.1, 0, Duration.ZERO, 1, 1, Duration.ofHours(1), 1,
                2, 3, 3, 0.1, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new UebaSettings(r.baselined(), 1, 1, 2, -1, 1, 1, 2, 1, 0,
                List.of(), 2, 1, 1, 0.5, 0, 1, 0, 1, 1, 2, 0.1, 0, Duration.ZERO, 1, 1, Duration.ofHours(1), 1,
                2, 3, 3, 0.1, 1, 2));
        assertThrows(IllegalArgumentException.class, () -> new UebaSettings(r.baselined(), 1, 1, 2, 1, 1, 1, 2, 1, -1,
                List.of(), 2, 1, 1, 0.5, 0, 1, 0, 1, 1, 2, 0.1, 0, Duration.ZERO, 1, 1, Duration.ofHours(1), 1,
                2, 3, 3, 0.1, 1, 2));
        assertThrows(IllegalArgumentException.class, () -> new UebaSettings(r.baselined(), 1, 1, 2, 1, 1, 1, 2, 1, 0,
                List.of(), 2, 1, 1, 0.5, 0, 1, 0, 1, 1, 2, 0.1, -1, Duration.ZERO, 1, 1, Duration.ofHours(1), 1,
                2, 3, 3, 0.1, 1, 2));
        Instant t = UebaFixtures.T0;
        assertThrows(IllegalArgumentException.class, () -> new Anomaly(U, Anomaly.Detector.VOLUME, "g", 0, t,
                List.of(1L), true, null, "x"));
        assertThrows(IllegalArgumentException.class, () -> new Anomaly(U, Anomaly.Detector.VOLUME, "g", 1, t,
                List.of(), true, null, "x"));
        assertEquals("ueba:first_seen", new Anomaly(U, Anomaly.Detector.FIRST_SEEN, "g", 1, t, List.of(1L), true, null,
                "x".repeat(500)).source());
    }

    @Test
    void lateAndSkewedEventsAreCountedNotGuessed() {
        UebaFixtures f = new UebaFixtures();
        Instant t = UebaFixtures.at(3, 10, 0);
        f.see(t, "file.download", Provenance.COLLECTED, U, "bytes", "1");
        f.see(t.minus(Duration.ofHours(1)), t, "file.download", Provenance.COLLECTED, U, "bytes", "1");
        f.see(t.minus(Duration.ofDays(3)), t, "file.download", Provenance.COLLECTED, U, "bytes", "1");
        var s = f.engine.stats();
        assertEquals(1, s.lateEvents());
        assertEquals(1, s.skewedEvents());
        assertEquals(UebaSettings.reference(), f.engine.settings());
        assertThrows(NullPointerException.class, () -> f.engine.observe(null));
    }
}

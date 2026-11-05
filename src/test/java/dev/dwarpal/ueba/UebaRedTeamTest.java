package dev.dwarpal.ueba;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Asset;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EntityRisk;
import dev.dwarpal.soc.InMemoryAssetCatalog;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.SecurityEvent.Provenance;
import dev.dwarpal.soc.Severity;

/**
 * Red-team probes against the SOC itself. Each one was first written against the code as it stood and failed
 * (the breach reproduced), then the code was fixed; the probes stay as regression tests. Findings E-R1 to E-R6 in
 * docs/layer-5-2/part-e.md.
 */
class UebaRedTeamTest {

    static final Entity VICTIM = Entity.subject("victim");

    /** E-R1: slow baseline poisoning. Raise the hourly volume just under the z threshold for weeks, then exfiltrate. */
    @Test
    void slowPoisoningCannotTeachTheBaselineAnExfiltrationRate() {
        UebaFixtures f = new UebaFixtures();
        f.ordinaryDays(VICTIM, 0, 7, 2);
        // The attacker knows the algorithm and tracks the mean of what they sent (the last 168 active hours).
        ArrayDeque<Integer> model = new ArrayDeque<>();
        for (int i = 0; i < 56; i++) {
            model.add(2);
        }
        int firedDuringRamp = 0;
        for (int d = 7; d < 47; d++) {
            for (int h = 9; h < 17; h++) {
                double lambda = Math.max(model.stream().mapToInt(Integer::intValue).average().orElse(0), 0.5);
                int k = Math.max(9, (int) Math.floor(lambda + 3.9 * Math.sqrt(lambda)));
                for (int i = 0; i < k; i++) {
                    firedDuringRamp += f.see(UebaFixtures.at(d, h, i * (3600 / k)), "file.download", Provenance.COLLECTED,
                            VICTIM, "bytes", "1000000").size();
                }
                model.addLast(k);
                if (model.size() > 168) {
                    model.removeFirst();
                }
            }
        }
        List<Anomaly> burst = new ArrayList<>();
        for (int i = 0; i < 60; i++) {
            burst.addAll(f.see(UebaFixtures.at(48, 10, i * 50), "file.download", Provenance.COLLECTED, VICTIM,
                    "bytes", "1000000"));
        }
        assertTrue(f.anomalies.stream().anyMatch(a -> a.detector() == Anomaly.Detector.DRIFT),
                "the drift of the baseline itself is reported; anomalies during the ramp: " + firedDuringRamp);
        assertTrue(burst.stream().anyMatch(a -> a.detector() == Anomaly.Detector.VOLUME),
                "60 downloads in an hour are still unusual after weeks of slow poisoning");
    }

    /** E-R2: raising an innocent person's risk with forged collected events (syslog anyone can send). */
    @Test
    void forgedCollectedEventsCannotMakeAnInnocentPersonHighRisk() {
        UebaFixtures f = new UebaFixtures();
        Entity ceo = Entity.subject("ceo");
        f.ordinaryDays(ceo, 0, 5, 2);
        for (int i = 0; i < 40; i++) {
            f.see(UebaFixtures.at(6, 10, i * 30), "process.start", Provenance.COLLECTED, ceo, "process", "evil-" + i + ".exe",
                    "parent", "evil-parent-" + i + ".exe", "dst", "203.0.113." + i);
        }
        for (int i = 0; i < 80; i++) {
            f.see(UebaFixtures.at(6, 11, i * 40), "file.download", Provenance.COLLECTED, ceo, "bytes", "900000000");
        }
        Instant now = UebaFixtures.at(6, 12, 0);
        EntityRisk.RiskView v = f.risk.view(ceo, now);
        assertTrue(v.score() <= 50, "collected evidence alone stays at most medium, was " + v.score() + " " + v.level());
        RiskRanker ranker = new RiskRanker(f.risk, new InMemoryAssetCatalog(List.of(new Asset(ceo, 5, "ceo",
                Set.of("executive"), true))), f.index, TechniqueMap.standard().build());
        assertFalse(f.alerts.isEmpty());
        for (Alert a : f.alerts) {
            RankedAlert r = ranker.rank(a, now);
            assertFalse(r.actionable(), "forged collected events never allow a destructive action");
            assertFalse(r.priority() == Priority.P1, r.reasons().toString());
        }
    }

    /** E-R3: hiding in a noisy peer group: do something first-time that many peers already do. */
    @Test
    void aNoisyPeerGroupDoesNotHideAFirstTimeValue() {
        Map<String, String> groups = new HashMap<>();
        for (int i = 0; i < 10; i++) {
            groups.put("m" + i, "it");
        }
        groups.put("insider", "it");
        UebaFixtures f = new UebaFixtures(UebaSettings.reference(), PeerGroups.of(groups));
        String[] apps = {"code.exe", "chrome.exe", "teams.exe", "outlook.exe"};
        for (int i = 0; i < 10; i++) {
            for (int k = 0; k < 25; k++) {
                f.see(UebaFixtures.at(0, 9, i * 100 + k), "process.start", Provenance.SIGNED_SENSOR,
                        Entity.subject("m" + i), "process", i < 6 && k == 24 ? "psexec.exe" : apps[k % 4]);
            }
        }
        Entity insider = Entity.subject("insider");
        for (int k = 0; k < 30; k++) {
            f.see(UebaFixtures.at(0, 10, k), "process.start", Provenance.SIGNED_SENSOR, insider, "process", apps[k % 4]);
        }
        f.engine.flush();
        List<Anomaly> found = f.see(UebaFixtures.at(1, 10, 0), "process.start", Provenance.SIGNED_SENSOR, insider,
                "process", "psexec.exe");
        double individual = Math.log(0.5 / (5.0 / 32.0));
        assertTrue(found.stream().anyMatch(a -> a.detector() == Anomaly.Detector.FIRST_SEEN
                        && a.weight() >= individual - 1e-9),
                "peers may strengthen a finding, never weaken it: " + found);
    }

    /** E-R4: flooding the queue so the real alert falls out or sinks. */
    @Test
    void aFloodOfAlertsCannotPushARealAlertOutOfTheQueue() {
        UebaFixtures f = new UebaFixtures();
        f.index.put(1, Provenance.SIGNED_SENSOR);
        f.index.put(2, Provenance.COLLECTED);
        RiskRanker ranker = new RiskRanker(f.risk, new InMemoryAssetCatalog(List.of(), 3), f.index,
                TechniqueMap.standard().build());
        TriageQueue q = new TriageQueue(ranker, 100);
        Instant t = UebaFixtures.at(1, 9, 0);
        Alert real = new Alert("al-real", "honeytoken-touched", Severity.CRITICAL, t, List.of(Entity.subject("cfo")),
                List.of(1L), 1, "honeytoken read");
        for (int i = 0; i < 200; i++) {
            f.risk.raise(new Alert("al-boost-" + i, "dlp-block-spike", Severity.CRITICAL, t,
                    List.of(Entity.subject("cfo")), List.of(1L), 1, "boost"));
        }
        q.offer(real, t);
        for (int i = 0; i < 5_000; i++) {
            q.offer(new Alert("al-flood-" + i, "deny-storm-ip", Severity.HIGH, t.plusSeconds(i),
                    List.of(Entity.ip("198.51.100." + (i % 250) + "-" + i)), List.of(2L), 1, "flood"), t.plusSeconds(i));
        }
        assertEquals("al-real", q.head(1).get(0).ranked().alert().id(), "the real alert stays first");
        assertEquals(100, q.size());
    }

    /** E-R5: flooding new entities to evict a victim's baseline, so the victim looks new and unjudged. */
    @Test
    void aFloodOfNewEntitiesCannotEvictAnEstablishedBaseline() {
        UebaFixtures f = new UebaFixtures(UebaSettings.reference().withMaxProfiles(50), PeerGroups.none());
        f.ordinaryDays(VICTIM, 0, 4, 2);
        f.engine.flush();
        for (int i = 0; i < 200; i++) {
            f.see(UebaFixtures.at(5, 9, i), "network.flow", Provenance.COLLECTED, Entity.device("fake-" + i), "dst", "x");
        }
        List<Anomaly> found = f.see(UebaFixtures.at(5, 10, 0), "process.start", Provenance.SIGNED_SENSOR, VICTIM,
                "process", "mimikatz.exe");
        assertTrue(found.stream().anyMatch(a -> a.detector() == Anomaly.Detector.FIRST_SEEN), "victim still judged");
        assertTrue(f.engine.stats().refusedProfiles() > 0, "the flood is counted");
    }

    /** E-R6: one forged event dated a month ahead switches volume detection off for that action. */
    @Test
    void aFarFutureEventDoesNotSwitchOffVolumeDetection() {
        UebaFixtures f = new UebaFixtures();
        f.ordinaryDays(VICTIM, 0, 5, 2);
        Instant now = UebaFixtures.at(6, 9, 0);
        f.see(now.plus(Duration.ofDays(30)), now, "file.download", Provenance.COLLECTED, VICTIM, "bytes", "1");
        List<Anomaly> burst = new ArrayList<>();
        for (int i = 0; i < 60; i++) {
            burst.addAll(f.see(UebaFixtures.at(6, 10, i * 50), "file.download", Provenance.COLLECTED, VICTIM,
                    "bytes", "1000000"));
        }
        assertTrue(burst.stream().anyMatch(a -> a.detector() == Anomaly.Detector.VOLUME), "burst still seen");
        assertTrue(f.engine.stats().skewedEvents() > 0, "the far-future event is counted");
    }
}

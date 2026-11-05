package dev.dwarpal.siem;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.AuditSink;
import dev.dwarpal.audit.AuditSource;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 5 part A: detection rules, deduplication, throttling, and the trail itself. Abuse cases first. */
class DetectionEngineTest {

    private static final Instant T0 = Trails.T0;
    private static final String TOR = "185.220.101.4";

    private static Trails.Collected run(Trails t) {
        Trails.Collected out = new Trails.Collected();
        t.engine(out).poll();
        return out;
    }

    // ---- the trail itself --------------------------------------------------------------------------------

    @Test
    void aChainBreakRaisesOneCriticalAlertAndStopsForGood() {
        Trails t = new Trails();
        for (int i = 0; i < 6; i++) {
            t.event(T0.plusSeconds(i), "BREAK_GLASS_USED", "bg", "grantId", "g" + i, "subjectId", "bg");
        }
        List<AuditRecord> records = new ArrayList<>(t.sink.snapshot());
        AuditRecord r = records.get(3);
        records.set(3, new AuditRecord(r.sequence(), r.at(), r.type(), r.actor(), "{\"subjectId\":\"other\"}",
                r.previousMac(), r.mac()));
        Trails.Collected out = new Trails.Collected();
        DetectionEngine d = new DetectionEngine(over(records), t.key, out, Optional::empty,
                DetectionEngine.Settings.defaults());
        DetectionEngine.Report rep = d.poll();
        assertEquals(3, rep.events());
        assertTrue(rep.stopped().orElseThrow().contains("MAC mismatch"));
        assertEquals(3, out.of(Rules.BREAK_GLASS).size());
        List<Alert> breaks = out.of(DetectionEngine.CHAIN_BREAK);
        assertEquals(1, breaks.size());
        assertEquals(Severity.CRITICAL, breaks.getFirst().severity());
        assertEquals(List.of(4L), breaks.getFirst().evidence());
        assertEquals(T0.plusSeconds(2), breaks.getFirst().raisedAt(), "audit time of the last good event");
        assertEquals(0, d.poll().events());
        assertEquals(1, out.of(DetectionEngine.CHAIN_BREAK).size(), "only once");
        assertTrue(d.stopped().isPresent());
    }

    @Test
    void aSourceThatThrowsIsABreakNotAnEnd() {
        Trails t = new Trails();
        t.event(T0, "X", "pdp");
        AuditSource failing = new AuditSource() {
            @Override
            public List<AuditRecord> after(long sequence, int max) {
                if (sequence > 0) {
                    throw new IllegalStateException("audit store damaged: record 2: torn frame");
                }
                return t.sink.after(sequence, max);
            }

            @Override
            public long lastSequence() {
                return 1;
            }
        };
        Trails.Collected out = new Trails.Collected();
        DetectionEngine d = new DetectionEngine(failing, t.key, out, Optional::empty, DetectionEngine.Settings.defaults());
        assertTrue(d.poll().stopped().orElseThrow().contains("torn frame"));
        assertEquals(1, out.of(DetectionEngine.CHAIN_BREAK).size());
    }

    @Test
    void aRecordForgedWithAnotherKeyIsNeverDetectedOn() {
        Trails real = new Trails();
        Trails forged = new Trails();
        forged.event(T0, "BREAK_GLASS_USED", "ceo", "grantId", "g", "subjectId", "ceo");
        Trails.Collected out = new Trails.Collected();
        new DetectionEngine(forged.sink, real.key, out, Optional::empty, DetectionEngine.Settings.defaults()).poll();
        assertTrue(out.of(Rules.BREAK_GLASS).isEmpty());
        assertEquals(1, out.of(DetectionEngine.CHAIN_BREAK).size());
    }

    @Test
    void aTruncatedTrailDisagreesWithItsAnchor() {
        Trails t = new Trails();
        for (int i = 0; i < 10; i++) {
            t.event(T0.plusSeconds(i), "X", "pdp");
        }
        AuditLog.Head head = t.log.head();
        List<AuditRecord> cut = t.sink.snapshot().subList(0, 7);
        Trails.Collected out = new Trails.Collected();
        DetectionEngine d = new DetectionEngine(over(cut), t.key, out, () -> Optional.of(head),
                DetectionEngine.Settings.defaults());
        assertTrue(d.poll().stopped().orElseThrow().contains("truncated"));
        assertEquals(1, out.of(DetectionEngine.ANCHOR_MISMATCH).size());
    }

    @Test
    void aTrailRewrittenAtTheAnchorIsCaughtEvenIfItGoesOnBeyondIt() {
        Trails t = new Trails();
        for (int i = 0; i < 10; i++) {
            t.event(T0.plusSeconds(i), "X", "pdp");
        }
        AuditLog.Head atFive = new AuditLog.Head(5, "ab".repeat(32));
        Trails.Collected out = new Trails.Collected();
        DetectionEngine d = new DetectionEngine(t.sink, t.key, out, () -> Optional.of(atFive),
                DetectionEngine.Settings.defaults());
        DetectionEngine.Report r = d.poll();
        assertEquals(5, r.events(), "reading stops at the anchor to compare");
        assertTrue(r.stopped().orElseThrow().contains("rewritten"));
    }

    @Test
    void aMatchingAnchorLetsDetectionGoOnAndAFailingAnchorStopsIt() {
        Trails t = new Trails();
        for (int i = 0; i < 10; i++) {
            t.event(T0.plusSeconds(i), "X", "pdp");
        }
        AuditLog.Head atFive = new AuditLog.Head(5, t.sink.snapshot().get(4).mac());
        Trails.Collected out = new Trails.Collected();
        DetectionEngine d = new DetectionEngine(t.sink, t.key, out, () -> Optional.of(atFive),
                DetectionEngine.Settings.defaults());
        DetectionEngine.Report r = d.poll();
        assertEquals(10, r.events());
        assertTrue(r.stopped().isEmpty());
        assertTrue(out.alerts.isEmpty());

        Trails.Collected out2 = new Trails.Collected();
        DetectionEngine d2 = new DetectionEngine(t.sink, t.key, out2, () -> {
            throw new IllegalStateException("audit anchor forged or altered");
        }, DetectionEngine.Settings.defaults());
        assertTrue(d2.poll().stopped().orElseThrow().contains("forged"));
        assertEquals(1, out2.of(DetectionEngine.ANCHOR_MISMATCH).size());
    }

    // ---- output ------------------------------------------------------------------------------------------

    @Test
    void alertsTheSinkRefusesAreKeptAndNothingMoreIsReadUntilItAccepts() {
        Trails t = new Trails();
        t.event(T0, "BREAK_GLASS_USED", "bg", "grantId", "g1", "subjectId", "bg");
        t.event(T0.plusSeconds(1), "BREAK_GLASS_USED", "bg", "grantId", "g2", "subjectId", "bg");
        Trails.Collected out = new Trails.Collected();
        out.refusing = true;
        DetectionEngine d = new DetectionEngine(t.sink, t.key, out, Optional::empty,
                new DetectionEngine.Settings(Duration.ofHours(1), 50, 200, 100, 100, 1, 100));
        DetectionEngine.Report r = d.poll();
        assertEquals(1, r.events(), "back-pressure: stopped after the first refused alert");
        assertEquals(1, r.waiting());
        assertEquals(0, d.poll().events());
        out.refusing = false;
        d.poll();
        assertEquals(List.of("al-break-glass-used-1", "al-break-glass-used-2"),
                out.alerts.stream().map(Alert::id).toList());
        assertTrue(d.stats().refusedBySink() >= 2);
        assertEquals(0, d.stats().lost());
    }

    @Test
    void aSinkThatThrowsIsTreatedAsRefusing() {
        Trails t = new Trails();
        t.event(T0, "BREAK_GLASS_USED", "bg", "grantId", "g1", "subjectId", "bg");
        int[] calls = {0};
        DetectionEngine d = new DetectionEngine(t.sink, t.key, a -> {
            if (calls[0]++ == 0) {
                throw new IllegalStateException("down");
            }
            return true;
        }, Optional::empty, DetectionEngine.Settings.defaults());
        assertEquals(1, d.poll().waiting());
        assertEquals(1, d.poll().alerts());
    }

    @Test
    void settingsAreBounded() {
        assertThrows(IllegalArgumentException.class,
                () -> new DetectionEngine.Settings(Duration.ofSeconds(1), 50, 200, 10, 10, 10, 10));
        assertThrows(IllegalArgumentException.class,
                () -> new DetectionEngine.Settings(Duration.ofDays(2), 50, 200, 10, 10, 10, 10));
        assertThrows(IllegalArgumentException.class,
                () -> new DetectionEngine.Settings(Duration.ofHours(1), 0, 200, 10, 10, 10, 10));
        assertThrows(IllegalArgumentException.class,
                () -> new DetectionEngine.Settings(Duration.ofHours(1), 50, 20_000, 10, 10, 10, 10));
        assertThrows(IllegalArgumentException.class,
                () -> new DetectionEngine.Settings(Duration.ofHours(1), 50, 200, 0, 10, 10, 10));
        assertThrows(IllegalArgumentException.class,
                () -> new DetectionEngine.Settings(Duration.ofHours(1), 50, 200, 10, 2_000_000, 10, 10));
        assertThrows(IllegalArgumentException.class,
                () -> new DetectionEngine.Settings(Duration.ofHours(1), 50, 200, 10, 10, 20_000, 10));
        assertThrows(IllegalArgumentException.class,
                () -> new DetectionEngine.Settings(Duration.ofHours(1), 50, 200, 10, 10, 10, 0));
        assertThrows(NullPointerException.class, () -> new DetectionEngine(new Trails().sink, null, a -> true,
                Optional::empty, DetectionEngine.Settings.defaults()));
    }

    // ---- deduplication and throttling --------------------------------------------------------------------

    @Test
    void repeatsFoldIntoOneAlertAndARollUpWithTheirCount() {
        Trails t = new Trails();
        for (int i = 0; i < 25; i++) {
            t.decision(T0.plusSeconds(i * 60L), "u" + (i % 5 == 0 ? 0 : i), "DENY", TOR);
        }
        t.event(T0.plusSeconds(2 * 3600), "X", "pdp");
        Trails.Collected out = run(t);
        List<Alert> storms = out.of(Rules.DENY_STORM_IP);
        assertEquals(2, storms.size(), storms.toString());
        Alert first = storms.getFirst();
        Alert roll = storms.get(1);
        assertEquals(1, first.count());
        assertTrue(roll.id().startsWith(first.id() + "-x"));
        assertTrue(roll.count() >= 2);
        assertTrue(roll.summary().contains("more within the window"));
        assertEquals(first.entities(), roll.entities());
    }

    @Test
    void flushClosesOpenWindows() {
        Trails t = new Trails();
        for (int i = 0; i < 12; i++) {
            t.decision(T0.plusSeconds(i), "u" + i, "DENY", TOR);
        }
        Trails.Collected out = new Trails.Collected();
        DetectionEngine d = t.engine(out);
        d.poll();
        assertEquals(1, out.of(Rules.DENY_STORM_IP).size());
        d.flush();
        assertEquals(2, out.of(Rules.DENY_STORM_IP).size());
        assertEquals(0, d.stats().openWindows());
    }

    @Test
    void theSameTrailGivesTheSameAlertsWhateverTheBatchSize() {
        SimOrganisation org = SimOrganisation.create(7, 60);
        org.run(org.pipeline(org.engine()), org.traffic());
        List<String> one = alertsOf(org, 500);
        List<String> other = alertsOf(org, 7);
        assertEquals(one, other);
        assertFalse(one.isEmpty());
    }

    private static List<String> alertsOf(SimOrganisation org, int chunk) {
        Trails.Collected out = new Trails.Collected();
        DetectionEngine d = new DetectionEngine(org.sink, org.auditKey, out, Optional::empty,
                new DetectionEngine.Settings(Duration.ofHours(1), 50, 200, 50_000, 20_000, chunk, 1_000_000));
        while (d.poll().events() > 0) {
            // read in small polls too
        }
        d.flush();
        return out.alerts.stream().map(a -> a.id() + " " + a.count() + " " + a.entities() + " " + a.evidence())
                .toList();
    }

    @Test
    void resumingFromACheckpointReadsOnlyWhatIsNew() {
        Trails t = new Trails();
        for (int i = 0; i < 4; i++) {
            t.event(T0.plusSeconds(i), "BREAK_GLASS_USED", "bg", "grantId", "g" + i, "subjectId", "bg");
        }
        Trails.Collected out = new Trails.Collected();
        DetectionEngine d = t.engine(out);
        d.poll();
        AuditLog.Head cp = d.checkpoint();
        t.event(T0.plusSeconds(9), "BREAK_GLASS_USED", "bg", "grantId", "g9", "subjectId", "bg");
        Trails.Collected later = new Trails.Collected();
        DetectionEngine r = DetectionEngine.resume(t.sink, t.key, cp, later, Optional::empty,
                DetectionEngine.Settings.defaults());
        assertEquals(1, r.poll().events());
        assertEquals(List.of("al-break-glass-used-5"), later.alerts.stream().map(Alert::id).toList());
    }

    // ---- rules -------------------------------------------------------------------------------------------

    @Test
    void breakGlassUseIsCriticalEveryTime() {
        Trails t = new Trails();
        t.event(T0, "BREAK_GLASS_USED", "bg-admin", "grantId", "bg-1", "subjectId", "bg-admin", "severity", "CRITICAL");
        t.event(T0.plusSeconds(60), "BREAK_GLASS_USED", "bg-admin", "grantId", "bg-2", "subjectId", "bg-admin");
        List<Alert> a = run(t).of(Rules.BREAK_GLASS);
        assertEquals(2, a.size());
        assertEquals(Severity.CRITICAL, a.getFirst().severity());
        assertEquals(List.of(Entity.subject("bg-admin")), a.getFirst().entities());
        assertEquals(T0, a.getFirst().raisedAt());
    }

    @Test
    void aHoneytokenHitIsCriticalAndNamesSubjectDeviceAndAddress() {
        Trails t = new Trails();
        t.decision(T0, "svc-decoy", "DENY", "203.0.113.7", "policy", Rules.HONEYTOKEN_POLICY);
        t.decision(T0.plusSeconds(5), "svc-decoy", "DENY", "203.0.113.7", "policy", Rules.HONEYTOKEN_POLICY);
        t.decision(T0.plusSeconds(6), "svc-decoy", "DENY", "203.0.113.7", "policy", "hard-gate:deny-list");
        t.event(T0.plusSeconds(7200), "X", "pdp");
        List<Alert> a = run(t).of(Rules.HONEYTOKEN);
        assertEquals(2, a.size(), "one, then its roll-up");
        assertEquals(Severity.CRITICAL, a.getFirst().severity());
        assertEquals(Set.of(Entity.Kind.SUBJECT, Entity.Kind.DEVICE, Entity.Kind.IP),
                a.getFirst().entities().stream().map(Entity::kind).collect(Collectors.toSet()));
        assertEquals(1, a.get(1).count());
    }

    @Test
    void aTokenPresentedForAnotherDeviceIsATheftAlertButAnOrdinaryRevocationIsNot() {
        Trails t = new Trails();
        t.event(T0, "SESSION_REVOKED", "pa", "sessionId", "s-1", "subjectId", "u1", "deviceId", "laptop-u1",
                "resourceId", "wiki", "reason", "token presented for another subject or device: possible token theft");
        t.event(T0, "SESSION_REVOKED", "admin", "sessionId", "s-2", "subjectId", "u2", "deviceId", "laptop-u2",
                "resourceId", "wiki", "reason", "per-subject session limit: oldest session closed");
        List<Alert> a = run(t).of(Rules.STOLEN_TOKEN);
        assertEquals(1, a.size());
        assertEquals(Severity.HIGH, a.getFirst().severity());
        assertTrue(a.getFirst().entities().contains(new Entity(Entity.Kind.SESSION, "s-1")));
    }

    @Test
    void denyStormsPerPersonAndPerAddress() {
        Trails t = new Trails();
        for (int i = 0; i < 4; i++) {
            t.decision(T0.plusSeconds(i * 60L), "u1", "DENY", "198.51.100." + i);
        }
        t.decision(T0.plusSeconds(20 * 60L), "u1", "DENY", "198.51.100.9");
        Trails.Collected out = run(t);
        assertTrue(out.of(Rules.DENY_STORM_SUBJECT).isEmpty(), "5 denies, but not within 15 min");
        assertTrue(out.of(Rules.DENY_STORM_IP).isEmpty());

        Trails u = new Trails();
        for (int i = 0; i < 5; i++) {
            u.decision(T0.plusSeconds(i * 60L), "u" + i, "DENY", TOR);
        }
        for (int i = 0; i < 9; i++) {
            u.decision(T0.plusSeconds(i), "u1", "DENY", "203.0.113.1");
        }
        Trails.Collected out2 = run(u);
        List<Alert> ip = out2.of(Rules.DENY_STORM_IP);
        assertEquals(1, ip.size(), "five people from one address (the 9 from one person stay below 10)");
        assertEquals(new Entity(Entity.Kind.IP, TOR), ip.getFirst().entities().getFirst());
        assertTrue(ip.getFirst().summary().contains("5 different people"));
        assertEquals(1, out2.of(Rules.DENY_STORM_SUBJECT).size());

        Trails w = new Trails();
        for (int i = 0; i < 10; i++) {
            w.decision(T0.plusSeconds(i), "u1", "DENY", "203.0.113.1");
        }
        assertEquals(1, run(w).of(Rules.DENY_STORM_IP).size(), "ten denies from one address");
    }

    @Test
    void mfaFatigueNeedsFivePushesWithoutAnAllow() {
        Trails t = new Trails();
        for (int i = 0; i < 4; i++) {
            t.decision(T0.plusSeconds(i * 60L), "u1", "STEP_UP", "203.0.113.2");
        }
        t.decision(T0.plusSeconds(300), "u1", "ALLOW", "203.0.113.2");
        t.decision(T0.plusSeconds(360), "u1", "STEP_UP", "203.0.113.2");
        assertTrue(run(t).of(Rules.MFA_FATIGUE).isEmpty());

        Trails u = new Trails();
        for (int i = 0; i < 5; i++) {
            u.decision(T0.plusSeconds(i * 60L), "u1", "STEP_UP", "203.0.113.2");
        }
        List<Alert> a = run(u).of(Rules.MFA_FATIGUE);
        assertEquals(1, a.size());
        assertEquals(5, a.getFirst().evidence().size());
        assertEquals(Severity.HIGH, a.getFirst().severity());
    }

    private static final String TRAVEL = "[RiskFactor[name=network-novelty, logLikelihoodRatio=6.9, evidence=new IP],"
            + " RiskFactor[name=impossible-travel, logLikelihoodRatio=3.40, evidence=6662 km in 0.3 h]]";

    @Test
    void impossibleTravelThenAnAllowWithinTwoHours() {
        Trails t = new Trails();
        t.decision(T0, "u1", "DENY", "81.2.69.160", "factors", TRAVEL);
        t.decision(T0.plusSeconds(1800), "u1", "ALLOW", "100.64.1.10");
        t.decision(T0, "u2", "DENY", "81.2.69.160", "factors", TRAVEL);
        t.decision(T0.plusSeconds(3 * 3600), "u2", "ALLOW", "100.64.2.10");
        t.decision(T0.plusSeconds(3 * 3600), "u3", "ALLOW", "81.2.69.160", "factors", TRAVEL);
        List<Alert> a = run(t).of(Rules.TRAVEL_THEN_ALLOW);
        assertEquals(2, a.size(), a.toString());
        assertEquals(List.of(1L, 2L), a.getFirst().evidence());
        assertEquals(Entity.subject("u1"), a.getFirst().entities().getFirst());
        assertEquals(List.of(5L), a.get(1).evidence(), "flagged and allowed in one decision");
    }

    @Test
    void onlyARealPositiveTravelFactorCounts() {
        assertFalse(Rules.impossibleTravel(event(Map.of("factors",
                "[RiskFactor[name=impossible-travel, logLikelihoodRatio=-0.4, evidence=none]]"))));
        assertFalse(Rules.impossibleTravel(event(Map.of("factors",
                "[RiskFactor[name=device-novelty, logLikelihoodRatio=1, evidence=xRiskFactor[name=impossible-travel,"
                        + " logLikelihoodRatio=5, evidence=forged]]"))));
        assertFalse(Rules.impossibleTravel(event(Map.of("factors",
                "[RiskFactor[name=impossible-travel, logLikelihoodRatio=NaN, evidence=x]]"))));
        assertFalse(Rules.impossibleTravel(event(Map.of("factors",
                "[RiskFactor[name=impossible-travel, logLikelihoodRatio=" + "9".repeat(40) + ", evidence=x]]"))));
        assertFalse(Rules.impossibleTravel(event(Map.of("factors",
                "[RiskFactor[name=impossible-travel, logLikelihoodRatio=abc, x]]"))));
        assertFalse(Rules.impossibleTravel(event(Map.of("factors",
                "[RiskFactor[name=impossible-travel, logLikelihoodRatio=1"))));
        assertFalse(Rules.impossibleTravel(event(Map.of())));
        assertTrue(Rules.impossibleTravel(event(Map.of("factors",
                "[RiskFactor[name=impossible-travel, logLikelihoodRatio=2.5E-1, evidence=x]]"))));
    }

    private static dev.dwarpal.audit.AuditEvent event(Map<String, String> f) {
        return new dev.dwarpal.audit.AuditEvent(1, T0, "ACCESS_DECISION", "pdp", f);
    }

    @Test
    void dlpBlockSpikePerPerson() {
        Trails t = new Trails();
        for (int i = 0; i < 5; i++) {
            t.event(T0.plusSeconds(i * 60L), "casb.dlp", "u7", "action", i == 2 ? "REDACT" : "BLOCK",
                    "resource", "drive");
        }
        assertTrue(run(t).of(Rules.DLP_SPIKE).isEmpty(), "only four blocks");
        t.event(T0.plusSeconds(600), "casb.dlp", "u7", "action", "BLOCK", "resource", "mail");
        List<Alert> a = run(t).of(Rules.DLP_SPIKE);
        assertEquals(1, a.size());
        assertEquals(Severity.MEDIUM, a.getFirst().severity());
        assertTrue(a.getFirst().entities().contains(new Entity(Entity.Kind.RESOURCE, "mail")));
    }

    @Test
    void refusedPrivilegedAccess() {
        Trails t = new Trails();
        t.event(T0, "ELEVATION_REFUSED", "pam", "who", "u3", "role", "admin", "reason", "x");
        t.event(T0.plusSeconds(60), "ELEVATION_APPROVAL_REFUSED", "pam", "who", "u3", "role", "admin", "reason", "x");
        t.event(T0.plusSeconds(90), "ELEVATION_REFUSED", "pam", "who", "u4", "role", "admin", "reason", "x");
        t.event(T0.plusSeconds(120), "ELEVATION_REFUSED", "pam", "who", "u3", "role", "admin", "reason", "x");
        t.event(T0.plusSeconds(130), "BREAK_GLASS_REFUSED", "pam", "who", "bg-admin", "role", "admin", "reason", "x");
        Trails.Collected out = run(t);
        assertEquals(1, out.of(Rules.PAM_REFUSED).size());
        assertEquals(List.of(Entity.subject("u3")), out.of(Rules.PAM_REFUSED).getFirst().entities());
        assertEquals(1, out.of(Rules.BREAK_GLASS_REFUSED).size());
        assertEquals(Severity.HIGH, out.of(Rules.BREAK_GLASS_REFUSED).getFirst().severity());
    }

    @Test
    void oddIdsInARecordStillCountAndNeverReachAnAlertRaw() {
        Trails t = new Trails();
        for (int i = 0; i < 5; i++) {
            t.decision(T0.plusSeconds(i), "evil name" + (char) 10 + "x", "DENY", "203.0.113.5");
        }
        Alert a = run(t).of(Rules.DENY_STORM_SUBJECT).getFirst();
        assertTrue(a.entities().getFirst().id().matches("invalid-[0-9a-f]{16}"));
        assertFalse(a.summary().contains("evil"));
        assertTrue(Rules.entity(Entity.Kind.IP, Optional.of("")).isEmpty());
    }

    @Test
    void windowCounterIsBounded() {
        WindowCounter c = new WindowCounter(Duration.ofMinutes(1), 3, 2, false);
        assertTrue(c.add("a", T0, 1, "x").isEmpty());
        assertTrue(c.add("b", T0, 2, "x").isEmpty());
        assertTrue(c.add("c", T0, 3, "x").isEmpty(), "full: refused");
        assertEquals(1, c.overflow());
        assertTrue(c.add("c", T0.plusSeconds(120), 4, "x").isEmpty(), "idle keys make room");
        assertEquals(1, c.size());
        assertThrows(IllegalArgumentException.class, () -> new WindowCounter(Duration.ZERO, 3, 2, false));
        assertThrows(IllegalArgumentException.class, () -> new WindowCounter(Duration.ofMinutes(1), 101, 2, false));
        WindowCounter d = new WindowCounter(Duration.ofMinutes(1), 2, 5, true);
        assertTrue(d.add("ip", T0, 1, "u1").isEmpty());
        assertTrue(d.add("ip", T0, 2, "u1").isEmpty(), "same tag again");
        assertEquals(2, d.add("ip", T0, 3, "u2").size());
    }

    // ---- the simulated organisation -----------------------------------------------------------------------

    /**
     * The simulated organisation (seed 7, 60 users, 720 decisions): attacks from shared addresses (Tor exit,
     * the impossible-travel address, the spray address) raise address alerts; nothing names a person whose
     * only traffic was legitimate. Consistency with the threat model, not real-world accuracy.
     */
    @Test
    void theSimulatedOrganisationsTrail() {
        SimOrganisation org = SimOrganisation.create(7, 60);
        List<SimOrganisation.Result> results = org.run(org.pipeline(org.engine()), org.traffic());
        Trails.Collected out = new Trails.Collected();
        DetectionEngine d = new DetectionEngine(org.sink, org.auditKey, out, Optional::empty,
                DetectionEngine.Settings.defaults());
        DetectionEngine.Report r = d.poll();
        d.flush();
        assertEquals(results.size(), r.events());
        assertTrue(r.stopped().isEmpty());

        Set<String> stormIps = out.of(Rules.DENY_STORM_IP).stream()
                .map(a -> a.entities().getFirst().id()).collect(Collectors.toSet());
        assertTrue(stormIps.contains(SimOrganisation.TOR_EXIT), stormIps.toString());
        assertTrue(stormIps.contains("81.2.69.160"), stormIps.toString());
        assertTrue(stormIps.contains(SimOrganisation.SPRAY_IP), stormIps.toString());

        Set<String> legitimateIps = results.stream().filter(x -> !x.labelled().scenario().attack())
                .map(x -> x.labelled().request().network().ip()).collect(Collectors.toSet());
        for (Alert a : out.alerts) {
            for (Entity e : a.entities()) {
                if (e.kind() == Entity.Kind.IP) {
                    assertFalse(legitimateIps.contains(e.id()), "alert on a legitimate address: " + a);
                }
            }
            assertTrue(a.severity().atLeast(Severity.MEDIUM));
        }
        assertTrue(out.of(Rules.MFA_FATIGUE).isEmpty());
        assertTrue(out.of(Rules.TRAVEL_THEN_ALLOW).isEmpty(), "no ALLOW follows a flagged login in this traffic");
        assertTrue(out.of(DetectionEngine.ALERT_FLOOD).isEmpty());
    }

    // ---- bounded memory -------------------------------------------------------------------------------------

    /**
     * 1,000,000 verified events, every one a DENY from a new address for a new person: rule state, open
     * windows and waiting alerts stay within their limits. The source generates the chain on the fly, so
     * the test itself holds only one batch.
     */
    @Test
    void boundedUnderAMillionEvents() {
        GeneratedTrail trail = new GeneratedTrail(1_000_000);
        long[] alerts = {0};
        DetectionEngine.Settings s = new DetectionEngine.Settings(Duration.ofHours(1), 50, 200, 5_000, 5_000,
                AuditSource.MAX_BATCH, 1_000_000);
        DetectionEngine d = new DetectionEngine(trail, trail.key, a -> ++alerts[0] > 0, Optional::empty, s);
        long total = 0;
        int maxState = 0;
        int maxOpen = 0;
        DetectionEngine.Report r;
        do {
            r = d.poll();
            total += r.events();
            maxState = Math.max(maxState, d.stats().ruleState());
            maxOpen = Math.max(maxOpen, d.stats().openWindows());
        } while (r.events() > 0);
        assertEquals(1_000_000, total);
        assertTrue(r.stopped().isEmpty());
        assertTrue(maxState <= 9 * 5_000, "rule state " + maxState);
        assertTrue(maxOpen <= 5_000, "open windows " + maxOpen);
        assertTrue(d.stats().throttled() > 0);
        assertEquals(0, d.stats().lost());
        assertTrue(alerts[0] > 0 && alerts[0] < 2_000, "alerts " + alerts[0]);
    }

    /**
     * A valid HMAC chain made on demand, one DENY per 2 ms: each address is denied for five different people
     * in a row (a spray from 200,000 addresses), every seventh request comes from one Tor exit.
     */
    private static final class GeneratedTrail implements AuditSource {
        final javax.crypto.SecretKey key = Trails.hmacKey();
        private final int size;
        private final List<AuditRecord> batch = new ArrayList<>();
        private final AuditLog log = new AuditLog(key, (AuditSink) batch::add);

        GeneratedTrail(int size) {
            this.size = size;
        }

        @Override
        public List<AuditRecord> after(long sequence, int max) {
            if (sequence != log.head().sequence()) {
                throw new IllegalStateException("generated trail is read in order only");
            }
            batch.clear();
            int n = (int) Math.min(Math.min(max, MAX_BATCH), size - sequence);
            for (int i = 0; i < n; i++) {
                long n5 = sequence + i;
                long k = n5 / 5;
                String ip = (10 + k / 16_777_216 % 200) + "." + (k / 65_536 % 256) + "." + (k / 256 % 256) + "." + (k % 256);
                log.append("ACCESS_DECISION", "pdp", T0.plusMillis(n5 * 2), Map.of("outcome", "DENY",
                        "subject", "p" + (n5 % 300_000), "sourceIp", n5 % 7 == 0 ? TOR : ip, "policy", "P-90"));
            }
            return List.copyOf(batch);
        }

        @Override
        public long lastSequence() {
            return size;
        }
    }

    /** A source over a fixed list of records, which an attacker may have edited. */
    private static AuditSource over(List<AuditRecord> records) {
        return new AuditSource() {
            @Override
            public List<AuditRecord> after(long sequence, int max) {
                List<AuditRecord> out = new ArrayList<>();
                for (AuditRecord r : records) {
                    if (r.sequence() > sequence && out.size() < max) {
                        out.add(r);
                    }
                }
                return out;
            }

            @Override
            public long lastSequence() {
                return records.isEmpty() ? 0 : records.getLast().sequence();
            }
        };
    }
}

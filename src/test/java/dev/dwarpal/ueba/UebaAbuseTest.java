package dev.dwarpal.ueba;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.response.VerdictGate;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EntityRisk;
import dev.dwarpal.soc.SecurityEvent.Provenance;
import dev.dwarpal.soc.SecurityEvents;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Verdict;

/** Abuse cases first: what an attacker or a broken input does to part E, and that it fails closed. */
class UebaAbuseTest {

    static final Entity U = Entity.subject("u1");

    static Alert alert(String id, String rule, Severity s, Instant at, Entity e, long seq) {
        return new Alert(id, rule, s, at, List.of(e), List.of(seq), 1, "test");
    }

    @Test
    void anEntitysOwnGoodBehaviourNeverLowersItsRisk() {
        UebaFixtures f = new UebaFixtures();
        f.index.put(1, Provenance.VERIFIED_AUDIT);
        Instant t = UebaFixtures.at(1, 9, 0);
        f.risk.raise(alert("al-1", "honeytoken-touched", Severity.HIGH, t, U, 1));
        double before = f.risk.view(U, t).score();
        for (int i = 0; i < 500; i++) {
            f.see(t.plusSeconds(i), "access.decision", Provenance.VERIFIED_AUDIT, U, "outcome", "ALLOW");
        }
        assertEquals(before, f.risk.view(U, t).score(), 1e-9, "only time or a signed false positive lowers risk");
        assertTrue(f.risk.view(U, t.plus(Duration.ofDays(7))).score() < before, "time does");
    }

    @Test
    void forgedReplayedOrWrongVerdictsDoNotLowerRisk() {
        SimOrganisation org = SimOrganisation.create(7, 6);
        Instant t = UebaFixtures.at(1, 9, 0);
        org.clock.set(t);
        VerdictGate gate = new VerdictGate(org.keys, org.clock);
        Ueba ueba = Ueba.reference(PeerGroups.none(), new dev.dwarpal.soc.InMemoryAssetCatalog(List.of()), a -> true);
        ueba.evidence().put(1, Provenance.VERIFIED_AUDIT);
        assertTrue(ueba.raise(alert("al-1", "mfa-fatigue", Severity.HIGH, t, U, 1)));
        double before = ueba.risk().view(U, t).score();
        assertTrue(before > 0);

        Verdict tp = org.verdict("ana", "al-1", Verdict.Outcome.TRUE_POSITIVE, t);
        assertFalse(ueba.falsePositive(tp, gate), "a true positive is not a false positive");
        Verdict other = org.verdict("ana", "al-2", Verdict.Outcome.FALSE_POSITIVE, t);
        Verdict forged = new Verdict("al-1", "ana", Verdict.Outcome.FALSE_POSITIVE, other.proof());
        assertFalse(ueba.falsePositive(forged, gate), "a signature over another alert does not count");
        Verdict old = org.verdict("ana", "al-1", Verdict.Outcome.FALSE_POSITIVE, t.minus(Duration.ofHours(2)));
        assertFalse(ueba.falsePositive(old, gate), "too old");
        assertFalse(ueba.risk().falsePositive(forged, gate));
        assertEquals(before, ueba.risk().view(U, t).score(), 1e-9);

        Verdict fp = org.verdict("ana", "al-1", Verdict.Outcome.FALSE_POSITIVE, t);
        assertTrue(ueba.falsePositive(fp, gate));
        assertEquals(0, ueba.risk().view(U, t).score(), 1e-9, "a signed false positive removes what the alert added");
        assertFalse(ueba.falsePositive(fp, gate), "and works once");
    }

    @Test
    void aSignedFalsePositiveOnARealRiskOnlyTakesAwayThatAlert() {
        SimOrganisation org = SimOrganisation.create(7, 6);
        Instant t = UebaFixtures.at(1, 9, 0);
        org.clock.set(t);
        UebaFixtures f = new UebaFixtures();
        f.index.put(1, Provenance.VERIFIED_AUDIT);
        f.risk.raise(alert("al-a", "mfa-fatigue", Severity.HIGH, t, U, 1));
        f.risk.raise(alert("al-b", "honeytoken-touched", Severity.CRITICAL, t, U, 1));
        assertTrue(f.risk.falsePositive(org.verdict("ben", "al-a", Verdict.Outcome.FALSE_POSITIVE, t),
                new VerdictGate(org.keys, org.clock)));
        EntityRisk.RiskView v = f.risk.view(U, t);
        assertEquals(1, v.contributions().size());
        assertEquals("alert:honeytoken-touched", v.contributions().get(0).source());
    }

    @Test
    void eventsUnderAnAlertAreNotLearnedEvenIfTheAlertComesLater() {
        UebaFixtures f = new UebaFixtures();
        f.ordinaryDays(U, 0, 3, 1);
        f.engine.flush();
        Instant t = UebaFixtures.at(4, 10, 0);
        f.see(t, "process.start", Provenance.SIGNED_SENSOR, U, "process", "tool.exe");
        long seq = f.lastSequence();
        // Another rule (part D) raises an alert on that event 10 minutes later, still inside the quarantine.
        f.engine.alerted(alert("al-d", "sequence-rule", Severity.HIGH, t.plusSeconds(600), U, seq));
        f.see(t.plus(Duration.ofHours(3)), "process.start", Provenance.SIGNED_SENSOR, U, "process", "code.exe");
        List<Anomaly> again = f.see(t.plus(Duration.ofHours(4)), "process.start", Provenance.SIGNED_SENSOR, U,
                "process", "tool.exe");
        assertTrue(again.stream().anyMatch(a -> a.detector() == Anomaly.Detector.FIRST_SEEN),
                "the alerted value was kept out of the baseline");
    }

    @Test
    void aBrokenChainStopsReadingForGoodAndMalformedRecordsAreCounted() throws Exception {
        javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("HmacSHA256").generateKey();
        InMemoryAuditSink sink = new InMemoryAuditSink();
        AuditLog log = new AuditLog(key, sink);
        Instant t = UebaFixtures.at(1, 9, 0);
        log.append(SecurityEvents.RECORD_TYPE, "collector:firewall", t, Map.of("dataset", "firewall"));
        log.append(SecurityEvents.RECORD_TYPE, "collector:test", t, SecurityEvents.toAuditFields(
                UebaFixtures.event("x1", t, "file.download", Provenance.COLLECTED, List.of(U), "bytes", "1")));
        log.append("ACCESS_DECISION", "pdp", t, Map.of("subject", "u1", "outcome", "ALLOW"));
        UebaFixtures f = new UebaFixtures();
        assertEquals(3, f.engine.poll(AuditCursor.fromStart(sink, key), 10));
        assertEquals(1, f.engine.stats().malformed(), "missing fields: counted, not guessed");
        assertEquals(3, f.engine.stats().events() + f.engine.stats().malformed());
        assertEquals(Provenance.VERIFIED_AUDIT, f.index.provenance(3).orElseThrow());

        // A record signed with another key: the cursor breaks and the engine stops for good.
        javax.crypto.SecretKey other = javax.crypto.KeyGenerator.getInstance("HmacSHA256").generateKey();
        InMemoryAuditSink forged = new InMemoryAuditSink();
        AuditLog wrong = new AuditLog(other, forged);
        AuditRecord r = wrong.append("ACCESS_DECISION", "pdp", t, Map.of("subject", "u1"));
        assertEquals(1, r.sequence());
        UebaFixtures g = new UebaFixtures();
        AuditCursor c = AuditCursor.fromStart(forged, key);
        g.engine.poll(c, 10);
        assertTrue(g.engine.stats().chainProblem().isPresent());
        assertEquals(0, g.engine.poll(c, 10));
        assertThrows(IllegalArgumentException.class, () -> g.engine.poll(c, 0));
    }

    @Test
    void floodsAreBounded() {
        UebaSettings s = UebaSettings.reference().withMaxProfiles(5);
        UebaFixtures f = new UebaFixtures(s, PeerGroups.none());
        for (int i = 0; i < 20; i++) {
            f.see(UebaFixtures.at(1, 9, i), "x.y", Provenance.COLLECTED, Entity.subject("s" + i));
        }
        assertEquals(5, f.engine.stats().profiles());
        assertEquals(15, f.engine.stats().refusedProfiles());

        // Contributions per entity are bounded; a flood of weak ones never pushes out a strong one.
        UebaRisk risk = new UebaRisk(new UebaRisk.Settings(0.001, Math.log(1000), Math.log(1000), Duration.ofDays(1),
                UebaRisk.Settings.reference().severity(), 3, 4), new EvidenceIndex(10));
        Instant t = UebaFixtures.at(1, 9, 0);
        risk.raise(alert("al-strong", "honeytoken-touched", Severity.CRITICAL, t, U, 1));
        for (int i = 0; i < 50; i++) {
            risk.watch(U, "watch:w" + i, new UebaRisk.Weight(0.01, Duration.ofHours(1)), t, List.of(), "weak");
        }
        assertTrue(risk.contributions(U, t).stream().anyMatch(c -> c.source().equals("alert:honeytoken-touched")));
        assertTrue(risk.contributions(U, t).size() <= 4);
        // Entities are bounded; the least risky makes room.
        for (int i = 0; i < 10; i++) {
            risk.watch(Entity.device("d" + i), "watch:x", new UebaRisk.Weight(0.1 + i, Duration.ofDays(1)), t, List.of(),
                    "w");
        }
        assertEquals(3, risk.size());
        assertTrue(risk.dropped() > 0);
        assertEquals(0, risk.view(U, t).score(), 1e-9, "the three riskiest stay; u1 (ln 1000) was below d7 to d9");
        assertTrue(Set.of(Entity.device("d7"), Entity.device("d8"), Entity.device("d9"))
                .contains(risk.top(1, t).get(0).entity()), "each group is capped at ln 1000, so d7 to d9 tie");
    }

    @Test
    void hostileValuesAreHandledAsData() {
        UebaFixtures f = new UebaFixtures();
        f.ordinaryDays(U, 0, 3, 1);
        f.engine.flush();
        String nasty = "a\u202Eb\nc\"d<script>" + "x".repeat(900);
        List<Anomaly> found = f.see(UebaFixtures.at(4, 10, 0), "process.start", Provenance.SIGNED_SENSOR, U,
                "process", nasty, "bytes", "-5", "dst", "");
        assertFalse(found.isEmpty());
        for (Anomaly a : found) {
            assertFalse(a.reason().contains("\n") || a.reason().contains("\u202E"));
            assertTrue(a.reason().length() <= Anomaly.MAX_REASON + 20);
        }
        f.see(UebaFixtures.at(4, 10, 1), "file.download", Provenance.COLLECTED, U, "bytes", "99999999999999999999");
        assertTrue(Set.of(0L).contains(f.engine.stats().malformed()));
    }
}

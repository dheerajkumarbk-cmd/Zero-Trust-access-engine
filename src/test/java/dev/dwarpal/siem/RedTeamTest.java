package dev.dwarpal.siem;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Red-team pass on part A. Each test was first a working probe of the breach (see docs/layer-5/part-a.md,
 * findings R-A1 to R-A3); it now proves the fix. The rest attack the SOC itself.
 */
class RedTeamTest {

    @TempDir
    Path dir;

    /** R-A1: cutting the store back and putting an old anchor file in place hid the truncation after a restart. */
    @Test
    void rA1_aRestoredOldAnchorIsStaleAndStopsDetection() throws Exception {
        Path store = dir.resolve("audit.dwas");
        Path anchorFile = dir.resolve("anchor");
        var aes = Trails.aesKey();
        var hmac = Trails.hmacKey();
        var anchorKey = Trails.hmacKey();
        HeadAnchor anchor = new HeadAnchor(anchorFile, anchorKey, Clock.fixed(Trails.T0, ZoneOffset.UTC));
        long cut;
        try (EncryptedAuditStore s = EncryptedAuditStore.open(store, aes, EncryptedAuditStore.Durability.OS_BUFFERED)) {
            AuditLog log = new AuditLog(hmac, s);
            for (int i = 0; i < 5; i++) {
                log.append("ACCESS_DECISION", "pdp", Trails.T0.plusSeconds(i), Map.of("outcome", "ALLOW"));
            }
            anchor.anchor(s.head());
            cut = Files.size(store);
            Files.copy(anchorFile, dir.resolve("old-anchor"));
            for (int i = 5; i < 10; i++) {
                log.append("BREAK_GLASS_USED", "pdp", Trails.T0.plusSeconds(i), Map.of("subjectId", "mallory"));
            }
            anchor.anchor(s.head());
        }
        try (FileChannel ch = FileChannel.open(store, StandardOpenOption.WRITE)) {
            ch.truncate(cut);
        }
        Files.copy(dir.resolve("old-anchor"), anchorFile, StandardCopyOption.REPLACE_EXISTING);

        HeadAnchor restarted = new HeadAnchor(anchorFile, anchorKey,
                Clock.fixed(Trails.T0.plus(Duration.ofDays(1)), ZoneOffset.UTC));
        IllegalStateException stale = assertThrows(IllegalStateException.class,
                () -> restarted.readFresh(Duration.ofMinutes(5)));
        assertTrue(stale.getMessage().contains("stale"));
        try (EncryptedAuditStore s = EncryptedAuditStore.open(store, aes, EncryptedAuditStore.Durability.OS_BUFFERED)) {
            Trails.Collected out = new Trails.Collected();
            DetectionEngine d = new DetectionEngine(s, hmac, out,
                    () -> Optional.of(restarted.readFresh(Duration.ofMinutes(5))), DetectionEngine.Settings.defaults());
            assertTrue(d.poll().stopped().isPresent());
            assertEquals(1, out.of(DetectionEngine.ANCHOR_MISMATCH).size());
            assertEquals(Severity.CRITICAL, out.alerts.getFirst().severity());
        }
    }

    /** The heartbeat: re-anchoring an unchanged head renews its time, so a quiet trail is not "stale". */
    @Test
    void rA1_aLiveAnchorStaysFreshOnAQuietTrail() {
        Instant[] now = {Trails.T0};
        Clock clock = new Clock() {
            @Override
            public java.time.ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(java.time.ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return now[0];
            }
        };
        HeadAnchor a = new HeadAnchor(dir.resolve("anchor"), Trails.hmacKey(), clock);
        AuditLog.Head h = new AuditLog.Head(3, "ab".repeat(32));
        a.anchor(h);
        now[0] = now[0].plus(Duration.ofMinutes(4));
        a.anchor(h);
        now[0] = now[0].plus(Duration.ofMinutes(4));
        assertEquals(h, a.readFresh(Duration.ofMinutes(5)));
    }

    /** R-A2: one DENY between pushes reset the MFA-fatigue count; 40 pushes in 15 minutes raised nothing. */
    @Test
    void rA2_aDenyBetweenPushesDoesNotResetMfaFatigue() {
        Trails t = new Trails();
        Instant at = Trails.T0;
        for (int round = 0; round < 10; round++) {
            for (int i = 0; i < 4; i++) {
                t.decision(at = at.plusSeconds(20), "ceo", "STEP_UP", "203.0.113.9");
            }
            t.decision(at = at.plusSeconds(5), "ceo", "DENY", "185.220.101.4");
        }
        Trails.Collected out = new Trails.Collected();
        t.engine(out).poll();
        assertFalse(out.of(Rules.MFA_FATIGUE).isEmpty());
    }

    /** R-A3: CRITICAL alerts were never throttled; honeytoken hits with invented devices raised 2,000 of them. */
    @Test
    void rA3_honeytokenFloodsAreCappedWithOneCriticalFloodAlert() {
        Trails t = new Trails();
        for (int i = 0; i < 2_000; i++) {
            t.decision(Trails.T0.plusSeconds(i), "svc-backup-old", "DENY", "203.0.113.7",
                    "policy", Rules.HONEYTOKEN_POLICY, "device", "pc-" + i);
        }
        Trails.Collected out = new Trails.Collected();
        DetectionEngine d = t.engine(out);
        d.poll();
        assertEquals(200, out.of(Rules.HONEYTOKEN).size());
        assertEquals(1, out.of(DetectionEngine.ALERT_FLOOD).size());
        assertEquals(Severity.CRITICAL, out.of(DetectionEngine.ALERT_FLOOD).getFirst().severity());
        assertEquals(1_800, d.stats().throttled());
    }

    /** SOC attack: a flood of one rule cannot bury a CRITICAL alert of another. */
    @Test
    void aDenyFloodCannotBuryABreakGlassAlert() {
        Trails t = new Trails();
        for (int i = 0; i < 5_000; i++) {
            t.decision(Trails.T0.plusMillis(i * 100L), "junk" + i, "DENY", "198.51.100." + (i % 200));
        }
        t.event(Trails.T0.plusSeconds(600), "BREAK_GLASS_USED", "bg-admin", "grantId", "bg-1", "subjectId", "bg-admin");
        Trails.Collected out = new Trails.Collected();
        t.engine(out).poll();
        assertEquals(1, out.of(Rules.BREAK_GLASS).size());
        assertTrue(out.of(Rules.DENY_STORM_IP).size() <= 50);
    }

    /** SOC attack: filling rule state with invented addresses is visible, not silent. */
    @Test
    void floodingDetectionStateRaisesStateFull() {
        Trails t = new Trails();
        for (int i = 0; i < 300; i++) {
            t.decision(Trails.T0.plusSeconds(i), "u" + i, "DENY", "203.0." + (i / 250) + "." + (i % 250));
        }
        Trails.Collected out = new Trails.Collected();
        DetectionEngine d = new DetectionEngine(t.sink, t.key, out, Optional::empty,
                new DetectionEngine.Settings(Duration.ofHours(1), 50, 200, 1000, 100, 500, 1_000_000));
        d.poll();
        assertEquals(1, out.of(DetectionEngine.STATE_FULL).size());
        assertTrue(d.stats().stateOverflow() > 0);
        assertTrue(d.stats().ruleState() <= 9 * 100 + 100);
    }

    /** SOC attack: requests sent in the CEO's name make the CEO the target of the alert, never the suspect alone. */
    @Test
    void junkInSomeonesNameNamesTheAttackingAddresses() {
        Trails t = new Trails();
        for (int i = 0; i < 5; i++) {
            t.decision(Trails.T0.plusSeconds(i * 10L), "ceo", "DENY", "45.155.205." + i);
        }
        Trails.Collected out = new Trails.Collected();
        t.engine(out).poll();
        Alert a = out.of(Rules.DENY_STORM_SUBJECT).getFirst();
        assertEquals(6, a.entities().size());
        assertEquals(5, a.entities().stream().filter(e -> e.kind() == Entity.Kind.IP).count());
        assertTrue(a.summary().contains("not evidence against them"));
    }

    /** SOC attack: someone who can write the store file but lacks the keys appends a forged break-glass record. */
    @Test
    void aFrameAppendedWithoutTheKeyIsDamageAndAChainBreak() throws Exception {
        Path store = dir.resolve("audit.dwas");
        var hmac = Trails.hmacKey();
        var aes = Trails.aesKey();
        try (EncryptedAuditStore s = EncryptedAuditStore.open(store, aes, EncryptedAuditStore.Durability.OS_BUFFERED)) {
            AuditLog log = new AuditLog(hmac, s);
            log.append("ACCESS_DECISION", "pdp", Trails.T0, Map.of("outcome", "ALLOW"));
        }
        // The attacker's own store, own key, valid frame for sequence 2.
        Path theirs = dir.resolve("theirs.dwas");
        var theirKey = Trails.aesKey();
        try (EncryptedAuditStore s = EncryptedAuditStore.open(theirs, theirKey, EncryptedAuditStore.Durability.OS_BUFFERED)) {
            AuditLog log = new AuditLog(Trails.hmacKey(), s);
            log.append("ACCESS_DECISION", "pdp", Trails.T0, Map.of("outcome", "ALLOW"));
            log.append("BREAK_GLASS_USED", "pdp", Trails.T0, Map.of("subjectId", "mallory"));
        }
        byte[] t = Files.readAllBytes(theirs);
        int firstLen = java.nio.ByteBuffer.wrap(t, EncryptedAuditStore.HEADER_BYTES, 4).getInt();
        int second = EncryptedAuditStore.HEADER_BYTES + 4 + firstLen;
        Files.write(store, java.util.Arrays.copyOfRange(t, second, t.length), StandardOpenOption.APPEND);

        try (EncryptedAuditStore s = EncryptedAuditStore.open(store, aes, EncryptedAuditStore.Durability.OS_BUFFERED)) {
            assertTrue(s.damage().orElseThrow().contains("authentication failed"));
            assertEquals(1, s.lastSequence());
            Trails.Collected out = new Trails.Collected();
            DetectionEngine d = new DetectionEngine(s, hmac, out, Optional::empty, DetectionEngine.Settings.defaults());
            d.poll();
            d.poll();
            assertTrue(out.of(Rules.BREAK_GLASS).isEmpty());
            assertEquals(1, out.of(DetectionEngine.CHAIN_BREAK).size());
            assertThrows(IllegalStateException.class, () -> s.write(new dev.dwarpal.audit.AuditRecord(2, Trails.T0,
                    "X", "pdp", "{}", s.head().mac(), "00".repeat(32))));
        }
    }
}

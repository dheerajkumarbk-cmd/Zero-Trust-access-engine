package dev.dwarpal.lab;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.siem.HeadAnchor;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The audit explorer's read side: paging, one record, and verification that notices every kind of tampering. */
class LabAuditTest {

    private static final Instant T0 = Instant.parse("2026-11-05T10:00:00Z");

    private record Rig(InMemoryAuditSink sink, AuditLog log, SecretKey key, HeadAnchor anchor, Path anchorFile,
                       LabAudit audit) {
    }

    private static Rig rig(int records) throws Exception {
        SecretKey key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        InMemoryAuditSink sink = new InMemoryAuditSink();
        AuditLog log = new AuditLog(key, sink);
        Path file = Files.createTempDirectory("dwarpal-labaudit").resolve("a.anchor");
        HeadAnchor anchor = new HeadAnchor(file, key, Clock.fixed(T0, ZoneOffset.UTC));
        for (int i = 1; i <= records; i++) {
            log.append(i % 3 == 0 ? "NOTE" : "DECISION", "actor" + (i % 2), T0.plusSeconds(i),
                    Map.of("n", Integer.toString(i)));
        }
        return new Rig(sink, log, key, anchor, file, new LabAudit(sink, key, anchor));
    }

    @Test
    void pagesShowRecordsInOrderFilterByTypeAndRefuseSillyArguments() throws Exception {
        Rig r = rig(30);
        LabAudit.Page p = r.audit().page(0, 10, Optional.empty());
        assertEquals(10, p.entries().size());
        assertEquals(1, p.entries().getFirst().sequence());
        assertTrue(p.more());
        assertEquals(30, p.head());
        LabAudit.Page last = r.audit().page(25, 10, Optional.empty());
        assertEquals(5, last.entries().size());
        assertFalse(last.more());
        LabAudit.Page notes = r.audit().page(0, 100, Optional.of("NOTE"));
        assertEquals(10, notes.entries().size());
        assertTrue(notes.entries().stream().allMatch(e -> e.type().equals("NOTE")));
        assertThrows(IllegalArgumentException.class, () -> r.audit().page(-1, 10, Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> r.audit().page(0, 0, Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> r.audit().page(0, LabAudit.MAX_PAGE + 1, Optional.empty()));
        assertEquals(30, r.audit().record(30).orElseThrow().entry().sequence());
        assertTrue(r.audit().record(31).isEmpty());
        assertTrue(r.audit().record(0).isEmpty());
        assertEquals(r.audit().record(7).orElseThrow().previousMac(), r.audit().record(6).orElseThrow().entry().mac());
    }

    @Test
    void anIntactChainThatReachesTheAnchorVerifies() throws Exception {
        Rig r = rig(40);
        r.anchor().anchor(r.log().head());
        LabAudit.Verified v = r.audit().verify();
        assertTrue(v.intact(), v.reason());
        assertTrue(v.anchorAgrees());
        assertEquals(40, v.records());
        // the chain grows after the anchor: still fine
        r.log().append("NOTE", "ana", T0.plusSeconds(99), Map.of("n", "x"));
        assertTrue(r.audit().verify().intact());
    }

    @Test
    void withoutAnAnchorItSaysSoAndAForgedAnchorIsTamperingNotSilence() throws Exception {
        Rig r = rig(10);
        LabAudit.Verified none = r.audit().verify();
        assertTrue(none.intact());
        assertFalse(none.anchorAgrees());
        assertTrue(none.reason().contains("no anchor"));

        r.anchor().anchor(r.log().head());
        Files.writeString(r.anchorFile(), "dwarpal-anchor/v1 10 " + "0".repeat(64) + " " + T0 + " " + "f".repeat(64) + "\n");
        LabAudit.Verified damaged = r.audit().verify();
        assertFalse(damaged.intact());
        assertTrue(damaged.reason().contains("anchor"), damaged.reason());
    }

    @Test
    void aChainCutShortRewrittenAndExtendedOrAlteredIsCaught() throws Exception {
        Rig r = rig(20);
        r.anchor().anchor(r.log().head());

        // truncated: the newest records removed
        InMemoryAuditSink cut = new InMemoryAuditSink();
        r.sink().snapshot().stream().limit(15).forEach(cut::write);
        LabAudit.Verified truncated = new LabAudit(cut, r.key(), r.anchor()).verify();
        assertFalse(truncated.intact());
        assertTrue(truncated.reason().contains("truncated"), truncated.reason());

        // rewritten at record 5 with the right key, then extended past the anchor: the head alone would not show it
        InMemoryAuditSink forged = new InMemoryAuditSink();
        AuditLog again = new AuditLog(r.key(), forged);
        for (AuditRecord rec : r.sink().snapshot()) {
            again.append(rec.type(), rec.actor(), rec.at(),
                    Map.of("n", rec.sequence() == 5 ? "FORGED" : Long.toString(rec.sequence())));
        }
        for (int i = 0; i < 5; i++) {
            again.append("NOTE", "x", T0.plusSeconds(500 + i), Map.of("n", "more"));
        }
        LabAudit.Verified rewritten = new LabAudit(forged, r.key(), r.anchor()).verify();
        assertFalse(rewritten.intact(), "history rewritten and extended must not pass");
        assertTrue(rewritten.reason().contains("rewritten") || rewritten.reason().contains("differs"), rewritten.reason());

        // altered record: a payload changed without the key
        List<AuditRecord> all = new ArrayList<>(r.sink().snapshot());
        AuditRecord x = all.get(9);
        all.set(9, new AuditRecord(x.sequence(), x.at(), x.type(), x.actor(), "{\"n\":\"changed\"}", x.previousMac(),
                x.mac()));
        InMemoryAuditSink altered = new InMemoryAuditSink();
        all.forEach(altered::write);
        LabAudit.Verified bad = new LabAudit(altered, r.key(), r.anchor()).verify();
        assertFalse(bad.intact());
        assertEquals(10, bad.firstBad());
    }
}

package dev.dwarpal.audit;

import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 5 part 0: reading the audit trail in order, and refusing everything after a break. */
class AuditCursorTest {

    private static final Instant T = Instant.parse("2026-11-04T10:00:00Z");

    private static SecretKey key() throws Exception {
        return KeyGenerator.getInstance("HmacSHA256").generateKey();
    }

    private static InMemoryAuditSink trail(SecretKey key, int n) {
        InMemoryAuditSink sink = new InMemoryAuditSink();
        AuditLog log = new AuditLog(key, sink);
        for (int i = 1; i <= n; i++) {
            log.append("ACCESS_DECISION", "pdp", T.plusSeconds(i), Map.of("subject", "u" + i, "outcome", "ALLOW"));
        }
        return sink;
    }

    /** A source over a fixed list, which an attacker may have edited. */
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

    private static AuditRecord withPayload(AuditRecord r, String payload) {
        return new AuditRecord(r.sequence(), r.at(), r.type(), r.actor(), payload, r.previousMac(), r.mac());
    }

    @Test
    void theWholeTrailIsReadInBatchesAndParsed() throws Exception {
        SecretKey k = key();
        InMemoryAuditSink sink = trail(k, 25);
        AuditCursor c = AuditCursor.fromStart(sink, k);
        List<AuditEvent> all = new ArrayList<>();
        AuditCursor.Batch b;
        do {
            b = c.next(10);
            assertTrue(b.problem().isEmpty());
            all.addAll(b.events());
        } while (!b.events().isEmpty());
        assertEquals(25, all.size());
        assertEquals(Optional.of("u7"), all.get(6).field("subject"));
        assertEquals(25, c.checkpoint().sequence());
        assertEquals(sink.snapshot().getLast().mac(), c.checkpoint().mac());
    }

    @Test
    void anAlteredRecordStopsTheCursorForGood() throws Exception {
        SecretKey k = key();
        List<AuditRecord> records = new ArrayList<>(trail(k, 10).snapshot());
        records.set(4, withPayload(records.get(4), "{\"subject\":\"someone-else\",\"outcome\":\"ALLOW\"}"));
        AuditCursor c = AuditCursor.fromStart(over(records), k);
        AuditCursor.Batch b = c.next(100);
        assertEquals(4, b.events().size(), "everything before the break is still delivered");
        assertTrue(b.problem().orElseThrow().contains("MAC mismatch"), b.problem().toString());
        AuditCursor.Batch after = c.next(100);
        assertTrue(after.events().isEmpty(), "nothing after a break is trusted, ever");
        assertEquals(b.problem(), after.problem());
        assertEquals(b.problem(), c.broken());
        assertEquals(4, c.checkpoint().sequence());
    }

    @Test
    void gapsReorderingAndDuplicatesAreBreaksEvenWithoutTheKey() throws Exception {
        List<AuditRecord> good = trail(key(), 6).snapshot();
        List<AuditRecord> gap = new ArrayList<>(good);
        gap.remove(2);
        assertTrue(AuditCursor.fromStart(over(gap)).next(100).problem().orElseThrow().contains("expected sequence 3"));

        List<AuditRecord> swapped = new ArrayList<>(good);
        swapped.set(2, good.get(3));
        swapped.set(3, good.get(2));
        assertTrue(AuditCursor.fromStart(over(swapped)).next(100).problem().isPresent());

        // The previous link must match: a record moved in from another trail breaks the chain.
        List<AuditRecord> spliced = new ArrayList<>(good);
        spliced.set(3, trail(key(), 6).snapshot().get(3));
        assertTrue(AuditCursor.fromStart(over(spliced)).next(100).problem().orElseThrow().contains("link"));
    }

    @Test
    void aChainForgedWithAnotherKeyPassesTheLinksButNotTheMacs() throws Exception {
        SecretKey real = key();
        List<AuditRecord> forged = trail(key(), 5).snapshot();
        assertTrue(AuditCursor.fromStart(over(forged)).next(100).problem().isEmpty(),
                "without the key a consistent forgery cannot be told apart (documented limit)");
        assertTrue(AuditCursor.fromStart(over(forged), real).next(100).problem().orElseThrow().contains("MAC"));
    }

    @Test
    void aCursorResumesFromATrustedCheckpointAndRefusesAWrongOne() throws Exception {
        SecretKey k = key();
        InMemoryAuditSink sink = trail(k, 12);
        AuditCursor first = AuditCursor.fromStart(sink, k);
        assertEquals(5, first.next(5).events().size());
        AuditLog.Head saved = first.checkpoint();
        AuditCursor.Batch rest = AuditCursor.resume(sink, k, saved).next(100);
        assertEquals(7, rest.events().size());
        assertEquals(6, rest.events().getFirst().sequence());
        assertTrue(AuditCursor.resume(sink, k, new AuditLog.Head(5, AuditLog.GENESIS)).next(100).problem().isPresent(),
                "a checkpoint that does not match the trail is a break");
        assertThrows(IllegalArgumentException.class, () -> AuditCursor.resume(sink, k, new AuditLog.Head(-1, "x")));
    }

    @Test
    void aTruncatedOrRewrittenTrailDisagreesWithItsAnchor() throws Exception {
        SecretKey k = key();
        InMemoryAuditSink sink = new InMemoryAuditSink();
        AuditLog log = new AuditLog(k, sink);
        for (int i = 0; i < 8; i++) {
            log.append("X", "pdp", T, Map.of("i", Integer.toString(i)));
        }
        AuditLog.Head anchor = log.head();

        AuditCursor whole = AuditCursor.fromStart(sink, k);
        whole.next(100);
        assertTrue(whole.checkAgainst(anchor).isEmpty());

        AuditCursor cut = AuditCursor.fromStart(over(sink.snapshot().subList(0, 6)), k);
        cut.next(100);
        assertTrue(cut.checkAgainst(anchor).orElseThrow().contains("truncated"));

        AuditCursor other = AuditCursor.fromStart(trail(key(), 8));
        other.next(100);
        assertTrue(other.checkAgainst(anchor).orElseThrow().contains("rewritten"));

        AuditCursor broken = AuditCursor.fromStart(over(List.of(sink.snapshot().get(1))), k);
        broken.next(100);
        assertEquals(broken.broken(), broken.checkAgainst(anchor));
    }

    @Test
    void aSourceThatSendsMoreThanAskedIsNotBelieved() throws Exception {
        List<AuditRecord> good = trail(key(), 5).snapshot();
        AuditSource greedy = new AuditSource() {
            @Override
            public List<AuditRecord> after(long sequence, int max) {
                return good;
            }

            @Override
            public long lastSequence() {
                return 5;
            }
        };
        AuditCursor.Batch b = AuditCursor.fromStart(greedy).next(2);
        assertEquals(2, b.events().size());
        assertTrue(b.problem().orElseThrow().contains("more records than asked"));
        assertThrows(IllegalArgumentException.class, () -> AuditCursor.fromStart(greedy).next(0));
    }

    @Test
    void payloadsMustBeFlatObjectsOfStrings() {
        AuditRecord base = new AuditRecord(1, T, "X", "pdp", "{}", AuditLog.GENESIS, "m");
        assertTrue(AuditEvent.of(base).fields().isEmpty());
        for (String bad : List.of("[]", "\"x\"", "{\"a\":1}", "{\"a\":{\"b\":\"c\"}}", "{\"a\":\"x\",\"a\":\"y\"}",
                "{\"a\":\"x\"", "{\"a\":null}", "{\"a\":[\"x\"]}")) {
            assertThrows(IllegalArgumentException.class, () -> AuditEvent.of(withPayload(base, bad)), bad);
        }
        String huge = "{\"a\":\"" + "x".repeat(70_000) + "\"}";
        assertThrows(IllegalArgumentException.class, () -> AuditEvent.of(withPayload(base, huge)));
    }

    @Test
    void anUnreadablePayloadIsABreakNotASkip() throws Exception {
        List<AuditRecord> records = new ArrayList<>(trail(key(), 3).snapshot());
        records.set(1, withPayload(records.get(1), "{\"a\":1}"));
        AuditCursor.Batch b = AuditCursor.fromStart(over(records)).next(10);
        assertEquals(1, b.events().size());
        assertTrue(b.problem().orElseThrow().contains("unreadable"));
    }

    @Test
    void theInMemorySinkAnswersRangesAndCapsBatches() throws Exception {
        InMemoryAuditSink sink = trail(key(), 30);
        assertEquals(30, sink.lastSequence());
        assertEquals(0, new InMemoryAuditSink().lastSequence());
        assertEquals(1, sink.after(0, 1).getFirst().sequence());
        assertEquals(List.of(11L, 12L, 13L), sink.after(10, 3).stream().map(AuditRecord::sequence).toList());
        assertTrue(sink.after(30, 5).isEmpty());
        assertTrue(sink.after(99, 5).isEmpty());
        assertTrue(sink.after(5, 0).isEmpty());
        assertEquals(30, sink.after(-3, Integer.MAX_VALUE).size());
        assertFalse(sink.after(0, 100).isEmpty());
    }

    @Test
    void aLongTrailIsReadInLinearTime() throws Exception {
        SecretKey k = key();
        InMemoryAuditSink sink = trail(k, 50_000);
        long start = System.nanoTime();
        AuditCursor c = AuditCursor.fromStart(sink, k);
        int n = 0;
        for (AuditCursor.Batch b = c.next(AuditSource.MAX_BATCH); !b.events().isEmpty(); b = c.next(AuditSource.MAX_BATCH)) {
            n += b.events().size();
        }
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertEquals(50_000, n);
        assertTrue(ms < 20_000, "50,000 records verified in " + ms + " ms");
    }
}

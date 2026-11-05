package dev.dwarpal.siem;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.AuditSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 5 part A: the encrypted, append-only audit store. Abuse cases first. */
class EncryptedAuditStoreTest {

    private static final EncryptedAuditStore.Durability FAST = EncryptedAuditStore.Durability.OS_BUFFERED;

    @TempDir
    Path dir;

    private final SecretKey aes = Trails.aesKey();
    private final SecretKey hmac = Trails.hmacKey();

    /** A store with {@code n} records; returns the file. */
    private Path filled(int n) throws Exception {
        Path f = dir.resolve("audit.dwas");
        try (EncryptedAuditStore s = EncryptedAuditStore.open(f, aes, FAST)) {
            AuditLog log = new AuditLog(hmac, s);
            for (int i = 1; i <= n; i++) {
                log.append("ACCESS_DECISION", "pdp", Trails.T0.plusSeconds(i),
                        Map.of("subject", "u" + i, "outcome", "ALLOW", "marker", "PLAINTEXT-MARKER-" + i));
            }
        }
        return f;
    }

    /** Byte offsets of each frame in the file. */
    private static List<int[]> frames(byte[] file) {
        List<int[]> out = new ArrayList<>();
        int pos = EncryptedAuditStore.HEADER_BYTES;
        while (pos + 4 <= file.length) {
            int len = ByteBuffer.wrap(file, pos, 4).getInt();
            out.add(new int[]{pos, 4 + len});
            pos += 4 + len;
        }
        return out;
    }

    private EncryptedAuditStore reopen(Path f) {
        return EncryptedAuditStore.open(f, aes, FAST);
    }

    // ---- tampering -----------------------------------------------------------------------------------

    @Test
    void aFlippedBitIsDetectedAndEarlierRecordsStayReadable() throws Exception {
        Path f = filled(5);
        byte[] b = Files.readAllBytes(f);
        int[] third = frames(b).get(2);
        b[third[0] + 4 + 20] ^= 0x01;
        Files.write(f, b);
        try (EncryptedAuditStore s = reopen(f)) {
            assertTrue(s.damage().orElseThrow().startsWith("record 3: authentication failed"));
            assertEquals(2, s.lastSequence());
            assertEquals(2, s.after(0, 100).size());
            IllegalStateException e = assertThrows(IllegalStateException.class, () -> s.after(2, 100));
            assertTrue(e.getMessage().contains("damaged"));
            assertThrows(IllegalStateException.class, () -> s.write(rec(3, s.head().mac())));
        }
    }

    @Test
    void swappedRecordsAreDetected() throws Exception {
        Path f = filled(4);
        byte[] b = Files.readAllBytes(f);
        List<int[]> fr = frames(b);
        // Frames 2 and 3 have the same length (same payload shape), so swapping them keeps the framing.
        assertEquals(fr.get(1)[1], fr.get(2)[1]);
        byte[] swapped = b.clone();
        System.arraycopy(b, fr.get(2)[0], swapped, fr.get(1)[0], fr.get(2)[1]);
        System.arraycopy(b, fr.get(1)[0], swapped, fr.get(2)[0], fr.get(1)[1]);
        Files.write(f, swapped);
        try (EncryptedAuditStore s = reopen(f)) {
            assertTrue(s.damage().orElseThrow().startsWith("record 2:"));
            assertEquals(1, s.lastSequence());
        }
    }

    @Test
    void aReplayedRecordIsDetected() throws Exception {
        Path f = filled(3);
        byte[] b = Files.readAllBytes(f);
        int[] first = frames(b).getFirst();
        Files.write(f, Arrays.copyOfRange(b, first[0], first[0] + first[1]), StandardOpenOption.APPEND);
        try (EncryptedAuditStore s = reopen(f)) {
            assertTrue(s.damage().orElseThrow().startsWith("record 4: authentication failed"));
            assertEquals(3, s.after(0, 100).size());
        }
    }

    @Test
    void aTornLastRecordIsDetected() throws Exception {
        Path f = filled(3);
        try (FileChannel ch = FileChannel.open(f, StandardOpenOption.WRITE)) {
            ch.truncate(ch.size() - 7);
        }
        try (EncryptedAuditStore s = reopen(f)) {
            assertTrue(s.damage().orElseThrow().contains("torn frame"));
            assertEquals(2, s.lastSequence());
        }
        try (FileChannel ch = FileChannel.open(f, StandardOpenOption.WRITE)) {
            ch.truncate(ch.size() - (ch.size() - EncryptedAuditStore.HEADER_BYTES) + 2);
        }
        try (EncryptedAuditStore s = reopen(f)) {
            assertTrue(s.damage().orElseThrow().contains("torn frame"));
        }
    }

    @Test
    void aTruncationAtAFrameBoundaryNeedsTheAnchor() throws Exception {
        Path f = filled(4);
        AuditLog.Head full;
        try (EncryptedAuditStore s = reopen(f)) {
            full = s.head();
        }
        byte[] b = Files.readAllBytes(f);
        int[] last = frames(b).getLast();
        Files.write(f, Arrays.copyOf(b, last[0]));
        try (EncryptedAuditStore s = reopen(f)) {
            assertTrue(s.damage().isEmpty(), "invisible to the store alone");
            AuditCursor c = AuditCursor.fromStart(s, hmac);
            assertEquals(3, c.next(100).events().size());
            assertTrue(c.checkAgainst(full).orElseThrow().contains("truncated"));
        }
    }

    @Test
    void aFrameLengthOutOfBoundsIsDamageNotAHugeAllocation() throws Exception {
        Path f = filled(2);
        byte[] b = Files.readAllBytes(f);
        int[] second = frames(b).get(1);
        ByteBuffer.wrap(b, second[0], 4).putInt(Integer.MAX_VALUE);
        Files.write(f, b);
        try (EncryptedAuditStore s = reopen(f)) {
            assertTrue(s.damage().orElseThrow().contains("frame length out of bounds"));
        }
    }

    @Test
    void theWrongKeyReadsNothing() throws Exception {
        Path f = filled(2);
        try (EncryptedAuditStore s = EncryptedAuditStore.open(f, Trails.aesKey(), FAST)) {
            assertTrue(s.damage().orElseThrow().startsWith("record 1: authentication failed"));
            assertEquals(0, s.lastSequence());
            assertThrows(IllegalStateException.class, () -> s.after(0, 10));
        }
    }

    @Test
    void aChangedStoreIdBreaksEveryRecord() throws Exception {
        Path f = filled(2);
        byte[] b = Files.readAllBytes(f);
        b[EncryptedAuditStore.MAGIC.length + 1] ^= 0x40;
        Files.write(f, b);
        try (EncryptedAuditStore s = reopen(f)) {
            assertTrue(s.damage().orElseThrow().startsWith("record 1:"));
        }
    }

    @Test
    void aFileChangedAfterOpeningIsCaughtOnRead() throws Exception {
        Path f = filled(3);
        try (EncryptedAuditStore s = reopen(f)) {
            assertTrue(s.damage().isEmpty());
            byte[] b = Files.readAllBytes(f);
            int[] second = frames(b).get(1);
            try (FileChannel ch = FileChannel.open(f, StandardOpenOption.WRITE)) {
                ch.write(ByteBuffer.wrap(new byte[]{(byte) (b[second[0] + 30] ^ 0x10)}), second[0] + 30);
            }
            assertEquals(1, s.after(0, 100).size());
            assertTrue(s.damage().orElseThrow().startsWith("record 2:"));
            assertThrows(IllegalStateException.class, () -> s.after(1, 100));
            assertThrows(IllegalStateException.class, () -> s.write(rec(4, s.head().mac())));
        }
    }

    @Test
    void notAStoreIsRefused() throws Exception {
        Path f = dir.resolve("other");
        Files.writeString(f, "hello, this is not an audit store at all");
        assertThrows(IllegalArgumentException.class, () -> reopen(f));
        Path g = dir.resolve("short");
        Files.write(g, new byte[]{'D', 'W'});
        assertThrows(IllegalArgumentException.class, () -> reopen(g));
    }

    // ---- what the writer may do --------------------------------------------------------------------------

    @Test
    void onlyTheNextRecordOfTheChainIsAccepted() {
        try (EncryptedAuditStore s = reopenNew()) {
            assertThrows(IllegalStateException.class, () -> s.write(rec(2, AuditLog.GENESIS)), "gap");
            assertThrows(IllegalStateException.class, () -> s.write(rec(1, "ab".repeat(32))), "fork");
            s.write(rec(1, AuditLog.GENESIS));
            assertThrows(IllegalStateException.class, () -> s.write(rec(1, AuditLog.GENESIS)), "replay");
            assertEquals(1, s.lastSequence());
        } catch (java.io.IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Test
    void oversizedRecordsAreRefusedBeforeAnythingIsWritten() throws Exception {
        try (EncryptedAuditStore s = reopenNew()) {
            String huge = "x".repeat(EncryptedAuditStore.MAX_RECORD_BYTES);
            assertThrows(IllegalArgumentException.class, () -> s.write(new AuditRecord(1, Trails.T0, "T", "pdp",
                    "{\"v\":\"" + huge + "\"}", AuditLog.GENESIS, "00".repeat(32))));
            assertEquals(0, s.lastSequence());
            assertTrue(s.damage().isEmpty());
            assertEquals(EncryptedAuditStore.HEADER_BYTES, Files.size(dir.resolve("new.dwas")));
        }
    }

    @Test
    void aSecondWriterOnTheSameFileIsRefused() throws Exception {
        try (EncryptedAuditStore s = reopenNew()) {
            assertThrows(IllegalStateException.class, () -> EncryptedAuditStore.open(dir.resolve("new.dwas"), aes, FAST));
            s.write(rec(1, AuditLog.GENESIS));
        }
        try (EncryptedAuditStore again = EncryptedAuditStore.open(dir.resolve("new.dwas"), aes, FAST)) {
            assertEquals(1, again.lastSequence());
        }
    }

    @Test
    void onlyA256BitAesKeyIsAccepted() {
        Path f = dir.resolve("k.dwas");
        assertThrows(IllegalArgumentException.class, () -> EncryptedAuditStore.open(f, hmac, FAST));
        assertThrows(IllegalArgumentException.class,
                () -> EncryptedAuditStore.open(f, new SecretKeySpec(new byte[16], "AES"), FAST));
        assertThrows(IllegalArgumentException.class,
                () -> EncryptedAuditStore.open(f, new SecretKeySpec(new byte[32], "AES"), FAST));
        assertFalse(Files.exists(f));
    }

    @Test
    void theFileHoldsNeitherPlaintextNorTheKey() throws Exception {
        Path f = filled(20);
        byte[] b = Files.readAllBytes(f);
        String asText = new String(b, StandardCharsets.ISO_8859_1);
        assertFalse(asText.contains("PLAINTEXT-MARKER"));
        assertFalse(asText.contains("ACCESS_DECISION"));
        byte[] k = aes.getEncoded();
        for (int i = 0; i + k.length <= b.length; i++) {
            assertFalse(Arrays.equals(b, i, i + k.length, k, 0, k.length));
        }
        // Fresh nonces: no two frames share one.
        List<String> nonces = new ArrayList<>();
        for (int[] fr : frames(b)) {
            nonces.add(Arrays.toString(Arrays.copyOfRange(b, fr[0] + 4, fr[0] + 4 + EncryptedAuditStore.NONCE_BYTES)));
        }
        assertEquals(nonces.size(), nonces.stream().distinct().count());
    }

    // ---- normal use ------------------------------------------------------------------------------------

    @Test
    void recordsSurviveReopeningExactlyAndTheChainVerifies() throws Exception {
        Path f = filled(30);
        try (EncryptedAuditStore s = EncryptedAuditStore.open(f, aes, EncryptedAuditStore.Durability.SYNC_EVERY_RECORD)) {
            assertEquals(30, s.lastSequence());
            assertEquals(Trails.T0.plusSeconds(30), s.lastTime().orElseThrow());
            List<AuditRecord> all = s.after(0, 1000);
            assertEquals(30, all.size());
            assertTrue(AuditLog.verify(all, hmac, s.head()).intact());
            assertEquals(10, s.after(5, 10).size());
            assertEquals(6, s.after(5, 10).getFirst().sequence());
            assertTrue(s.after(30, 10).isEmpty());
            assertTrue(s.after(-4, 0).isEmpty());
            assertEquals(1, s.after(-4, 1).getFirst().sequence());
            // and it keeps appending where it left off, durably
            AuditRecord last = all.getLast();
            s.write(new AuditRecord(31, Trails.T0, "X", "pdp", "{}", last.mac(), "cd".repeat(32)));
            assertEquals(31, s.lastSequence());
        }
    }

    @Test
    void batchesAreCappedLikeEverySource() throws Exception {
        Path f = dir.resolve("big.dwas");
        try (EncryptedAuditStore s = EncryptedAuditStore.open(f, aes, FAST)) {
            AuditLog log = new AuditLog(hmac, s);
            for (int i = 0; i < AuditSource.MAX_BATCH + 50; i++) {
                log.append("T", "pdp", Trails.T0, Map.of());
            }
            assertEquals(AuditSource.MAX_BATCH, s.after(0, Integer.MAX_VALUE).size());
            assertEquals(50, s.after(AuditSource.MAX_BATCH, Integer.MAX_VALUE).size());
        }
    }

    @Test
    void aClosedStoreRefusesEverything() throws Exception {
        EncryptedAuditStore s = reopenNew();
        s.close();
        s.close();
        assertThrows(IllegalStateException.class, () -> s.write(rec(1, AuditLog.GENESIS)));
        assertThrows(IllegalStateException.class, () -> s.after(0, 1));
    }

    @Test
    void encodingRoundTripsAndRefusesGarbage() {
        AuditRecord r = new AuditRecord(7, Trails.T0.plusNanos(123), "TYPE", "actor", "{\"a\":\"é\"}", "p", "m");
        assertEquals(r, EncryptedAuditStore.decode(EncryptedAuditStore.encode(r)));
        byte[] e = EncryptedAuditStore.encode(r);
        assertThrows(RuntimeException.class, () -> EncryptedAuditStore.decode(Arrays.copyOf(e, e.length + 1)));
        byte[] bad = e.clone();
        ByteBuffer.wrap(bad, 20, 4).putInt(-1);
        assertThrows(IllegalArgumentException.class, () -> EncryptedAuditStore.decode(bad));
        assertArrayEquals(e, EncryptedAuditStore.encode(r));
    }

    private EncryptedAuditStore reopenNew() {
        return EncryptedAuditStore.open(dir.resolve("new.dwas"), aes, FAST);
    }

    private static AuditRecord rec(long seq, String prev) {
        return new AuditRecord(seq, Trails.T0, "TYPE", "pdp", "{}", prev, "ef".repeat(32));
    }
}

package dev.dwarpal.siem;

import dev.dwarpal.audit.AuditLog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 5 part A: anchoring the chain head outside the trail. Abuse cases first. */
class HeadAnchorTest {

    @TempDir
    Path dir;

    private final Clock clock = Clock.fixed(Trails.T0, ZoneOffset.UTC);
    private final javax.crypto.SecretKey key = Trails.hmacKey();

    private HeadAnchor anchor() {
        return new HeadAnchor(dir.resolve("anchor"), key, clock);
    }

    private static AuditLog.Head head(long seq, char c) {
        return new AuditLog.Head(seq, String.valueOf(c).repeat(64));
    }

    @Test
    void anAlteredAnchorIsRefused() throws Exception {
        anchor().anchor(head(10, 'a'));
        Path f = dir.resolve("anchor");
        String line = Files.readString(f);
        Files.writeString(f, line.replace(" 10 ", " 12 "));
        assertTrue(assertThrows(IllegalStateException.class, () -> anchor().read()).getMessage().contains("forged"));
        Files.writeString(f, "dwarpal-anchor/v1 nonsense");
        assertThrows(IllegalStateException.class, () -> anchor().read());
        Files.writeString(f, line.replace("2026", "2O26"));
        assertThrows(IllegalStateException.class, () -> anchor().read());
        Files.writeString(f, "x".repeat(600));
        assertThrows(IllegalStateException.class, () -> anchor().read());
    }

    @Test
    void anAnchorWrittenWithAnotherKeyIsRefused() {
        new HeadAnchor(dir.resolve("anchor"), Trails.hmacKey(), clock).anchor(head(3, 'b'));
        assertThrows(IllegalStateException.class, () -> anchor().read());
    }

    @Test
    void theAnchorOnlyMovesForward() {
        HeadAnchor a = anchor();
        a.anchor(head(10, 'a'));
        assertThrows(IllegalStateException.class, () -> a.anchor(head(9, 'a')), "rollback");
        assertThrows(IllegalStateException.class, () -> a.anchor(head(10, 'b')), "rewrite");
        a.anchor(head(10, 'a'));
        a.anchor(head(11, 'c'));
        assertEquals(head(11, 'c'), a.read().orElseThrow());
    }

    @Test
    void aRemovedOrRolledBackAnchorIsTamperingOnceOneExisted() throws Exception {
        HeadAnchor a = anchor();
        assertEquals(Optional.empty(), a.read());
        a.anchor(head(5, 'a'));
        Path f = dir.resolve("anchor");
        String five = Files.readString(f);
        a.anchor(head(8, 'b'));
        Files.writeString(f, five);
        assertTrue(assertThrows(IllegalStateException.class, a::read).getMessage().contains("rolled back"));
        Files.delete(f);
        assertTrue(assertThrows(IllegalStateException.class, a::read).getMessage().contains("removed"));
    }

    @Test
    void readFreshRefusesMissingStaleAndFutureAnchors() {
        assertThrows(IllegalStateException.class, () -> anchor().readFresh(Duration.ofMinutes(5)));
        new HeadAnchor(dir.resolve("anchor"), key, Clock.fixed(Trails.T0.plusSeconds(3600), ZoneOffset.UTC))
                .anchor(head(1, 'a'));
        assertTrue(assertThrows(IllegalStateException.class, () -> anchor().readFresh(Duration.ofMinutes(5)))
                .getMessage().contains("future"));
        HeadAnchor late = new HeadAnchor(dir.resolve("anchor"), key,
                Clock.fixed(Trails.T0.plusSeconds(7200), ZoneOffset.UTC));
        assertEquals(head(1, 'a'), late.readFresh(Duration.ofHours(2)));
        assertThrows(IllegalStateException.class, () -> late.readFresh(Duration.ofMinutes(30)));
    }

    @Test
    void onlyChainHeadsAndStrongKeysAreAccepted() {
        HeadAnchor a = anchor();
        assertThrows(IllegalArgumentException.class, () -> a.anchor(new AuditLog.Head(-1, "a".repeat(64))));
        assertThrows(IllegalArgumentException.class, () -> a.anchor(new AuditLog.Head(1, "not hex")));
        assertThrows(IllegalArgumentException.class,
                () -> new HeadAnchor(dir.resolve("x"), new SecretKeySpec(new byte[16], "HmacSHA256"), clock));
    }

    @Test
    void theLineIsReadableAndNamesNoSecret() throws Exception {
        anchor().anchor(head(42, 'd'));
        String line = Files.readString(dir.resolve("anchor"), StandardCharsets.US_ASCII);
        assertTrue(line.startsWith(HeadAnchor.VERSION + " 42 " + "d".repeat(64) + " " + Trails.T0 + " "));
        assertTrue(Files.notExists(dir.resolve("anchor.tmp")));
    }

    @Test
    void theScheduleAnchorsAndCountsFailures() throws Exception {
        HeadAnchor a = anchor();
        AtomicInteger calls = new AtomicInteger();
        ScheduledExecutorService ex = Executors.newSingleThreadScheduledExecutor();
        try {
            assertThrows(IllegalArgumentException.class, () -> a.schedule(ex, () -> head(1, 'a'), Duration.ofMillis(10)));
            ScheduledFuture<?> f = a.schedule(ex, () -> calls.incrementAndGet() == 1 ? head(7, 'e') : head(6, 'e'),
                    Duration.ofSeconds(1));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (a.failures() == 0 && System.nanoTime() < deadline) {
                Thread.sleep(50);
            }
            f.cancel(false);
        } finally {
            ex.shutdownNow();
        }
        assertEquals(head(7, 'e'), a.read().orElseThrow());
        assertTrue(a.failures() >= 1, "the rollback attempt is counted, the schedule survives it");
    }
}

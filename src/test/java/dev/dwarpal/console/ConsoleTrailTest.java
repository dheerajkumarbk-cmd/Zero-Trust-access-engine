package dev.dwarpal.console;

import dev.dwarpal.lab.LabAudit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The saved audit trail: it survives a restart, continues its chain, and a damaged, cut or replaced trail is refused. */
class ConsoleTrailTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-08T10:00:00Z"), ZoneOffset.UTC);

    @TempDir
    Path dir;

    private static void write(ConsoleTrail t, String type, String who, String text) {
        t.log().append(type, who, CLOCK.instant(), Map.of("note", text));
    }

    @Test
    void recordsSurviveARestartAndTheChainContinuesFromWhereItStopped() throws Exception {
        try (ConsoleTrail t = ConsoleTrail.open(dir, CLOCK)) {
            assertEquals(0, t.records());
            write(t, "CONSOLE_LOGIN", "ana", "one");
            write(t, "CONSOLE_READ", "ana", "two");
        }
        try (ConsoleTrail t = ConsoleTrail.open(dir, CLOCK)) {
            assertEquals(2, t.records(), "the two records are still there");
            write(t, "CONSOLE_LOGOUT", "ana", "three");
            assertEquals(3, t.records());
            LabAudit.Verified v = t.view().verify();
            assertTrue(v.intact(), v.reason());
            assertEquals(3, v.records());
            assertTrue(v.anchorAgrees(), "the chain reaches the anchored head");
            List<LabAudit.Entry> all = t.view().page(0, 10, Optional.empty()).entries();
            assertEquals(List.of("CONSOLE_LOGIN", "CONSOLE_READ", "CONSOLE_LOGOUT"), all.stream().map(LabAudit.Entry::type).toList());
        }
        try (ConsoleTrail t = ConsoleTrail.open(dir, CLOCK)) {
            assertEquals(3, t.records(), "and again after a second restart");
            assertEquals(3, t.view().verify().anchoredSeq().orElseThrow(), "the close anchored the newest record");
        }
    }

    @Test
    void anEmptyTrailIsNotAnchoredAndOpensAgain() throws Exception {
        try (ConsoleTrail t = ConsoleTrail.open(dir, CLOCK)) {
            assertEquals(0, t.records());
        }
        assertFalse(Files.exists(dir.resolve(ConsoleTrail.ANCHOR)), "nothing to anchor yet");
        try (ConsoleTrail t = ConsoleTrail.open(dir, CLOCK)) {
            assertEquals(0, t.records());
        }
    }

    @Test
    void theThreeKeysAreDifferentAndNeverInsideTheTrail() throws Exception {
        try (ConsoleTrail t = ConsoleTrail.open(dir, CLOCK)) {
            write(t, "CONSOLE_LOGIN", "ana", "one");
        }
        List<String> keys = Files.readAllLines(dir.resolve(ConsoleTrail.KEYS)).stream().filter(l -> !l.startsWith("#"))
                .map(l -> l.split(" ")[1]).collect(Collectors.toList());
        assertEquals(3, keys.size());
        assertEquals(3, keys.stream().distinct().count(), "store, chain and anchor use different keys");
        String store = new String(Files.readAllBytes(dir.resolve(ConsoleTrail.STORE)), StandardCharsets.ISO_8859_1);
        for (String k : keys) {
            assertFalse(store.contains(k));
        }
        assertFalse(store.contains("CONSOLE_LOGIN"), "the records are encrypted on disk");
    }

    @Test
    void aTrailWithoutItsKeyFileIsRefusedNotReplaced() throws Exception {
        try (ConsoleTrail t = ConsoleTrail.open(dir, CLOCK)) {
            write(t, "CONSOLE_LOGIN", "ana", "one");
        }
        long size = Files.size(dir.resolve(ConsoleTrail.STORE));
        Files.delete(dir.resolve(ConsoleTrail.KEYS));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> ConsoleTrail.open(dir, CLOCK));
        assertTrue(e.getMessage().contains("key file"), e.getMessage());
        assertFalse(Files.exists(dir.resolve(ConsoleTrail.KEYS)), "no new keys were made over the old trail");
        assertEquals(size, Files.size(dir.resolve(ConsoleTrail.STORE)), "the trail is untouched");
    }

    @Test
    void aTrailCutShortIsRefusedAndLeftAsItIs() throws Exception {
        long afterTwo;
        try (ConsoleTrail t = ConsoleTrail.open(dir, CLOCK)) {
            write(t, "CONSOLE_LOGIN", "ana", "one");
            write(t, "CONSOLE_READ", "ana", "two");
            afterTwo = Files.size(dir.resolve(ConsoleTrail.STORE));
            write(t, "CONSOLE_LOGOUT", "ana", "three");
        }
        try (FileChannel c = FileChannel.open(dir.resolve(ConsoleTrail.STORE), StandardOpenOption.WRITE)) {
            c.truncate(afterTwo);
        }
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> ConsoleTrail.open(dir, CLOCK));
        assertTrue(e.getMessage().contains("was not accepted"), e.getMessage());
        assertEquals(afterTwo, Files.size(dir.resolve(ConsoleTrail.STORE)), "the cut file is left as it is");
    }

    @Test
    void aDeletedTrailIsNotQuietlyStartedAgain() throws Exception {
        try (ConsoleTrail t = ConsoleTrail.open(dir, CLOCK)) {
            write(t, "CONSOLE_LOGIN", "ana", "one");
        }
        Files.delete(dir.resolve(ConsoleTrail.STORE));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> ConsoleTrail.open(dir, CLOCK));
        assertTrue(e.getMessage().contains("was not accepted"), e.getMessage());
    }

    @Test
    void anAlteredByteInTheTrailIsRefused() throws Exception {
        try (ConsoleTrail t = ConsoleTrail.open(dir, CLOCK)) {
            write(t, "CONSOLE_LOGIN", "ana", "one");
            write(t, "CONSOLE_READ", "ana", "two");
        }
        Path store = dir.resolve(ConsoleTrail.STORE);
        byte[] bytes = Files.readAllBytes(store);
        bytes[bytes.length - 20] ^= 0x01;
        Files.write(store, bytes);
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> ConsoleTrail.open(dir, CLOCK));
        assertTrue(e.getMessage().contains("damaged"), e.getMessage());
    }

    @Test
    void aSecondRunOnTheSameFilesIsRefusedWhileTheFirstIsOpen() throws Exception {
        try (ConsoleTrail first = ConsoleTrail.open(dir, CLOCK)) {
            write(first, "CONSOLE_LOGIN", "ana", "one");
            assertThrows(IllegalStateException.class, () -> ConsoleTrail.open(dir, CLOCK));
            assertEquals(1, first.records(), "the first run is unharmed");
        }
    }

    @Test
    void theAnchorFollowsTheHeadOnDemand() throws Exception {
        try (ConsoleTrail t = ConsoleTrail.open(dir, CLOCK)) {
            write(t, "CONSOLE_LOGIN", "ana", "one");
            assertNotEquals(1L, t.view().verify().anchoredSeq().orElse(-1L), "not anchored yet: it follows on a schedule");
            t.anchorNow();
            assertEquals(1L, t.view().verify().anchoredSeq().orElseThrow());
            assertEquals(0, t.anchorFailures());
        }
    }

    @Test
    void theKeyFileIsNotReadableAsATrail() throws IOException {
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(ConsoleTrail.KEYS), "store nothex\n");
        assertThrows(IllegalStateException.class, () -> ConsoleTrail.open(dir, CLOCK));
    }
}

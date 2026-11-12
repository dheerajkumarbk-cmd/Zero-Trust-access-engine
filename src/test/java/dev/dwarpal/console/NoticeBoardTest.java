package dev.dwarpal.console;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Notices are for one person each, stay until read, survive a restart, and cannot be read or cleared by anyone else. */
class NoticeBoardTest {

    @TempDir
    Path dir;

    @Test
    void aPersonSeesOnlyTheirOwnNewestFirstAndReadingOnlyClearsTheirOwn() {
        NoticeBoard b = NoticeBoard.inMemory(Clock.systemUTC());
        b.post("ana", "first");
        b.post("ben", "for ben");
        b.post("ana", "second");
        assertEquals(List.of("second", "first"), b.of("ana", 10).stream().map(NoticeBoard.Notice::text).toList());
        assertEquals(2, b.unread("ana"));
        b.markRead("ben", null);
        assertEquals(2, b.unread("ana"), "somebody else reading theirs changes nothing");
        String firstId = b.of("ana", 10).getLast().id();
        b.markRead("ana", firstId);
        assertEquals(1, b.unread("ana"));
        b.markRead("ana", null);
        assertEquals(0, b.unread("ana"));
        assertEquals(0, b.unread("ben"), "ben read his");
    }

    @Test
    void theyComeBackAfterARestartAndTheTextCannotBreakTheFile() throws Exception {
        Path file = dir.resolve("notices.txt");
        NoticeBoard b = NoticeBoard.open(file, Clock.systemUTC());
        b.post("ana", "line one|with a bar\nand a second line");
        b.post("ana", "x".repeat(1000));
        NoticeBoard again = NoticeBoard.open(file, Clock.systemUTC());
        assertEquals(2, again.of("ana", 10).size());
        assertFalse(again.of("ana", 10).getLast().text().contains("\n"));
        assertTrue(again.of("ana", 10).getFirst().text().length() <= 320 && again.of("ana", 10).getFirst().text().endsWith("[truncated]"));
        again.post("ana", "third");
        assertEquals(3, again.unread("ana"));
        assertEquals("n-3", again.of("ana", 1).getFirst().id(), "numbers go on after a restart");
        Files.writeString(file, "garbage without the right shape\n");
        assertThrows(java.io.IOException.class, () -> NoticeBoard.open(file, Clock.systemUTC()));
    }

    @Test
    void onlyTheNewestFiveHundredAreKept() {
        NoticeBoard b = NoticeBoard.inMemory(Clock.systemUTC());
        for (int i = 0; i < 520; i++) {
            b.post("ana", "n" + i);
        }
        assertEquals(500, b.unread("ana"));
        assertEquals("n519", b.of("ana", 1).getFirst().text());
    }
}

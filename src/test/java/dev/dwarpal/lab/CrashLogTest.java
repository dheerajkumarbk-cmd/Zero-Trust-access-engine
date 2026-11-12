package dev.dwarpal.lab;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The lab leaves a readable reason behind when it dies, and never writes the environment into it. */
class CrashLogTest {

    @TempDir
    Path dir;

    private static List<Path> files(Path folder) throws IOException {
        try (Stream<Path> s = Files.list(folder)) {
            return s.toList();
        }
    }

    @Test
    void aReportHasTheExceptionItsCauseTheFiguresAndEveryThread() throws Exception {
        Path logs = dir.resolve("logs");
        RuntimeException error = new RuntimeException("boom-test", new IllegalStateException("root-cause-test"));
        error.addSuppressed(new IllegalArgumentException("side-test"));

        Path file = CrashLog.writeTo(logs, "shutdown", error);

        assertEquals(List.of(file), files(logs));
        assertTrue(file.getFileName().toString().matches("crash-\\d{8}-\\d{6}-\\d+\\.log"), file.toString());
        String text = Files.readString(file, StandardCharsets.UTF_8);
        assertTrue(text.contains("java.lang.RuntimeException: boom-test"), text);
        assertTrue(text.contains("Caused by: java.lang.IllegalStateException: root-cause-test"), text);
        assertTrue(text.contains("Suppressed: java.lang.IllegalArgumentException: side-test"), text);
        assertTrue(text.contains("--- thread dump ---"), text);
        assertTrue(text.contains("\"" + Thread.currentThread().getName() + "\""), text);
        assertTrue(text.contains("heap: used="), text);
        assertTrue(text.contains("threads: live="), text);
        assertFalse(text.contains("JAVA_HOME"), text);
        assertFalse(text.contains(System.getProperty("java.home")), text);
        String path = System.getenv("PATH");
        if (path != null && !path.isBlank()) {
            assertFalse(text.contains(path), "the environment must not be written");
        }
    }

    @Test
    void reportsAreAppendedToTheSameFile() throws Exception {
        Path first = CrashLog.writeTo(dir, "first", null);
        Path second = CrashLog.writeTo(dir, "second", null);

        assertEquals(first, second);
        String text = Files.readString(first, StandardCharsets.UTF_8);
        assertTrue(text.contains("=== first ==="), text);
        assertTrue(text.contains("=== second ==="), text);
        assertTrue(text.contains("last uncaught exception: none"), text);
    }

    @Test
    void theUncaughtHandlerWritesThreadAndReasonAndTheShutdownRecordRemembersIt() throws Exception {
        Path logs = dir.resolve("deeper").resolve("logs");

        CrashLog.handler(logs, null).uncaughtException(Thread.currentThread(), new IllegalStateException("handler-test"));
        CrashLog.onShutdown(logs);

        String text = Files.readString(files(logs).get(0), StandardCharsets.UTF_8);
        assertTrue(text.contains("=== uncaught exception ==="), text);
        assertTrue(text.contains("thread: " + Thread.currentThread().getName()), text);
        assertTrue(text.contains("java.lang.IllegalStateException: handler-test"), text);
        assertTrue(text.contains("=== shutdown ==="), text);
        assertFalse(text.contains("last uncaught exception: none"), text);
    }

    @Test
    void theLogFolderFollowsTheDirOptionAndDefaultsToLab() {
        assertEquals(Path.of("lab", "logs"), CrashLog.logDirFor(new String[]{}));
        assertEquals(Path.of("x", "logs"), CrashLog.logDirFor(new String[]{"--users", "30", "--dir", "x"}));
        assertEquals(Path.of("lab", "logs"), CrashLog.logDirFor(new String[]{"--dir"}));
    }
}

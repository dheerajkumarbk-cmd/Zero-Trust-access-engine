package dev.dwarpal.lab;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryUsage;
import java.lang.management.ThreadMXBean;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Leaves a reason behind when the lab process dies. Installed first thing by {@link LabMain}: an uncaught exception in
 * any thread, and the JVM shutdown itself, are each appended to {@code <lab dir>/logs/crash-<time>-<pid>.log}
 * (UTF-8). A shutdown record holds the uptime, the last uncaught exception, thread and heap figures and a dump of every
 * thread. It never writes environment variables, system properties or command-line arguments, and nothing here throws:
 * a failure to write is reduced to one line on standard error.
 */
public final class CrashLog {

    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private static final String START_STAMP = LocalDateTime.now().format(STAMP);
    private static final long START_MILLIS = System.currentTimeMillis();
    private static final AtomicReference<Throwable> LAST = new AtomicReference<>();

    private CrashLog() {
    }

    /** Where the crash log goes for these launcher arguments: {@code <--dir, default lab>/logs}; never throws. */
    static Path logDirFor(String[] args) {
        String dir = "lab";
        for (int i = 0; i + 1 < args.length; i += 2) {
            if ("--dir".equals(args[i])) {
                dir = args[i + 1];
            }
        }
        try {
            return Path.of(dir, "logs");
        } catch (InvalidPathException e) {
            return Path.of("lab", "logs");
        }
    }

    /** Registers the uncaught-exception handler and the shutdown hook; never throws. */
    public static void install(Path dir) {
        try {
            Thread.setDefaultUncaughtExceptionHandler(handler(dir, Thread.getDefaultUncaughtExceptionHandler()));
            Runtime.getRuntime().addShutdownHook(new Thread(() -> onShutdown(dir), "dwarpal-crash-log"));
        } catch (RuntimeException | Error e) {
            System.err.println("crash log not installed: " + e);
        }
    }

    static Thread.UncaughtExceptionHandler handler(Path dir, Thread.UncaughtExceptionHandler previous) {
        return (thread, error) -> {
            LAST.set(error);
            try {
                Path file = append(dir, w -> writeUncaught(w, thread, error));
                System.err.println("crash log written: " + file);
            } catch (IOException | RuntimeException | Error e) {
                System.err.println("crash log could not be written: " + e);
            }
            if (previous != null) {
                previous.uncaughtException(thread, error);
            } else {
                try {
                    StringWriter text = new StringWriter();
                    writeTrace(text, error, "", Collections.newSetFromMap(new IdentityHashMap<>()));
                    System.err.print("Exception in thread \"" + thread.getName() + "\" " + text);
                } catch (IOException | RuntimeException | Error e) {
                    System.err.println("Exception in thread \"" + thread.getName() + "\" " + error);
                }
            }
        };
    }

    static void onShutdown(Path dir) {
        try {
            writeTo(dir, "shutdown", LAST.get());
        } catch (IOException | RuntimeException | Error e) {
            System.err.println("crash log could not be written: " + e);
        }
    }

    /** Appends a full report (figures, last exception, every thread) to this process's crash file and returns it. */
    static Path writeTo(Path dir, String reason, Throwable last) throws IOException {
        return append(dir, w -> writeReport(w, reason, last));
    }

    static void writeReport(Writer out, String reason, Throwable last) throws IOException {
        line(out, "=== " + reason + " ===");
        line(out, "time: " + Instant.now());
        line(out, "pid: " + ProcessHandle.current().pid());
        line(out, "uptime: " + (System.currentTimeMillis() - START_MILLIS) / 1000 + " s");
        if (last == null) {
            line(out, "last uncaught exception: none");
        } else {
            line(out, "last uncaught exception:");
            writeTrace(out, last, "", Collections.newSetFromMap(new IdentityHashMap<>()));
        }
        ThreadMXBean threads = ManagementFactory.getThreadMXBean();
        line(out, "threads: live=" + threads.getThreadCount() + " peak=" + threads.getPeakThreadCount()
                + " daemon=" + threads.getDaemonThreadCount());
        MemoryUsage heap = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
        line(out, "heap: used=" + mib(heap.getUsed()) + " committed=" + mib(heap.getCommitted()) + " max="
                + mib(heap.getMax()));
        line(out, "--- thread dump ---");
        List<Map.Entry<Thread, StackTraceElement[]>> all = new ArrayList<>(Thread.getAllStackTraces().entrySet());
        all.sort(Comparator.comparingLong(entry -> entry.getKey().threadId()));
        for (Map.Entry<Thread, StackTraceElement[]> entry : all) {
            Thread t = entry.getKey();
            line(out, "\"" + t.getName() + "\" id=" + t.threadId() + " daemon=" + t.isDaemon() + " state="
                    + t.getState() + " priority=" + t.getPriority());
            for (StackTraceElement frame : entry.getValue()) {
                line(out, "\tat " + frame);
            }
        }
        line(out, "=== end ===");
    }

    private static void writeUncaught(Writer out, Thread thread, Throwable error) throws IOException {
        line(out, "=== uncaught exception ===");
        line(out, "time: " + Instant.now());
        line(out, "thread: " + thread.getName());
        writeTrace(out, error, "", Collections.newSetFromMap(new IdentityHashMap<>()));
        line(out, "=== end ===");
    }

    private static void writeTrace(Writer out, Throwable t, String prefix, Set<Throwable> seen) throws IOException {
        if (!seen.add(t)) {
            line(out, prefix + "[circular reference to " + t + "]");
            return;
        }
        line(out, prefix + t);
        for (StackTraceElement frame : t.getStackTrace()) {
            line(out, "\tat " + frame);
        }
        for (Throwable suppressed : t.getSuppressed()) {
            writeTrace(out, suppressed, "Suppressed: ", seen);
        }
        Throwable cause = t.getCause();
        if (cause != null) {
            writeTrace(out, cause, "Caused by: ", seen);
        }
    }

    private static String mib(long bytes) {
        return bytes < 0 ? "undefined" : (bytes >> 20) + " MiB";
    }

    private static void line(Writer out, String text) throws IOException {
        out.write(text);
        out.write('\n');
    }

    private interface Body {
        void write(Writer out) throws IOException;
    }

    private static Path append(Path dir, Body body) throws IOException {
        Files.createDirectories(dir);
        Path file = dir.resolve("crash-" + START_STAMP + "-" + ProcessHandle.current().pid() + ".log");
        try (Writer out = Files.newBufferedWriter(file, StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                StandardOpenOption.APPEND)) {
            body.write(out);
        }
        return file;
    }
}

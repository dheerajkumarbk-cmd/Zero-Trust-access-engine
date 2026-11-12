package dev.dwarpal.api;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * {@link EngineAlarm} that appends one JSON line per event to a file:
 * {@code {"event":"engine-down","at":"...","failures":5}} or {@code {"event":"engine-back","at":"...","failures":0}}.
 * Fixed text and numbers only, never request data. The file is capped (1 MiB by default); past the cap
 * nothing is written and the lines are counted in {@link #dropped()}.
 */
public final class FileEngineAlarm implements EngineAlarm {

    /** Default cap on the file size. */
    public static final long DEFAULT_MAX_BYTES = 1024 * 1024;

    private final Path file;
    private final long maxBytes;
    private final AtomicLong dropped = new AtomicLong();

    public FileEngineAlarm(Path file) {
        this(file, DEFAULT_MAX_BYTES);
    }

    public FileEngineAlarm(Path file, long maxBytes) {
        this.file = Objects.requireNonNull(file, "file");
        if (maxBytes <= 0) {
            throw new IllegalArgumentException("maxBytes must be positive");
        }
        this.maxBytes = maxBytes;
    }

    @Override
    public void engineDown(long consecutiveFailures, Instant at) {
        append("engine-down", at, consecutiveFailures);
    }

    @Override
    public void engineBack(Instant at) {
        append("engine-back", at, 0);
    }

    /** Lines not written because the file was at its cap or could not be written. */
    public long dropped() {
        return dropped.get();
    }

    private synchronized void append(String event, Instant at, long failures) {
        byte[] line = ("{\"event\":\"" + event + "\",\"at\":\"" + at + "\",\"failures\":" + failures + "}\n")
                .getBytes(StandardCharsets.UTF_8);
        try {
            long size = Files.exists(file) ? Files.size(file) : 0;
            if (size + line.length > maxBytes) {
                dropped.incrementAndGet();
                return;
            }
            Files.write(file, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException | RuntimeException e) {
            dropped.incrementAndGet();
        }
    }
}

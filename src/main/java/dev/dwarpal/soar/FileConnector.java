package dev.dwarpal.soar;

import dev.dwarpal.domain.Validate;
import dev.dwarpal.guard.RateLimiter;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;

/**
 * A simulated connector: instead of calling a ticketing system, a chat service or a mail server, it appends one
 * JSON line per notification to {@code <directory>/<name>.jsonl}. It never opens a network connection.
 *
 * <p>Limits: notifications per minute (a flood of cases cannot flood the file) and the file's size (beyond it,
 * notifications are refused and counted). The file is opened without following symbolic links, in an existing
 * directory chosen by the deployment.
 */
public final class FileConnector implements Connector {

    public static final long MAX_FILE_BYTES = 10L * 1024 * 1024;

    private final String name;
    private final Kind kind;
    private final Path file;
    private final Clock clock;
    private final RateLimiter limit;
    private long refused;
    private long sent;

    public FileConnector(String name, Kind kind, Path directory, int perMinute, Clock clock) {
        this.name = Validate.id(name, "connector.name");
        if (name.contains("/") || name.contains(":") || name.contains("@")) {
            throw new IllegalArgumentException("a connector name is letters, digits, '.', '_' and '-'");
        }
        this.kind = Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(directory, "directory");
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("connector directory must exist and not be a symbolic link");
        }
        this.file = directory.resolve(name + ".jsonl");
        if (perMinute < 1 || perMinute > 10_000) {
            throw new IllegalArgumentException("perMinute is 1 to 10,000");
        }
        this.limit = new RateLimiter(perMinute, Duration.ofMinutes(1), 1);
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public Kind kind() {
        return kind;
    }

    @Override
    public synchronized boolean send(Notification n) {
        Objects.requireNonNull(n, "notification");
        if (!limit.tryAcquire("all", clock.instant())) {
            refused++;
            return false;
        }
        byte[] line = (JsonWriter.write(JsonValue.object()
                .put("connector", name)
                .put("kind", kind.name().toLowerCase(Locale.ROOT))
                .put("at", n.at().toString())
                .put("case", n.caseId())
                .put("alert", n.alertId())
                .put("rule", n.rule())
                .put("priority", n.priority().name())
                .put("template", n.template().key())
                .put("title", n.title())
                .build()) + "\n").getBytes(StandardCharsets.UTF_8);
        try {
            if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)
                    && Files.size(file) + line.length > MAX_FILE_BYTES) {
                refused++;
                return false;
            }
            try (OutputStream out = Files.newOutputStream(file, StandardOpenOption.CREATE, StandardOpenOption.APPEND,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                out.write(line);
            }
            sent++;
            return true;
        } catch (IOException e) {
            refused++;
            return false;
        }
    }

    public synchronized long sent() {
        return sent;
    }

    public synchronized long refused() {
        return refused;
    }
}

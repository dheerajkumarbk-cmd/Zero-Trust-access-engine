package dev.dwarpal.lab;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Everything that decides what a lab looks like, in one place. A lab is a directory: certificates and their
 * secrets live under it and are never written anywhere else.
 *
 * @param dir          the lab directory (created if missing)
 * @param seed         the simulated organisation's seed (same seed, same organisation and same attacks)
 * @param users        people in the simulated organisation (6 to 10,000)
 * @param speed        simulated seconds that pass per wall-clock second (60 = a simulated minute each second)
 * @param warmupDays   simulated days run at once at start-up, so baselines exist before the first live minute
 * @param port         port of the SOC API (0 picks a free one)
 */
public record LabConfig(Path dir, long seed, int users, double speed, int warmupDays, int port) {

    public static final double MAX_SPEED = 100_000;

    public LabConfig {
        Objects.requireNonNull(dir, "dir");
        if (users < 6 || users > 10_000) {
            throw new IllegalArgumentException("between 6 and 10,000 users");
        }
        if (!(speed > 0 && speed <= MAX_SPEED)) {
            throw new IllegalArgumentException("speed must be above 0 and at most " + MAX_SPEED);
        }
        if (warmupDays < 0 || warmupDays > 30) {
            throw new IllegalArgumentException("warm-up is 0 to 30 days");
        }
        if (port < 0 || port > 65_535) {
            throw new IllegalArgumentException("port");
        }
    }

    /** The default lab: seed 7, 60 users, a simulated minute per second, three days of warm-up. */
    public static LabConfig defaults(Path dir) {
        return new LabConfig(dir, 7, 60, 60, 3, 8443);
    }

    public LabConfig withPort(int v) {
        return new LabConfig(dir, seed, users, speed, warmupDays, v);
    }

    public LabConfig withSpeed(double v) {
        return new LabConfig(dir, seed, users, v, warmupDays, port);
    }

    public LabConfig withWarmupDays(int v) {
        return new LabConfig(dir, seed, users, speed, v, port);
    }

    public LabConfig withUsers(int v) {
        return new LabConfig(dir, seed, v, speed, warmupDays, port);
    }
}

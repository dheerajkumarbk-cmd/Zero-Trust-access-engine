package dev.dwarpal.console;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/**
 * Every limit of the console server in one place (standards section 3: session lifetimes, step-up freshness, rates,
 * sizes, concurrency, streams). Each value bounds something an attacker, a stolen session or a broken page could
 * otherwise make unbounded.
 *
 * @param idle               a session with no activity for this long is dead (15 minutes)
 * @param absolute           a session is dead this long after login whatever it does (8 hours)
 * @param stepUpFreshness    how old the last second-factor proof may be for a privileged write (5 minutes)
 * @param maxSessionsPerPerson concurrent sessions of one person; the oldest is ended when a new one starts
 * @param maxSessions        sessions of all people
 * @param maxBodyBytes       request body, at most {@link #MAX_BODY_BYTES}
 * @param threads            worker threads for ordinary requests
 * @param queue              connections waiting for a worker
 * @param maxConcurrent      requests handled at once; beyond it 503
 * @param requestDeadline    handshake, headers, body and work together (not for the event stream)
 * @param maxStreams         open event streams in total (also one per session)
 * @param readsPerMinute     authenticated calls per person per minute
 * @param writesPerMinute    authenticated writes per person per minute
 * @param anonymousPerMinute calls without a session per client address per minute
 * @param passwordIterations PBKDF2 iterations for the demo passwords ({@code UserFile.MIN_ITERATIONS} or more)
 * @param pinIterations      PBKDF2 iterations for the security-key PIN
 * @param extraHosts         further {@code Host} values (name:port) the server answers to; empty on the loopback
 */
public record ConsoleSettings(Duration idle, Duration absolute, Duration stepUpFreshness, int maxSessionsPerPerson,
                              int maxSessions, int maxBodyBytes, int threads, int queue, int maxConcurrent,
                              Duration requestDeadline, int maxStreams, int readsPerMinute, int writesPerMinute,
                              int anonymousPerMinute, int passwordIterations, int pinIterations, Set<String> extraHosts) {

    public static final int MAX_BODY_BYTES = 64 * 1024;

    public ConsoleSettings {
        Objects.requireNonNull(idle, "idle");
        Objects.requireNonNull(absolute, "absolute");
        Objects.requireNonNull(stepUpFreshness, "stepUpFreshness");
        Objects.requireNonNull(requestDeadline, "requestDeadline");
        extraHosts = Set.copyOf(extraHosts);
        if (idle.isNegative() || idle.isZero() || absolute.compareTo(idle) < 0 || absolute.compareTo(Duration.ofHours(24)) > 0
                || stepUpFreshness.isNegative() || stepUpFreshness.isZero() || stepUpFreshness.compareTo(Duration.ofMinutes(15)) > 0
                || requestDeadline.isNegative() || requestDeadline.isZero() || requestDeadline.compareTo(Duration.ofMinutes(1)) > 0) {
            throw new IllegalArgumentException("console durations out of range");
        }
        if (maxSessionsPerPerson < 1 || maxSessionsPerPerson > 20 || maxSessions < maxSessionsPerPerson || maxSessions > 10_000
                || maxBodyBytes < 64 || maxBodyBytes > MAX_BODY_BYTES || threads < 1 || threads > 64 || queue < 1 || queue > 1_000
                || maxConcurrent < 1 || maxConcurrent > 256 || maxStreams < 1 || maxStreams > 1_000 || readsPerMinute < 1
                || writesPerMinute < 1 || anonymousPerMinute < 1 || passwordIterations < 10_000 || pinIterations < 1_000) {
            throw new IllegalArgumentException("console settings out of range");
        }
    }

    /** 15 minutes idle, 8 hours absolute, step-up 5 minutes, 3 sessions each, 64 KiB bodies, 8 threads, 64 streams. */
    public static ConsoleSettings defaults() {
        return new ConsoleSettings(Duration.ofMinutes(15), Duration.ofHours(8), Duration.ofMinutes(5), 3, 200, 16 * 1024,
                8, 64, 32, Duration.ofSeconds(5), 64, 1_800, 60, 120, 600_000, 100_000, Set.of());
    }

    /** Cheaper password hashing for tests; everything else as in production. */
    public ConsoleSettings fastHashing() {
        return new ConsoleSettings(idle, absolute, stepUpFreshness, maxSessionsPerPerson, maxSessions, maxBodyBytes, threads,
                queue, maxConcurrent, requestDeadline, maxStreams, readsPerMinute, writesPerMinute, anonymousPerMinute,
                10_000, 1_000, extraHosts);
    }

    public ConsoleSettings withLifetimes(Duration newIdle, Duration newAbsolute, Duration newStepUp) {
        return new ConsoleSettings(newIdle, newAbsolute, newStepUp, maxSessionsPerPerson, maxSessions, maxBodyBytes, threads,
                queue, maxConcurrent, requestDeadline, maxStreams, readsPerMinute, writesPerMinute, anonymousPerMinute,
                passwordIterations, pinIterations, extraHosts);
    }

    public ConsoleSettings withRates(int reads, int writes, int anonymous) {
        return new ConsoleSettings(idle, absolute, stepUpFreshness, maxSessionsPerPerson, maxSessions, maxBodyBytes, threads,
                queue, maxConcurrent, requestDeadline, maxStreams, reads, writes, anonymous, passwordIterations,
                pinIterations, extraHosts);
    }

    public ConsoleSettings withSessionLimits(int perPerson, int total, int streams) {
        return new ConsoleSettings(idle, absolute, stepUpFreshness, perPerson, total, maxBodyBytes, threads, queue,
                maxConcurrent, requestDeadline, streams, readsPerMinute, writesPerMinute, anonymousPerMinute,
                passwordIterations, pinIterations, extraHosts);
    }
}

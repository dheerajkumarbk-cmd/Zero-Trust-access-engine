package dev.dwarpal.api;

import java.time.Duration;
import java.util.Objects;

/**
 * Abuse limits of the engine API. Every value bounds something an attacker could otherwise make
 * unbounded: threads, queued connections, concurrent work, body size, time per request, calls per caller.
 *
 * @param threads             worker threads (bounded pool)
 * @param queue               connections waiting for a worker; beyond this a new connection is closed
 * @param maxConcurrent       requests being handled at once; beyond this the answer is 503
 * @param maxBodyBytes        request body, at most {@link dev.dwarpal.wire.JsonLimits#maxBytes()}
 * @param requestDeadline     a request (headers, body, handling) taking longer is cut off
 * @param callerLimit         calls per caller per {@code callerWindow}
 * @param callerWindow        window of the per-caller limit
 * @param refusalAuditsPerMinute refusal records per caller and status per minute (the rest are counted)
 */
public record ApiSettings(int threads, int queue, int maxConcurrent, int maxBodyBytes, Duration requestDeadline,
                          int callerLimit, Duration callerWindow, int refusalAuditsPerMinute) {

    public static final int MAX_BODY_BYTES = 64 * 1024;

    public ApiSettings {
        Objects.requireNonNull(requestDeadline, "requestDeadline");
        Objects.requireNonNull(callerWindow, "callerWindow");
        if (threads < 1 || threads > 256 || queue < 1 || queue > 10_000 || maxConcurrent < 1
                || maxBodyBytes < 1 || maxBodyBytes > MAX_BODY_BYTES || callerLimit < 1 || refusalAuditsPerMinute < 1) {
            throw new IllegalArgumentException("API settings out of range");
        }
        if (requestDeadline.isNegative() || requestDeadline.isZero() || requestDeadline.compareTo(Duration.ofMinutes(1)) > 0
                || callerWindow.isNegative() || callerWindow.isZero()) {
            throw new IllegalArgumentException("API durations out of range");
        }
    }

    /** 16 threads, 64 queued, 16 at once, 64 KiB bodies, 5 s per request, 2,000 calls per caller per second. */
    public static ApiSettings defaults() {
        return new ApiSettings(16, 64, 16, MAX_BODY_BYTES, Duration.ofSeconds(5), 2000, Duration.ofSeconds(1), 20);
    }

    public ApiSettings withCallerLimit(int limit, Duration window) {
        return new ApiSettings(threads, queue, maxConcurrent, maxBodyBytes, requestDeadline, limit, window,
                refusalAuditsPerMinute);
    }

    public ApiSettings withRequestDeadline(Duration d) {
        return new ApiSettings(threads, queue, maxConcurrent, maxBodyBytes, d, callerLimit, callerWindow,
                refusalAuditsPerMinute);
    }

    public ApiSettings withThreads(int workers, int concurrent) {
        return new ApiSettings(workers, queue, concurrent, maxBodyBytes, requestDeadline, callerLimit, callerWindow,
                refusalAuditsPerMinute);
    }
}

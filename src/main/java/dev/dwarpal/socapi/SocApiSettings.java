package dev.dwarpal.socapi;

import java.time.Duration;
import java.util.Objects;

/**
 * Abuse limits of the SOC API. Every value bounds something a caller (or a stolen analyst certificate) could
 * otherwise make unbounded.
 *
 * @param threads                worker threads
 * @param queue                  connections waiting for a worker
 * @param maxConcurrent          requests handled at once; beyond it 503
 * @param maxBodyBytes           request body, at most {@link #MAX_BODY_BYTES}
 * @param requestDeadline        handshake, headers, body and work together, at most 1 minute
 * @param readsPerMinute         read calls per analyst per minute
 * @param writesPerMinute        notes, assignments and verdicts per analyst per minute
 * @param searchesPerMinute      searches per analyst per minute (the most expensive read)
 * @param refusalAuditsPerMinute refusal records per caller and status per minute (the rest are counted)
 * @param maxSearchWindow        the longest time range one search may cover
 */
public record SocApiSettings(int threads, int queue, int maxConcurrent, int maxBodyBytes, Duration requestDeadline,
                             int readsPerMinute, int writesPerMinute, int searchesPerMinute, int refusalAuditsPerMinute,
                             Duration maxSearchWindow) {

    public static final int MAX_BODY_BYTES = 16 * 1024;

    public SocApiSettings {
        Objects.requireNonNull(requestDeadline, "requestDeadline");
        Objects.requireNonNull(maxSearchWindow, "maxSearchWindow");
        if (threads < 1 || threads > 64 || queue < 1 || queue > 1_000 || maxConcurrent < 1 || maxConcurrent > 256
                || maxBodyBytes < 64 || maxBodyBytes > MAX_BODY_BYTES || readsPerMinute < 1 || writesPerMinute < 1
                || searchesPerMinute < 1 || refusalAuditsPerMinute < 1) {
            throw new IllegalArgumentException("SOC API settings out of range");
        }
        if (requestDeadline.isNegative() || requestDeadline.isZero() || requestDeadline.compareTo(Duration.ofMinutes(1)) > 0
                || maxSearchWindow.isNegative() || maxSearchWindow.isZero()
                || maxSearchWindow.compareTo(Duration.ofDays(90)) > 0) {
            throw new IllegalArgumentException("SOC API durations out of range");
        }
    }

    /**
     * 8 threads, 32 queued, 16 at once, 16 KiB bodies, 5 s per request, 600 reads, 30 writes and 20 searches per
     * analyst per minute, searches over at most 31 days.
     */
    public static SocApiSettings defaults() {
        return new SocApiSettings(8, 32, 16, MAX_BODY_BYTES, Duration.ofSeconds(5), 600, 30, 20, 20, Duration.ofDays(31));
    }

    public SocApiSettings withRates(int reads, int writes, int searches) {
        return new SocApiSettings(threads, queue, maxConcurrent, maxBodyBytes, requestDeadline, reads, writes, searches,
                refusalAuditsPerMinute, maxSearchWindow);
    }

    public SocApiSettings withRequestDeadline(Duration d) {
        return new SocApiSettings(threads, queue, maxConcurrent, maxBodyBytes, d, readsPerMinute, writesPerMinute,
                searchesPerMinute, refusalAuditsPerMinute, maxSearchWindow);
    }
}

package dev.dwarpal.analytics;

import dev.dwarpal.decision.Decision;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.risk.SignalSnapshot;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A {@link DecisionPoint} decorator that keeps the last N requests and their decisions in memory, for
 * What-If replay. It never changes a decision: whatever the delegate answered is returned, and a failure
 * to record only counts as a drop.
 *
 * <ul>
 *   <li><b>Bounded.</b> At most {@code capacity} records (a ring: the oldest goes first), and at most
 *       {@code maxPerSubject} records per subject at a time, so one noisy or hostile account cannot evict
 *       everyone else's traffic and make a What-If speak only about the attacker's requests.</li>
 *   <li><b>Data-minimised.</b> Signed evidence is dropped ({@link RecordedRequest}); the signal snapshot
 *       is not kept at all, since it holds the honeytoken list, and a recorder dump must not reveal the
 *       traps. Nothing is written to disk or logs.</li>
 *   <li><b>Honest about its window.</b> {@link #stats()} says how many were recorded, evicted, refused and
 *       dropped, and the time span kept, so a report can state what it covers.</li>
 * </ul>
 */
public final class RequestRecorder implements DecisionPoint {

    public static final int MAX_CAPACITY = 100_000;

    /** What the recorder holds and what it had to leave out. */
    public record Stats(int kept, long recorded, long evicted, long refusedQuota, long dropped,
                        Optional<Instant> oldest, Optional<Instant> newest) {
    }

    private final DecisionPoint delegate;
    private final int capacity;
    private final int maxPerSubject;
    private final ArrayDeque<RecordedRequest> ring;
    private final Map<String, Integer> perSubject = new HashMap<>();
    private long recorded;
    private long evicted;
    private long refusedQuota;
    private long dropped;

    public RequestRecorder(DecisionPoint delegate, int capacity, int maxPerSubject) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        if (capacity < 1 || capacity > MAX_CAPACITY) {
            throw new IllegalArgumentException("capacity must be between 1 and " + MAX_CAPACITY);
        }
        if (maxPerSubject < 1 || maxPerSubject > capacity) {
            throw new IllegalArgumentException("maxPerSubject must be between 1 and the capacity");
        }
        this.capacity = capacity;
        this.maxPerSubject = maxPerSubject;
        this.ring = new ArrayDeque<>(Math.min(capacity, 1024));
    }

    @Override
    public Decision decide(AccessRequest request, SignalSnapshot signals) {
        Decision d = delegate.decide(request, signals);
        try {
            record(RecordedRequest.of(request, d));
        } catch (RuntimeException e) {
            // Recording is for analysis only: it must never change or block the decision.
            synchronized (this) {
                dropped++;
            }
        }
        return d;
    }

    private synchronized void record(RecordedRequest r) {
        String subject = r.request().subject().id();
        int held = perSubject.getOrDefault(subject, 0);
        if (held >= maxPerSubject) {
            refusedQuota++;
            return;
        }
        if (ring.size() == capacity) {
            RecordedRequest old = ring.removeFirst();
            perSubject.computeIfPresent(old.request().subject().id(), (k, v) -> v == 1 ? null : v - 1);
            evicted++;
        }
        ring.addLast(r);
        perSubject.merge(subject, 1, Integer::sum);
        recorded++;
    }

    /** A copy of what is held, oldest first. */
    public synchronized List<RecordedRequest> snapshot() {
        return List.copyOf(ring);
    }

    public synchronized Stats stats() {
        Optional<Instant> oldest = ring.stream().map(r -> r.request().timestamp()).min(Instant::compareTo);
        Optional<Instant> newest = ring.stream().map(r -> r.request().timestamp()).max(Instant::compareTo);
        return new Stats(ring.size(), recorded, evicted, refusedQuota, dropped, oldest, newest);
    }

    /** Forgets everything (for example after a What-If, or to honour an erasure request). */
    public synchronized void clear() {
        ring.clear();
        perSubject.clear();
    }

    /** Forgets one subject's records (data-subject erasure). */
    public synchronized int forget(String subjectId) {
        Objects.requireNonNull(subjectId, "subjectId");
        int before = ring.size();
        ring.removeIf(r -> r.request().subject().id().equals(subjectId));
        perSubject.remove(subjectId);
        return before - ring.size();
    }
}

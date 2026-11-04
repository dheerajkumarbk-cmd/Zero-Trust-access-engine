package dev.dwarpal.pip;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.risk.SignalSnapshot;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The engine-side signals the SOC controls (a Policy Information Point). Two kinds of entry:
 * <ul>
 *   <li><b>Deny</b> a subject, device or address until a time. Always temporary: at most
 *       {@link #MAX_DENY}, so a mistaken or malicious deny ends on its own.</li>
 *   <li><b>Watch</b> one with a risk weight, a log-likelihood ratio that halves every half-life
 *       (model M5): {@code w(t) = w0 * 2^(-(t - t0) / halfLife)}. A new watch on the same entity adds to
 *       what is left of the old one, capped at {@link #MAX_WATCH_LOG_LR}. Watches only ever add risk:
 *       reassurance must be earned by the engine's own evidence, never declared.</li>
 * </ul>
 * The engine reads {@link #snapshot(Instant)} (deny lists and honeytokens) on every decision; a scorer
 * reads {@link #watchLogLr}. Every change is written to the audit trail first: no audit, no change.
 * The store is bounded; when it is full, new entries are refused and counted, never silently dropped.
 *
 * <p>Changes are timed by the feed's own clock and take durations, never a caller's idea of "now"
 * (Layer 5 part 0 finding: a caller claiming it was five years in the future set a five-year deny).
 * Reading never changes the store, whatever time a reader asks about.
 */
public final class SignalFeed {

    public enum Kind { SUBJECT, DEVICE, IP }

    public static final Duration MAX_DENY = Duration.ofDays(30);
    public static final Duration MIN_HALF_LIFE = Duration.ofMinutes(1);
    public static final Duration MAX_HALF_LIFE = Duration.ofDays(90);
    /** The same cap as one attack factor in the aggregator: at most x1000. */
    public static final double MAX_WATCH_LOG_LR = Math.log(1000);
    /** Below this weight (x1.01) a watch has faded away and is dropped. */
    public static final double FADED_LOG_LR = 0.01;
    public static final int MAX_ENTRIES = 100_000;
    public static final int MAX_REASON = 256;

    private record Key(Kind kind, String id) {
    }

    /** A snapshot and the interval it is right for, read and replaced together. */
    private record Cached(SignalSnapshot snapshot, Instant builtFor, Instant validUntil) {
        boolean covers(Instant t) {
            return !t.isBefore(builtFor) && t.isBefore(validUntil);
        }
    }

    private record Watch(double logLr, Instant since, Duration halfLife) {
        double at(Instant now) {
            double age = Math.max(0, Duration.between(since, now).toMillis());
            return logLr * Math.pow(2, -age / halfLife.toMillis());
        }
    }

    private final Set<String> honeytokens;
    private final AuditLog audit;
    private final Clock clock;
    private final Map<Key, Instant> denies = new HashMap<>();
    private final Map<Key, Watch> watches = new HashMap<>();
    private final AtomicLong refused = new AtomicLong();
    private volatile Cached cached;

    /**
     * @param honeytokens identities, devices and credentials that must never be used; fixed for the
     *                    feed's life (they come from deployment, not from the SOC)
     */
    public SignalFeed(Set<String> honeytokens, AuditLog audit, Clock clock) {
        this.honeytokens = Set.copyOf(honeytokens);
        this.honeytokens.forEach(h -> Validate.id(h, "honeytoken"));
        this.audit = Objects.requireNonNull(audit, "audit");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Denies {@code id} for {@code duration} from now (the feed's clock). A deny already in force is
     * extended only if the new one ends later (never shortened here: use {@link #clear}).
     *
     * @return false if refused (store full, or the audit trail is unavailable)
     */
    public synchronized boolean deny(Kind kind, String id, Duration duration, String actor, String reason) {
        Key k = key(kind, id);
        Objects.requireNonNull(duration, "duration");
        if (duration.isNegative() || duration.isZero() || duration.compareTo(MAX_DENY) > 0) {
            throw new IllegalArgumentException("a deny lasts more than zero and at most " + MAX_DENY.toDays() + " days");
        }
        Instant now = clock.instant();
        Instant until = now.plus(duration);
        if (!denies.containsKey(k) && !roomFor()) {
            return false;
        }
        Map<String, String> f = fields(k, actor, reason);
        f.put("until", until.toString());
        if (!audited("SIGNAL_DENY", actor, now, f)) {
            return false;
        }
        denies.merge(k, until, (a, b) -> a.isAfter(b) ? a : b);
        invalidate();
        return true;
    }

    /**
     * Adds a watch weight to {@code id}: what is left of an earlier watch plus {@code logLr}, capped, with
     * the new half-life.
     *
     * @return false if refused (store full, or the audit trail is unavailable)
     */
    public synchronized boolean watch(Kind kind, String id, double logLr, Duration halfLife, String actor,
                                      String reason) {
        Key k = key(kind, id);
        Objects.requireNonNull(halfLife, "halfLife");
        Instant now = clock.instant();
        if (!Double.isFinite(logLr) || logLr <= 0 || logLr > MAX_WATCH_LOG_LR) {
            throw new IllegalArgumentException("a watch adds risk: 0 < logLr <= ln(1000)");
        }
        if (halfLife.compareTo(MIN_HALF_LIFE) < 0 || halfLife.compareTo(MAX_HALF_LIFE) > 0) {
            throw new IllegalArgumentException("half-life must be between 1 minute and 90 days");
        }
        if (!watches.containsKey(k) && !roomFor()) {
            return false;
        }
        Watch old = watches.get(k);
        double total = Math.min(MAX_WATCH_LOG_LR, (old == null ? 0 : old.at(now)) + logLr);
        Map<String, String> f = fields(k, actor, reason);
        f.put("logLr", Double.toString(logLr));
        f.put("total", Double.toString(total));
        f.put("halfLife", halfLife.toString());
        if (!audited("SIGNAL_WATCH", actor, now, f)) {
            return false;
        }
        watches.put(k, new Watch(total, now, halfLife));
        return true;
    }

    /**
     * Ends any deny and watch on {@code id} (for example after a false-positive verdict).
     *
     * @return false if there was nothing to clear or the audit trail is unavailable
     */
    public synchronized boolean clear(Kind kind, String id, String actor, String reason) {
        Key k = key(kind, id);
        Instant now = clock.instant();
        if (!denies.containsKey(k) && !watches.containsKey(k)) {
            return false;
        }
        if (!audited("SIGNAL_CLEAR", actor, now, fields(k, actor, reason))) {
            return false;
        }
        denies.remove(k);
        watches.remove(k);
        invalidate();
        return true;
    }

    /**
     * What the engine reads on every decision: honeytokens and the denies in force at {@code now}.
     * Cached until the next change or the next expiry, so a decision costs no copying.
     */
    public SignalSnapshot snapshot(Instant now) {
        Cached c = cached;
        if (c != null && c.covers(now)) {
            return c.snapshot();
        }
        return rebuild(now);
    }

    private synchronized SignalSnapshot rebuild(Instant now) {
        Set<String> subjects = new HashSet<>();
        Set<String> devices = new HashSet<>();
        Set<String> ips = new HashSet<>();
        Instant nextExpiry = Instant.MAX;
        for (Map.Entry<Key, Instant> e : denies.entrySet()) {
            if (!e.getValue().isAfter(now)) {
                continue;
            }
            nextExpiry = e.getValue().isBefore(nextExpiry) ? e.getValue() : nextExpiry;
            (switch (e.getKey().kind()) {
                case SUBJECT -> subjects;
                case DEVICE -> devices;
                case IP -> ips;
            }).add(e.getKey().id());
        }
        SignalSnapshot s = new SignalSnapshot(honeytokens, subjects, devices, ips);
        cached = new Cached(s, now, nextExpiry);
        return s;
    }

    /** The decayed watch weight (a log-likelihood ratio, 0 when not watched) of {@code id} at {@code now}. */
    public synchronized double watchLogLr(Kind kind, String id, Instant now) {
        Watch w = watches.get(new Key(Objects.requireNonNull(kind, "kind"), Objects.requireNonNull(id, "id")));
        if (w == null) {
            return 0;
        }
        double v = w.at(now);
        return v < FADED_LOG_LR ? 0 : v;
    }

    /** Whether {@code id} is denied at {@code now}. */
    public synchronized boolean denied(Kind kind, String id, Instant now) {
        Instant until = denies.get(new Key(kind, id));
        return until != null && until.isAfter(now);
    }

    /** Entries held (denies and watches, including ones not yet purged). */
    public synchronized int size() {
        return denies.size() + watches.size();
    }

    /** New entries refused because the store was full. */
    public long refused() {
        return refused.get();
    }

    /** Drops denies that have ended and watches that have faded, by the feed's clock; returns how many. */
    public synchronized int purge() {
        Instant now = clock.instant();
        int before = size();
        denies.values().removeIf(until -> !until.isAfter(now));
        watches.values().removeIf(w -> w.at(now) < FADED_LOG_LR);
        invalidate();
        return before - size();
    }

    private boolean roomFor() {
        if (size() < MAX_ENTRIES) {
            return true;
        }
        purge();
        if (size() < MAX_ENTRIES) {
            return true;
        }
        refused.incrementAndGet();
        return false;
    }

    private boolean audited(String type, String actor, Instant now, Map<String, String> fields) {
        try {
            audit.append(type, Validate.id(actor, "actor"), now, fields);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static Key key(Kind kind, String id) {
        return new Key(Objects.requireNonNull(kind, "kind"), Validate.id(id, "id"));
    }

    private static Map<String, String> fields(Key k, String actor, String reason) {
        Validate.id(actor, "actor");
        Map<String, String> f = new LinkedHashMap<>();
        f.put("kind", k.kind().name());
        f.put("id", k.id());
        f.put("reason", Sanitize.text(Objects.requireNonNull(reason, "reason"), MAX_REASON));
        return f;
    }

    private void invalidate() {
        cached = null;
    }
}

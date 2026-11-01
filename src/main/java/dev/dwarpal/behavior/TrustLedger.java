package dev.dwarpal.behavior;

import dev.dwarpal.domain.Validate;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Beta reputation per entity (Jøsang &amp; Ismail, 2002), with exponential forgetting (model M4/M5).
 *
 * <p>An entity ("subject:alice", "device:laptop-1") accumulates good and bad events. Each event's
 * weight halves every {@code halfLife}, so old behaviour fades: a device that was clean a year ago
 * and silent since is not "trusted" today, and an old incident does not haunt a user forever.
 * <pre>
 *   r = sum of decayed good weights,  s = sum of decayed bad weights
 *   E = (r + 1) / (r + s + 2)          expected trustworthiness
 *   u = 2 / (r + s + 2)                 uncertainty (1 = know nothing)
 * </pre>
 * Separating E from u is the point: "no history" (E=0.5, u=1) is not the same as "mixed history"
 * (E=0.5, u small). Bounded like the other stores.
 */
public final class TrustLedger implements TrustView {

    public static final int MAX_ENTITIES = 200_000;
    public static final int MAX_EVENTS_PER_ENTITY = 1_000;

    private record Event(Instant at, boolean good) {
    }

    /** Decayed evidence for one entity. */
    public record Trust(double good, double bad) {
        public double expectation() {
            return (good + 1) / (good + bad + 2);
        }

        public double uncertainty() {
            return 2 / (good + bad + 2);
        }

        public boolean hasEvidence() {
            return good + bad > 0;
        }
    }

    private final Duration halfLife;
    private final Map<String, ArrayDeque<Event>> events = new LinkedHashMap<>(16, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, ArrayDeque<Event>> eldest) {
            return size() > MAX_ENTITIES;
        }
    };

    public TrustLedger(Duration halfLife) {
        this.halfLife = Objects.requireNonNull(halfLife, "halfLife");
        if (halfLife.isNegative() || halfLife.isZero()) {
            throw new IllegalArgumentException("halfLife must be positive");
        }
    }

    public synchronized void recordGood(String entity, Instant at) {
        add(entity, new Event(at, true));
    }

    public synchronized void recordBad(String entity, Instant at) {
        add(entity, new Event(at, false));
    }

    private void add(String entity, Event e) {
        Validate.id(entity, "entity");
        Objects.requireNonNull(e.at(), "at");
        ArrayDeque<Event> q = events.computeIfAbsent(entity, k -> new ArrayDeque<>());
        q.addLast(e);
        if (q.size() > MAX_EVENTS_PER_ENTITY) {
            q.removeFirst();
        }
    }

    /** Trust as of {@code now}. Events dated after {@code now} are ignored (no credit from the future). */
    @Override
    public synchronized Trust trust(String entity, Instant now) {
        ArrayDeque<Event> q = events.get(entity);
        if (q == null) {
            return new Trust(0, 0);
        }
        double good = 0;
        double bad = 0;
        double halfLifeMillis = halfLife.toMillis();
        for (Event e : q) {
            long ageMillis = Duration.between(e.at(), now).toMillis();
            if (ageMillis < 0) {
                continue;
            }
            double w = Math.pow(0.5, ageMillis / halfLifeMillis);
            if (e.good()) {
                good += w;
            } else {
                bad += w;
            }
        }
        return new Trust(good, bad);
    }

    public static String subjectKey(String subjectId) {
        return "subject:" + subjectId;
    }

    public static String deviceKey(String deviceId) {
        return "device:" + deviceId;
    }
}

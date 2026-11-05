package dev.dwarpal.response;

import dev.dwarpal.pip.SignalFeed;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Who put what on the {@link SignalFeed}, so one holder's entries can be lifted without lifting
 * anyone else's. The feed keeps one deny and one watch per entity and {@link SignalFeed#clear} ends
 * both; a false positive on case 7 must not end the deny case 9 put on the same person, nor the DLP
 * watch on them. So every deny and watch the SOC loop makes goes through here, tagged with its holder
 * (a case id, or {@link #DLP}); lifting a holder clears the entity and puts back what the other
 * holders still have in force (their denies with the time left, their watches with the weight left).
 *
 * <p>Putting back is conservative: the remaining watches are re-added as one weight with the longest
 * of their half-lives, so the entity never ends up with less risk than the other holders gave it. If
 * putting back fails (the audit trail is down), the entity is remembered as unsettled and
 * {@link #reconcile()} retries; until then it has <em>less</em> than it should, which is reported.
 *
 * <p>Must be given the feed's own clock. Bounded: {@link #MAX_ENTITIES} entities and
 * {@link #MAX_HOLDERS_PER_ENTITY} holders on each; beyond that, new entries are refused.
 */
public final class SignalLedger {

    public static final String DLP = "dlp";
    public static final int MAX_ENTITIES = 100_000;
    public static final int MAX_HOLDERS_PER_ENTITY = 64;

    record Target(SignalFeed.Kind kind, String id) {
        Target {
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(id, "id");
        }
    }

    /** One holder's share on one entity. */
    private record Share(Instant denyUntil, double logLr, Instant since, Duration halfLife) {
        double weightAt(Instant now) {
            if (halfLife == null) {
                return 0;
            }
            double age = Math.max(0, Duration.between(since, now).toMillis());
            return logLr * Math.pow(2, -age / halfLife.toMillis());
        }

        boolean liveAt(Instant now) {
            return (denyUntil != null && denyUntil.isAfter(now)) || weightAt(now) >= SignalFeed.FADED_LOG_LR;
        }
    }

    private final SignalFeed feed;
    private final Clock clock;
    private final Map<Target, LinkedHashMap<String, Share>> shares = new HashMap<>();
    private final Set<Target> unsettled = new HashSet<>();

    public SignalLedger(SignalFeed feed, Clock feedClock) {
        this.feed = Objects.requireNonNull(feed, "feed");
        this.clock = Objects.requireNonNull(feedClock, "feedClock");
    }

    /** Denies for {@code holder}; false if refused (feed or ledger full, audit down). */
    public synchronized boolean deny(String holder, SignalFeed.Kind kind, String id, Duration duration, String actor,
                                     String reason) {
        Target t = new Target(kind, id);
        if (!roomFor(t, holder)) {
            return false;
        }
        if (!feed.deny(kind, id, duration, actor, reason)) {
            return false;
        }
        Instant until = clock.instant().plus(duration);
        Share old = shareOf(t, holder);
        Instant keep = old != null && old.denyUntil() != null && old.denyUntil().isAfter(until) ? old.denyUntil() : until;
        put(t, holder, new Share(keep, old == null ? 0 : old.logLr(), old == null ? null : old.since(),
                old == null ? null : old.halfLife()));
        return true;
    }

    /** Adds watch weight for {@code holder}; false if refused. */
    public synchronized boolean watch(String holder, SignalFeed.Kind kind, String id, double logLr, Duration halfLife,
                                      String actor, String reason) {
        Target t = new Target(kind, id);
        if (!roomFor(t, holder)) {
            return false;
        }
        if (!feed.watch(kind, id, logLr, halfLife, actor, reason)) {
            return false;
        }
        Instant now = clock.instant();
        Share old = shareOf(t, holder);
        double left = old == null ? 0 : old.weightAt(now);
        put(t, holder, new Share(old == null ? null : old.denyUntil(),
                Math.min(SignalFeed.MAX_WATCH_LOG_LR, left + logLr), now, halfLife));
        return true;
    }

    /** The decayed watch weight {@code holder} has put on an entity (0 if none). */
    public synchronized double weightOf(String holder, SignalFeed.Kind kind, String id) {
        Share s = shareOf(new Target(kind, id), holder);
        return s == null ? 0 : s.weightAt(clock.instant());
    }

    /**
     * Lifts everything {@code holder} put on the entity and puts back the other holders' shares.
     *
     * @return false if the feed refused (nothing changed, or it is now unsettled; see {@link #unsettled()})
     */
    public synchronized boolean lift(String holder, SignalFeed.Kind kind, String id, String actor, String reason) {
        Target t = new Target(kind, id);
        LinkedHashMap<String, Share> on = shares.get(t);
        if (on == null || !on.containsKey(holder)) {
            return true;
        }
        if (!feed.clear(kind, id, actor, reason)) {
            return false;
        }
        on.remove(holder);
        return restore(t, actor, reason);
    }

    /** Entities whose other holders' shares could not be put back yet. */
    public synchronized int unsettled() {
        return unsettled.size();
    }

    /** Retries putting back shares on unsettled entities; returns how many are still unsettled. */
    public synchronized int reconcile(String actor) {
        for (Target t : new ArrayList<>(unsettled)) {
            // Whatever is left on the feed is replaced; if the clear fails too, re-adding only adds risk.
            feed.clear(t.kind(), t.id(), actor, "reconcile");
            restore(t, actor, "reconcile");
        }
        return unsettled.size();
    }

    /** Drops shares that have ended or faded; returns how many entities were dropped. */
    public synchronized int purge() {
        Instant now = clock.instant();
        int before = shares.size();
        shares.values().forEach(m -> m.values().removeIf(s -> !s.liveAt(now)));
        shares.entrySet().removeIf(e -> e.getValue().isEmpty() && !unsettled.contains(e.getKey()));
        return before - shares.size();
    }

    public synchronized int size() {
        return shares.size();
    }

    private boolean restore(Target t, String actor, String reason) {
        Instant now = clock.instant();
        LinkedHashMap<String, Share> on = shares.getOrDefault(t, new LinkedHashMap<>());
        on.values().removeIf(s -> !s.liveAt(now));
        Instant until = null;
        double weight = 0;
        Duration halfLife = null;
        for (Share s : on.values()) {
            if (s.denyUntil() != null && s.denyUntil().isAfter(now) && (until == null || s.denyUntil().isAfter(until))) {
                until = s.denyUntil();
            }
            double w = s.weightAt(now);
            if (w >= SignalFeed.FADED_LOG_LR) {
                weight += w;
                halfLife = halfLife == null || s.halfLife().compareTo(halfLife) > 0 ? s.halfLife() : halfLife;
            }
        }
        boolean ok = true;
        String why = "restored after " + reason;
        if (until != null) {
            ok = feed.deny(t.kind(), t.id(), Duration.between(now, until), actor, why);
        }
        if (ok && halfLife != null) {
            ok = feed.watch(t.kind(), t.id(), Math.min(SignalFeed.MAX_WATCH_LOG_LR, weight), halfLife, actor, why);
        }
        if (on.isEmpty()) {
            shares.remove(t);
        }
        if (ok) {
            unsettled.remove(t);
        } else {
            unsettled.add(t);
        }
        return ok;
    }

    private Share shareOf(Target t, String holder) {
        Map<String, Share> on = shares.get(t);
        return on == null ? null : on.get(holder);
    }

    private void put(Target t, String holder, Share s) {
        shares.computeIfAbsent(t, k -> new LinkedHashMap<>()).put(holder, s);
    }

    private boolean roomFor(Target t, String holder) {
        Map<String, Share> on = shares.get(t);
        if (on == null) {
            if (shares.size() >= MAX_ENTITIES) {
                purge();
            }
            return shares.size() < MAX_ENTITIES;
        }
        return on.containsKey(holder) || on.size() < MAX_HOLDERS_PER_ENTITY;
    }

    /** Holders with a live share on an entity (for tests and the analyst view). */
    synchronized List<String> holders(SignalFeed.Kind kind, String id) {
        Map<String, Share> on = shares.get(new Target(kind, id));
        Instant now = clock.instant();
        return on == null ? List.of() : on.entrySet().stream().filter(e -> e.getValue().liveAt(now))
                .map(Map.Entry::getKey).toList();
    }
}

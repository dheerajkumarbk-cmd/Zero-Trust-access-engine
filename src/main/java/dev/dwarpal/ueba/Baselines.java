package dev.dwarpal.ueba;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.dwarpal.risk.scorers.CircularStats;
import dev.dwarpal.soc.Entity;

/**
 * The learned state of the detectors: one profile per baselined entity, and what each peer group has seen.
 * Everything is bounded by {@link UebaSettings}. Not thread-safe: {@link UebaEngine} holds the lock.
 */
final class Baselines {

    /** A map in access order that drops its least recently used entry above {@code max} entries. */
    static final class Lru<K, V> extends LinkedHashMap<K, V> {
        private static final long serialVersionUID = 1L;
        private final int max;
        long evicted;

        Lru(int max) {
            super(16, 0.75f, true);
            this.max = max;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
            boolean evict = size() > max;
            if (evict) {
                evicted++;
            }
            return evict;
        }
    }

    /** Hourly volume baseline of one action of one entity. */
    static final class Volume {
        final int[] counts;
        final long[] bytes;
        int filled;
        int next;
        long learnHour = Long.MIN_VALUE;
        int learnCount;
        long learnBytes;
        long scoreHour = Long.MIN_VALUE;
        int scoreCount;
        long scoreBytes;
        boolean volumeFired;
        boolean bytesFired;
        final Set<Long> flaggedHours = new HashSet<>();
        /** Daily snapshots of the mean, for the drift check. */
        final double[] daily = new double[7];
        int dailyFilled;
        long lastSnapshotDay = Long.MIN_VALUE;
        long driftFiredDay = Long.MIN_VALUE;

        Volume(int window) {
            counts = new int[window];
            bytes = new long[window];
        }

        double meanCount() {
            if (filled == 0) {
                return 0;
            }
            long s = 0;
            for (int i = 0; i < filled; i++) {
                s += counts[i];
            }
            return (double) s / filled;
        }

        double meanBytes() {
            if (filled == 0) {
                return 0;
            }
            double s = 0;
            for (int i = 0; i < filled; i++) {
                s += bytes[i];
            }
            return s / filled;
        }

        void push(int count, long b) {
            counts[next] = count;
            bytes[next] = b;
            next = (next + 1) % counts.length;
            filled = Math.min(filled + 1, counts.length);
        }

        double minDaily() {
            double m = Double.POSITIVE_INFINITY;
            for (int i = 0; i < dailyFilled; i++) {
                m = Math.min(m, daily[i]);
            }
            return m;
        }

        void snapshot(long day, double mean) {
            if (day == lastSnapshotDay) {
                return;
            }
            lastSnapshotDay = day;
            System.arraycopy(daily, 0, daily, 1, daily.length - 1);
            daily[0] = mean;
            dailyFilled = Math.min(dailyFilled + 1, daily.length);
        }
    }

    /** First-seen values of one field of one entity, with the novelty history of the rule of succession. */
    static final class Novelty {
        final Lru<String, Boolean> seen;
        final boolean[] wasNew;
        int filled;
        int next;
        long observations;

        Novelty(int maxValues, int window) {
            this.seen = new Lru<>(maxValues);
            this.wasNew = new boolean[window];
        }

        int newCount() {
            int k = 0;
            for (int i = 0; i < filled; i++) {
                if (wasNew[i]) {
                    k++;
                }
            }
            return k;
        }

        boolean knows(String value) {
            return seen.containsKey(value);
        }

        /** Learns one observation; returns whether it was new. */
        boolean learn(String value) {
            boolean isNew = seen.put(value, Boolean.TRUE) == null;
            wasNew[next] = isNew;
            next = (next + 1) % wasNew.length;
            filled = Math.min(filled + 1, wasNew.length);
            observations++;
            return isNew;
        }
    }

    /** Times of day (minutes) of learned events. */
    static final class TimeOfDay {
        final int[] minutes;
        int filled;
        int next;
        long firedHour = Long.MIN_VALUE;

        TimeOfDay(int max) {
            minutes = new int[max];
        }

        void learn(int minute) {
            minutes[next] = minute;
            next = (next + 1) % minutes.length;
            filled = Math.min(filled + 1, minutes.length);
        }

        List<Integer> samples() {
            List<Integer> l = new ArrayList<>(filled);
            for (int i = 0; i < filled; i++) {
                l.add(minutes[i]);
            }
            return l;
        }

        /** -n/(n+10) ln(2 pi f(theta)) of M6. */
        double logLikelihoodRatio(int minute, double kappa) {
            double n = filled;
            return -(n / (n + 10)) * CircularStats.logDensityRatio(CircularStats.toAngle(minute), samples(), kappa);
        }
    }

    static final class Profile {
        final Entity entity;
        final Map<String, Volume> volumes = new HashMap<>();
        final Map<String, Novelty> fields = new HashMap<>();
        final TimeOfDay time;
        /** dataset|destination -> times (epoch seconds) of the latest connections, for the beacon check. */
        final Lru<String, ArrayDeque<Long>> connections = new Lru<>(MAX_DESTINATIONS);
        final Map<String, Long> beaconFired = new HashMap<>();

        Profile(Entity entity, int timeSamples) {
            this.entity = entity;
            this.time = new TimeOfDay(timeSamples);
        }
    }

    private final UebaSettings settings;
    private final Lru<Entity, Profile> profiles;
    /** group|kind|field|value -> ids of the group's entities that learned the value. */
    private final Map<String, Set<String>> peerKnowledge = new HashMap<>();
    static final int MAX_PEER_KEYS = 200_000;
    static final int MAX_DESTINATIONS = 64;
    static final int BEACON_TIMES = 32;
    static final int MAX_PEER_MEMBERS = 10_000;
    long refusedProfiles;

    long evictedProfiles() {
        return profiles.evicted;
    }

    Baselines(UebaSettings settings) {
        this.settings = settings;
        int max = settings.maxProfiles();
        this.profiles = new Lru<>(max);
    }

    /** The profile of an entity, created if there is room. */
    Optional<Profile> profile(Entity e) {
        Profile p = profiles.get(e);
        if (p == null) {
            p = new Profile(e, Math.max(settings.timeMinSamples(), 200));
            profiles.put(e, p);
        }
        return Optional.of(p);
    }

    Optional<Profile> existing(Entity e) {
        return Optional.ofNullable(profiles.get(e));
    }

    int size() {
        return profiles.size();
    }

    Volume volume(Profile p, String action) {
        Volume v = p.volumes.get(action);
        if (v == null && p.volumes.size() < settings.maxActions()) {
            v = new Volume(settings.volumeWindow());
            p.volumes.put(action, v);
        }
        return v;
    }

    Novelty novelty(Profile p, String field) {
        return p.fields.computeIfAbsent(field, f -> new Novelty(settings.maxValues(), settings.noveltyWindow()));
    }

    private static String peerKey(String group, Entity.Kind kind, String field, String value) {
        return group + '|' + kind + '|' + field + '|' + value;
    }

    /** How many of the group's entities of this kind learned the value. */
    int peersKnowing(String group, Entity.Kind kind, String field, String value) {
        Set<String> s = peerKnowledge.get(peerKey(group, kind, field, value));
        return s == null ? 0 : s.size();
    }

    void peerLearn(String group, Entity entity, String field, String value) {
        String key = peerKey(group, entity.kind(), field, value);
        Set<String> s = peerKnowledge.get(key);
        if (s == null) {
            if (peerKnowledge.size() >= MAX_PEER_KEYS) {
                return;
            }
            s = new HashSet<>();
            peerKnowledge.put(key, s);
        }
        if (s.size() < MAX_PEER_MEMBERS) {
            s.add(entity.id());
        }
    }
}

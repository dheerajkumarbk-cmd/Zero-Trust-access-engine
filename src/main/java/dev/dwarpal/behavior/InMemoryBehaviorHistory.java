package dev.dwarpal.behavior;

import java.util.ArrayDeque;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Thread-safe, memory-bounded store of behavioural baselines.
 *
 * <p>Every key here is attacker-influenced (an attacker chooses usernames to try, rotates source
 * IPs), so unbounded maps would be a memory-exhaustion denial of service. Bounds:
 * <ul>
 *   <li>at most {@link #MAX_USERS} users, least-recently-used evicted;</li>
 *   <li>at most {@link #MAX_VALUES_PER_FEATURE} distinct values per user and feature, least-used
 *       evicted;</li>
 *   <li>the last {@link #MAX_TIMES} login times, and whether each login brought a new value, per user.</li>
 * </ul>
 * Only trusted logins should be recorded (see {@link LearningDecisionPoint}).
 */
public final class InMemoryBehaviorHistory implements BehaviorHistory {

    public static final int MAX_USERS = 100_000;
    public static final int MAX_VALUES_PER_FEATURE = 256;
    public static final int MAX_TIMES = 200;

    private static final class UserData {
        long logins;
        final EnumMap<Feature, Map<String, Long>> counts = new EnumMap<>(Feature.class);
        final EnumMap<Feature, ArrayDeque<Boolean>> novelty = new EnumMap<>(Feature.class);
        final ArrayDeque<Integer> minutes = new ArrayDeque<>();
        LoginEvent last;
    }

    private final int maxUsers;
    private final Map<String, UserData> users;

    public InMemoryBehaviorHistory() {
        this(MAX_USERS);
    }

    /** Smaller bound for tests of the eviction behaviour. */
    InMemoryBehaviorHistory(int maxUsers) {
        this.maxUsers = maxUsers;
        this.users = new LinkedHashMap<>(16, 0.75f, true) {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<String, UserData> eldest) {
                return size() > InMemoryBehaviorHistory.this.maxUsers;
            }
        };
    }

    public synchronized void record(LoginEvent e) {
        UserData u = users.computeIfAbsent(e.subjectId(), k -> new UserData());
        u.logins++;
        for (Feature f : Feature.values()) {
            Map<String, Long> m = u.counts.computeIfAbsent(f, k -> new LinkedHashMap<>());
            ArrayDeque<Boolean> nov = u.novelty.computeIfAbsent(f, k -> new ArrayDeque<>());
            nov.addLast(!m.containsKey(e.value(f)));
            if (nov.size() > MAX_TIMES) {
                nov.removeFirst();
            }
            m.merge(e.value(f), 1L, Long::sum);
            if (m.size() > MAX_VALUES_PER_FEATURE) {
                String rarest = m.entrySet().stream().min(Map.Entry.comparingByValue()).orElseThrow().getKey();
                m.remove(rarest);
            }
        }
        u.minutes.addLast(e.minuteOfDayUtc());
        if (u.minutes.size() > MAX_TIMES) {
            u.minutes.removeFirst();
        }
        if (u.last == null || !e.at().isBefore(u.last.at())) {
            u.last = e;
        }
    }

    /** Incident response: drop a (possibly poisoned) baseline so the user re-enrols. */
    public synchronized void forget(String subjectId) {
        users.remove(subjectId);
    }

    public synchronized int userCount() {
        return users.size();
    }

    @Override
    public synchronized long logins(String subjectId) {
        UserData u = users.get(subjectId);
        return u == null ? 0 : u.logins;
    }

    @Override
    public synchronized long distinct(String subjectId, Feature feature) {
        UserData u = users.get(subjectId);
        if (u == null) {
            return 0;
        }
        Map<String, Long> m = u.counts.get(feature);
        return m == null ? 0 : m.size();
    }

    @Override
    public synchronized boolean seen(String subjectId, Feature feature, String value) {
        UserData u = users.get(subjectId);
        if (u == null) {
            return false;
        }
        Map<String, Long> m = u.counts.get(feature);
        return m != null && m.containsKey(value);
    }

    @Override
    public synchronized Novelty novelty(String subjectId, Feature feature) {
        UserData u = users.get(subjectId);
        ArrayDeque<Boolean> nov = u == null ? null : u.novelty.get(feature);
        if (nov == null) {
            return new Novelty(0, 0);
        }
        return new Novelty(nov.stream().filter(b -> b).count(), nov.size());
    }

    @Override
    public synchronized Optional<LoginEvent> lastLogin(String subjectId) {
        UserData u = users.get(subjectId);
        return u == null ? Optional.empty() : Optional.ofNullable(u.last);
    }

    @Override
    public synchronized List<Integer> loginMinutes(String subjectId) {
        UserData u = users.get(subjectId);
        return u == null ? List.of() : List.copyOf(u.minutes);
    }
}

package dev.dwarpal.gateway;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.edge.EdgeGrant;
import dev.dwarpal.edge.EdgeRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The sessions this gateway opened, so that on every later request the subject and device come from
 * the session, never from anything the client sends. Holds only the token's hash. Bounded: when full
 * it first drops expired entries, then refuses new logins (fail-closed). Like the Policy
 * Administrator it keeps at most {@code perSubject} sessions for one subject and drops the oldest
 * (B6: otherwise sessions the administrator had already closed piled up here for their whole lifetime,
 * and one user's logins could fill the table for everyone).
 */
final class GatewaySessions {

    record Entry(String sessionId, String tokenHash, String subjectId, String deviceId, String resourceId,
                 DevicePosture loginPosture, Instant expiresAt, long sequence) {
    }

    private final Map<String, Entry> bySessionId = new ConcurrentHashMap<>();
    private final int capacity;
    private final int perSubject;
    private long sequence;

    GatewaySessions(int capacity, int perSubject) {
        this.capacity = capacity;
        this.perSubject = perSubject;
    }

    /** False when there is no room (the login is then refused). */
    synchronized boolean hasRoom(Instant now) {
        if (bySessionId.size() >= capacity) {
            purge(now);
        }
        return bySessionId.size() < capacity;
    }

    synchronized boolean remember(EdgeGrant grant, EdgeRequest login, Instant now) {
        List<Entry> mine = bySessionId.values().stream().filter(e -> e.subjectId().equals(login.subjectId()))
                .sorted(Comparator.comparingLong(Entry::sequence)).toList();
        for (int i = 0; i <= mine.size() - perSubject; i++) {
            bySessionId.remove(mine.get(i).sessionId());
        }
        if (!hasRoom(now)) {
            return false;
        }
        bySessionId.put(grant.sessionId(), new Entry(grant.sessionId(), Digests.sha256Hex(grant.token()),
                login.subjectId(), login.deviceId(), login.resourceId(), login.claimedPosture(), grant.expiresAt(),
                ++sequence));
        return true;
    }

    /** The session named by the client, if this gateway opened it, it is not past its lifetime and the token matches. */
    Optional<Entry> find(String sessionId, String token, Instant now) {
        Objects.requireNonNull(token, "token");
        Entry e = sessionId == null ? null : bySessionId.get(sessionId);
        if (e == null) {
            return Optional.empty();
        }
        if (!now.isBefore(e.expiresAt())) {
            bySessionId.remove(sessionId, e);
            return Optional.empty();
        }
        boolean same = MessageDigest.isEqual(e.tokenHash().getBytes(StandardCharsets.US_ASCII),
                Digests.sha256Hex(token).getBytes(StandardCharsets.US_ASCII));
        return same ? Optional.of(e) : Optional.empty();
    }

    void forget(String sessionId) {
        bySessionId.remove(sessionId);
    }

    synchronized int purge(Instant now) {
        int before = bySessionId.size();
        bySessionId.values().removeIf(e -> !now.isBefore(e.expiresAt()));
        return before - bySessionId.size();
    }

    int size() {
        return bySessionId.size();
    }
}

package dev.dwarpal.siem.platform;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EventSource;
import dev.dwarpal.soc.SecurityEvent;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * What every collector shares: a bounded queue of normalised events, unique event ids, counters of refused
 * input, and the rule that refused input is never dropped silently. Input that cannot be parsed becomes a
 * {@code parse.failure} event (its reason, length and a SHA-256 prefix, never the raw text, which may carry
 * secrets); when the queue is full, the overflow is counted and reported by one {@code collector.overflow}
 * event as soon as there is room again.
 */
abstract class CollectorBase implements EventSource {

    /** Events waiting to be ingested, per collector. */
    static final int MAX_PENDING = 10_000;
    /** Fields a collector copies from one raw item; the rest are counted in {@code extraFields}. */
    static final int MAX_COPIED_FIELDS = 32;

    private final String dataset;
    private final String prefix;
    private final String runId;
    private final ArrayDeque<SecurityEvent> pending = new ArrayDeque<>();
    private long sequence;
    private long refused;
    private long overflow;
    private long overflowReported;
    private long accepted;

    CollectorBase(String dataset, String prefix, String runId) {
        this.dataset = Validate.id(dataset, "dataset");
        this.prefix = Validate.id(prefix, "prefix");
        this.runId = Validate.id(runId, "runId");
        if (runId.length() > 24) {
            throw new IllegalArgumentException("runId: at most 24 characters");
        }
    }

    @Override
    public final String name() {
        return dataset;
    }

    @Override
    public final synchronized List<SecurityEvent> poll(int max) {
        if (max < 1) {
            throw new IllegalArgumentException("max must be positive");
        }
        List<SecurityEvent> out = new ArrayList<>(Math.min(max, pending.size() + 1));
        while (out.size() < max && !pending.isEmpty()) {
            out.add(pending.poll());
        }
        if (out.size() < max && overflow > overflowReported) {
            long lost = overflow - overflowReported;
            overflowReported = overflow;
            out.add(event(lastTime(out), SecurityEvent.Category.SYSTEM, "collector.overflow",
                    SecurityEvent.EventOutcome.FAILURE, SecurityEvent.Provenance.COLLECTED, List.of(),
                    Map.of("lost", Long.toString(lost), "reason", "queue full")));
        }
        return out;
    }

    private Instant lastTime(List<SecurityEvent> out) {
        return out.isEmpty() ? lastOffered : out.getLast().at();
    }

    private Instant lastOffered = Instant.EPOCH;

    @Override
    public final synchronized long refused() {
        return refused;
    }

    /** Raw items turned into events so far. */
    public final synchronized long accepted() {
        return accepted;
    }

    /** Events lost because the queue was full (each counted and reported, never silent). */
    public final synchronized long overflowed() {
        return overflow;
    }

    /** Events waiting to be polled. */
    public final synchronized int pending() {
        return pending.size();
    }

    final synchronized void seen(Instant receivedAt) {
        lastOffered = Objects.requireNonNull(receivedAt, "receivedAt");
    }

    /** Queues an event; false (and counted) when the queue is full. */
    final synchronized boolean enqueue(SecurityEvent e) {
        if (pending.size() >= MAX_PENDING) {
            overflow++;
            return false;
        }
        pending.add(e);
        accepted++;
        return true;
    }

    /** Counts refused input and keeps a trace of it, without the raw text. */
    final synchronized void refuse(Instant receivedAt, String action, String reason, String raw,
                                   SecurityEvent.Provenance provenance, List<Entity> entities,
                                   Map<String, String> extra) {
        refused++;
        Map<String, String> f = new LinkedHashMap<>(extra);
        f.put("reason", reason);
        f.put("length", Integer.toString(raw.length()));
        f.put("sha256", Digests.sha256Hex(raw).substring(0, 32));
        if (pending.size() >= MAX_PENDING) {
            overflow++;
            return;
        }
        pending.add(event(receivedAt, SecurityEvent.Category.SYSTEM, action, SecurityEvent.EventOutcome.FAILURE,
                provenance, entities, f));
    }

    final void parseFailure(Instant receivedAt, String reason, String raw) {
        refuse(receivedAt, "parse.failure", reason, raw, SecurityEvent.Provenance.COLLECTED, List.of(), Map.of());
    }

    final synchronized SecurityEvent event(Instant at, SecurityEvent.Category category, String action,
                                           SecurityEvent.EventOutcome outcome, SecurityEvent.Provenance provenance,
                                           List<Entity> entities, Map<String, String> fields) {
        String id = prefix + "-" + runId + "-" + (++sequence);
        return new SecurityEvent(id, at, dataset, category, action, outcome, provenance, entities, fields);
    }

    /** An entity if the value is a valid id, otherwise nothing (the value stays in the fields). */
    static void addEntity(List<Entity> out, Entity.Kind kind, String value) {
        if (value == null || value.isEmpty() || out.size() >= SecurityEvent.MAX_ENTITIES) {
            return;
        }
        try {
            Entity e = new Entity(kind, value);
            if (!out.contains(e)) {
                out.add(e);
            }
        } catch (IllegalArgumentException ignored) {
            // not an id: kept as a field only, so it can never be confused with a real entity
        }
    }

    /** Whether a string is a plausible IPv4 or IPv6 address (checked by hand, no regex). */
    static boolean address(String s) {
        if (s.isEmpty() || s.length() > 45) {
            return false;
        }
        if (s.indexOf(':') >= 0) {
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex && c != ':' && c != '.') {
                    return false;
                }
            }
            return true;
        }
        int parts = 0;
        int value = -1;
        for (int i = 0; i <= s.length(); i++) {
            char c = i < s.length() ? s.charAt(i) : '.';
            if (c == '.') {
                if (value < 0) {
                    return false;
                }
                parts++;
                value = -1;
            } else if (c >= '0' && c <= '9') {
                value = (value < 0 ? 0 : value * 10) + (c - '0');
                if (value > 255) {
                    return false;
                }
            } else {
                return false;
            }
        }
        return parts == 4;
    }

    /** A non-negative integer of at most 18 digits, or -1. */
    static long count(String s) {
        if (s.isEmpty() || s.length() > 18) {
            return -1;
        }
        long v = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return -1;
            }
            v = v * 10 + (c - '0');
        }
        return v;
    }

    /** Whether a string is a valid event field name. */
    static boolean fieldName(String n) {
        try {
            SecurityEvent.name(n);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}

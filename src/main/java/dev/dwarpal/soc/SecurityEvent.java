package dev.dwarpal.soc;

import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * One event in the common format every source is normalised into (Dwarpal's own audit trail, firewall,
 * endpoint sensors, cloud applications), so one rule, one search and one baseline work across all of them.
 *
 * @param id         unique within its dataset (for example {@code fw-000042}); an identifier
 * @param at         when it happened at the source (not when it was collected)
 * @param dataset    where it came from, for example {@code dwarpal.audit}, {@code firewall}, {@code endpoint},
 *                   {@code cloud}; an identifier
 * @param category   what kind of event it is
 * @param action     what happened, lower case and dotted, for example {@code access.decision},
 *                   {@code process.start}, {@code network.flow}, {@code file.download}
 * @param outcome    how it ended
 * @param provenance how far it can be trusted (see {@link Provenance})
 * @param entities   who and what it is about, at most {@link #MAX_ENTITIES}, no duplicates
 * @param fields     other facts, at most {@link #MAX_FIELDS}; names {@code [a-zA-Z][a-zA-Z0-9_.]*} up to 64
 *                   characters, values sanitised (no line breaks, controls or bidi) and cut at
 *                   {@link #MAX_VALUE} characters
 */
public record SecurityEvent(String id, Instant at, String dataset, Category category, String action,
                            EventOutcome outcome, Provenance provenance, List<Entity> entities,
                            Map<String, String> fields) {

    public static final int MAX_ENTITIES = 16;
    public static final int MAX_FIELDS = 64;
    public static final int MAX_NAME = 64;
    public static final int MAX_VALUE = 1024;
    public static final int MAX_ACTION = 64;

    /** What kind of event, in the spirit of the Elastic Common Schema's event categories. */
    public enum Category {
        AUTHENTICATION, ACCESS, SESSION, PRIVILEGE, NETWORK, PROCESS, FILE, DATA, CLOUD, SOC, SYSTEM
    }

    public enum EventOutcome { SUCCESS, FAILURE, CHALLENGED, UNKNOWN }

    /**
     * How far an event can be trusted. An alert supported only by {@link #COLLECTED} events may watch,
     * rank and open cases, but must never trigger a destructive action on its own: anyone on the network
     * can send a syslog line naming someone.
     */
    public enum Provenance {
        /** Written by Dwarpal's own code into the keyed audit chain. */
        VERIFIED_AUDIT,
        /** Sent by a sensor and verified with that sensor's own key, bound to its device. */
        SIGNED_SENSOR,
        /** From a source that cannot prove who sent it (syslog over the network, exported files). */
        COLLECTED;

        /** Whether this event alone may justify a destructive response. */
        public boolean actionable() {
            return this != COLLECTED;
        }
    }

    public SecurityEvent {
        Validate.id(id, "event.id");
        Objects.requireNonNull(at, "event.at");
        Validate.id(dataset, "event.dataset");
        Objects.requireNonNull(category, "event.category");
        action(action);
        Objects.requireNonNull(outcome, "event.outcome");
        Objects.requireNonNull(provenance, "event.provenance");
        entities = List.copyOf(entities);
        if (entities.size() > MAX_ENTITIES) {
            throw new IllegalArgumentException("an event names at most " + MAX_ENTITIES + " entities");
        }
        if (entities.stream().distinct().count() != entities.size()) {
            throw new IllegalArgumentException("an event names each entity once");
        }
        Objects.requireNonNull(fields, "event.fields");
        if (fields.size() > MAX_FIELDS) {
            throw new IllegalArgumentException("an event has at most " + MAX_FIELDS + " fields");
        }
        Map<String, String> clean = new LinkedHashMap<>();
        for (Map.Entry<String, String> f : fields.entrySet()) {
            clean.put(name(f.getKey()), value(f.getValue()));
        }
        fields = Collections.unmodifiableMap(clean);
    }

    /** A field, if present. */
    public Optional<String> field(String name) {
        return Optional.ofNullable(fields.get(name));
    }

    /** The first entity of a kind, if any. */
    public Optional<Entity> first(Entity.Kind kind) {
        return entities.stream().filter(e -> e.kind() == kind).findFirst();
    }

    /** Validates an action: lower-case letters, digits, '_' and '.', starting with a letter. */
    public static String action(String a) {
        Objects.requireNonNull(a, "event.action");
        if (a.isEmpty() || a.length() > MAX_ACTION || !lower(a.charAt(0))) {
            throw new IllegalArgumentException("event.action must start with a lower-case letter, at most "
                    + MAX_ACTION + " characters");
        }
        for (int i = 1; i < a.length(); i++) {
            char c = a.charAt(i);
            if (!lower(c) && !(c >= '0' && c <= '9') && c != '_' && c != '.') {
                throw new IllegalArgumentException("event.action: only a-z, 0-9, '_' and '.'");
            }
        }
        return a;
    }

    /** Validates a field name: a letter, then letters, digits, '_' or '.', at most 64 characters. */
    public static String name(String n) {
        Objects.requireNonNull(n, "field name");
        if (n.isEmpty() || n.length() > MAX_NAME || !letter(n.charAt(0))) {
            throw new IllegalArgumentException("field names start with a letter, at most " + MAX_NAME + " characters");
        }
        for (int i = 1; i < n.length(); i++) {
            char c = n.charAt(i);
            if (!letter(c) && !(c >= '0' && c <= '9') && c != '_' && c != '.') {
                throw new IllegalArgumentException("field names: only letters, digits, '_' and '.'");
            }
        }
        return n;
    }

    private static String value(String v) {
        String s = Sanitize.text(Objects.requireNonNull(v, "field value"), MAX_VALUE);
        return s.length() > MAX_VALUE ? s.substring(0, MAX_VALUE) : s;
    }

    private static boolean lower(char c) {
        return c >= 'a' && c <= 'z';
    }

    private static boolean letter(char c) {
        return lower(c) || (c >= 'A' && c <= 'Z');
    }
}

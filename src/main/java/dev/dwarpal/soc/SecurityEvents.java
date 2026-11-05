package dev.dwarpal.soc;

import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.domain.Validate;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The bridge between {@link SecurityEvent}s and the audit chain, in both directions.
 *
 * <p><b>Into the chain.</b> A collector writes every normalised event as one {@link #RECORD_TYPE} record
 * with {@link #toAuditFields}, under the actor {@code collector:<dataset>}, before anything reads it. From
 * then on the event is tamper-evident, and alerts cite it by audit sequence number like any other record.
 *
 * <p><b>Out of the chain.</b> {@link #fromAudit} turns every record into an event: {@code SECURITY_EVENT}
 * records back into what was collected, and Dwarpal's own records (decisions, sessions, privileged access,
 * DLP, SOC actions) into events with {@link SecurityEvent.Provenance#VERIFIED_AUDIT}. Readers therefore see
 * one stream across all sources. A collected record can never claim to be Dwarpal's own.
 */
public final class SecurityEvents {

    public static final String RECORD_TYPE = "SECURITY_EVENT";
    public static final String NATIVE_DATASET = "dwarpal.audit";
    public static final String COLLECTOR_PREFIX = "collector:";
    /** The data guard's (Layer 4) DLP audit type, whose actor is the uploader. */
    static final String DLP_TYPE = "casb.dlp";
    /** Prefix of the event's own fields inside a {@code SECURITY_EVENT} payload. */
    static final String FIELD_PREFIX = "f.";

    /** Payload fields of native records that name entities, and the kind they name. */
    private static final Map<String, Entity.Kind> ENTITY_FIELDS = Map.ofEntries(
            Map.entry("subject", Entity.Kind.SUBJECT), Map.entry("subjectId", Entity.Kind.SUBJECT),
            Map.entry("device", Entity.Kind.DEVICE), Map.entry("deviceId", Entity.Kind.DEVICE),
            Map.entry("sourceIp", Entity.Kind.IP), Map.entry("ip", Entity.Kind.IP),
            Map.entry("sessionId", Entity.Kind.SESSION),
            Map.entry("resource", Entity.Kind.RESOURCE), Map.entry("resourceId", Entity.Kind.RESOURCE));
    private static final Set<String> FAILURE_WORDS = Set.of("REFUSED", "FAILED", "REJECTED", "REPLAY", "DENIED",
            "REJECTIONS", "NOT");
    private static final Set<String> SUCCESS_WORDS = Set.of("OPENED", "GRANTED", "APPROVED", "USED", "INSTALLED",
            "ACCEPTED", "REVIEWED", "RELEASED", "UNDONE");

    private SecurityEvents() {
    }

    /** The payload of the {@code SECURITY_EVENT} record that carries {@code e} into the chain. */
    public static Map<String, String> toAuditFields(SecurityEvent e) {
        Objects.requireNonNull(e, "event");
        if (e.provenance() == SecurityEvent.Provenance.VERIFIED_AUDIT || e.dataset().equals(NATIVE_DATASET)) {
            throw new IllegalArgumentException("a collected event cannot claim to be Dwarpal's own audit record");
        }
        Map<String, String> f = new LinkedHashMap<>();
        f.put("eventId", e.id());
        f.put("eventTime", e.at().toString());
        f.put("dataset", e.dataset());
        f.put("category", e.category().name());
        f.put("action", e.action());
        f.put("outcome", e.outcome().name());
        f.put("provenance", e.provenance().name());
        f.put("entities", encode(e.entities()));
        for (Map.Entry<String, String> x : e.fields().entrySet()) {
            f.put(FIELD_PREFIX + x.getKey(), x.getValue());
        }
        return f;
    }

    /** The actor under which a collector writes events of {@code dataset}. */
    public static String collectorActor(String dataset) {
        return COLLECTOR_PREFIX + Validate.id(dataset, "dataset");
    }

    /**
     * The event a record stands for.
     *
     * @throws IllegalArgumentException if a {@code SECURITY_EVENT} record is malformed, was not written by
     *                                  the collector of its dataset, or claims to be Dwarpal's own; readers
     *                                  count such records as malformed and never guess
     */
    public static ChainedEvent fromAudit(AuditEvent a) {
        Objects.requireNonNull(a, "audit event");
        SecurityEvent e = a.type().equals(RECORD_TYPE) ? collected(a) : nativeEvent(a);
        return new ChainedEvent(a.sequence(), a.at(), e);
    }

    private static SecurityEvent collected(AuditEvent a) {
        String dataset = required(a, "dataset");
        if (dataset.equals(NATIVE_DATASET)) {
            throw new IllegalArgumentException("a collected record cannot use the native dataset");
        }
        if (!a.actor().equals(COLLECTOR_PREFIX + dataset)) {
            throw new IllegalArgumentException("record written by " + a.actor() + " for dataset " + dataset);
        }
        SecurityEvent.Provenance p = enumOf(SecurityEvent.Provenance.class, required(a, "provenance"));
        if (p == SecurityEvent.Provenance.VERIFIED_AUDIT) {
            throw new IllegalArgumentException("a collected record cannot claim VERIFIED_AUDIT");
        }
        Instant at;
        try {
            at = Instant.parse(required(a, "eventTime"));
        } catch (DateTimeParseException ex) {
            throw new IllegalArgumentException("eventTime is not an ISO-8601 instant", ex);
        }
        Map<String, String> fields = new LinkedHashMap<>();
        for (Map.Entry<String, String> x : a.fields().entrySet()) {
            if (x.getKey().startsWith(FIELD_PREFIX)) {
                fields.put(x.getKey().substring(FIELD_PREFIX.length()), x.getValue());
            }
        }
        return new SecurityEvent(required(a, "eventId"), at, dataset,
                enumOf(SecurityEvent.Category.class, required(a, "category")), required(a, "action"),
                enumOf(SecurityEvent.EventOutcome.class, required(a, "outcome")), p,
                decode(required(a, "entities")), fields);
    }

    private static SecurityEvent nativeEvent(AuditEvent a) {
        List<Entity> entities = new ArrayList<>();
        Map<String, String> fields = new LinkedHashMap<>();
        for (Map.Entry<String, String> x : a.fields().entrySet()) {
            Entity.Kind kind = ENTITY_FIELDS.get(x.getKey());
            if (kind != null && !x.getValue().isEmpty()) {
                Entity en = entity(kind, x.getValue());
                if (!entities.contains(en) && entities.size() < SecurityEvent.MAX_ENTITIES) {
                    entities.add(en);
                }
            } else if (fields.size() < SecurityEvent.MAX_FIELDS && validName(x.getKey())) {
                fields.put(x.getKey(), x.getValue());
            }
        }
        if (fields.size() < SecurityEvent.MAX_FIELDS) {
            fields.put("auditType", a.type());
        }
        if (fields.size() < SecurityEvent.MAX_FIELDS) {
            fields.put("actor", a.actor());
        }
        // A DLP record names the uploader only as its actor: make them a person the rules can count by.
        if (a.type().equals(DLP_TYPE) && entities.size() < SecurityEvent.MAX_ENTITIES) {
            Entity uploader = entity(Entity.Kind.SUBJECT, a.actor());
            if (!entities.contains(uploader)) {
                entities.add(uploader);
            }
        }
        return new SecurityEvent("audit-" + a.sequence(), a.at(), NATIVE_DATASET, category(a.type()),
                actionOf(a.type()), outcome(a), SecurityEvent.Provenance.VERIFIED_AUDIT, entities, fields);
    }

    /** The category of one of Dwarpal's own audit types. */
    static SecurityEvent.Category category(String type) {
        if (type.equals("ACCESS_DECISION")) {
            return SecurityEvent.Category.ACCESS;
        }
        if (type.startsWith("SESSION_")) {
            return SecurityEvent.Category.SESSION;
        }
        if (type.startsWith("ELEVATION_") || type.startsWith("BREAK_GLASS_")) {
            return SecurityEvent.Category.PRIVILEGE;
        }
        if (type.startsWith("casb.")) {
            return SecurityEvent.Category.DATA;
        }
        if (type.startsWith("SIGNAL_") || type.startsWith("CASE_") || type.startsWith("VERDICT_")
                || type.startsWith("RESPONSE_")) {
            return SecurityEvent.Category.SOC;
        }
        if (type.startsWith("API_") || type.startsWith("AUTH")) {
            return SecurityEvent.Category.AUTHENTICATION;
        }
        return SecurityEvent.Category.SYSTEM;
    }

    /** {@code SESSION_REVOKED} becomes {@code session.revoked}; {@code casb.dlp} stays {@code casb.dlp}. */
    static String actionOf(String type) {
        StringBuilder b = new StringBuilder(type.length());
        for (int i = 0; i < type.length() && b.length() < SecurityEvent.MAX_ACTION; i++) {
            char c = type.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                b.append((char) (c - 'A' + 'a'));
            } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
                b.append(c);
            } else if (!b.isEmpty() && b.charAt(b.length() - 1) != '.') {
                b.append('.');
            }
        }
        String s = b.toString();
        if (s.isEmpty() || s.charAt(0) < 'a' || s.charAt(0) > 'z') {
            s = "audit." + s;
        }
        return s.length() > SecurityEvent.MAX_ACTION ? s.substring(0, SecurityEvent.MAX_ACTION) : s;
    }

    private static SecurityEvent.EventOutcome outcome(AuditEvent a) {
        String decided = a.field("outcome").orElse("");
        switch (decided) {
            case "ALLOW" -> {
                return SecurityEvent.EventOutcome.SUCCESS;
            }
            case "DENY" -> {
                return SecurityEvent.EventOutcome.FAILURE;
            }
            case "STEP_UP" -> {
                return SecurityEvent.EventOutcome.CHALLENGED;
            }
            default -> {
                // not a decision: judged by the words of the type below
            }
        }
        if (a.type().endsWith("_REQUIRED")) {
            return SecurityEvent.EventOutcome.CHALLENGED;
        }
        if (a.type().equals(DLP_TYPE)) {
            return a.field("action").filter("BLOCK"::equals).isPresent()
                    ? SecurityEvent.EventOutcome.FAILURE : SecurityEvent.EventOutcome.SUCCESS;
        }
        String[] words = a.type().toUpperCase(Locale.ROOT).split("[_.]", 16);
        for (String w : words) {
            if (FAILURE_WORDS.contains(w)) {
                return SecurityEvent.EventOutcome.FAILURE;
            }
        }
        for (String w : words) {
            if (SUCCESS_WORDS.contains(w)) {
                return SecurityEvent.EventOutcome.SUCCESS;
            }
        }
        return SecurityEvent.EventOutcome.UNKNOWN;
    }

    /**
     * An entity from a value. A value that is not a valid id (only possible in a record Dwarpal did not
     * write) is not dropped, which would let it hide; it becomes {@code invalid-<hash>}.
     */
    static Entity entity(Entity.Kind kind, String raw) {
        try {
            return new Entity(kind, Validate.id(raw, "entity"));
        } catch (IllegalArgumentException e) {
            return new Entity(kind, "invalid-" + Digests.sha256Hex(raw).substring(0, 16));
        }
    }

    /** {@code SUBJECT=u1;DEVICE=laptop-u1}; ids cannot contain ';' or '='. */
    static String encode(List<Entity> entities) {
        StringBuilder b = new StringBuilder();
        for (Entity e : entities) {
            if (!b.isEmpty()) {
                b.append(';');
            }
            b.append(e.kind().name()).append('=').append(e.id());
        }
        return b.toString();
    }

    static List<Entity> decode(String s) {
        List<Entity> out = new ArrayList<>();
        if (s.isEmpty()) {
            return out;
        }
        String[] parts = s.split(";", SecurityEvent.MAX_ENTITIES + 2);
        if (parts.length > SecurityEvent.MAX_ENTITIES) {
            throw new IllegalArgumentException("too many entities");
        }
        for (String p : parts) {
            int eq = p.indexOf('=');
            if (eq < 1) {
                throw new IllegalArgumentException("entity without a kind");
            }
            out.add(new Entity(enumOf(Entity.Kind.class, p.substring(0, eq)), p.substring(eq + 1)));
        }
        return out;
    }

    private static String required(AuditEvent a, String name) {
        return a.field(name).orElseThrow(() -> new IllegalArgumentException("missing field " + name));
    }

    private static <E extends Enum<E>> E enumOf(Class<E> type, String name) {
        try {
            return Enum.valueOf(type, name);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("unknown " + type.getSimpleName() + " value", e);
        }
    }

    private static boolean validName(String n) {
        try {
            SecurityEvent.name(n);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}

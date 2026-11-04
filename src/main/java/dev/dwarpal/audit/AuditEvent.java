package dev.dwarpal.audit;

import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * One audit record as readers use it: its position, time, type and actor, and its payload as a map of
 * field names to values. Every Dwarpal payload is a flat JSON object of strings ({@link Json#object});
 * anything else (nested values, numbers, duplicate keys, oversized documents) is refused, because a
 * reader that guesses at a malformed record can be steered by whoever wrote it.
 */
public record AuditEvent(long sequence, Instant at, String type, String actor, Map<String, String> fields) {

    /** Payloads are written by Dwarpal and small; these limits only stop hostile or corrupt input. */
    public static final JsonLimits PAYLOAD_LIMITS = new JsonLimits(256 * 1024, 2, 65_536, 256, 1, 32, 600);
    private static final JsonReader READER = new JsonReader(PAYLOAD_LIMITS);

    public AuditEvent {
        Objects.requireNonNull(at, "at");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(actor, "actor");
        fields = Map.copyOf(fields);
    }

    /**
     * Parses a record's payload.
     *
     * @throws IllegalArgumentException if the payload is not a flat object of strings within the limits
     */
    public static AuditEvent of(AuditRecord r) {
        Objects.requireNonNull(r, "record");
        JsonValue v;
        try {
            v = READER.read(r.payloadJson());
        } catch (JsonException e) {
            throw new IllegalArgumentException("audit record " + r.sequence() + ": payload is not valid JSON", e);
        }
        if (!(v instanceof JsonValue.JObject o)) {
            throw new IllegalArgumentException("audit record " + r.sequence() + ": payload is not an object");
        }
        Map<String, String> f = new LinkedHashMap<>();
        for (String k : o.keys()) {
            if (!(o.get(k).orElseThrow() instanceof JsonValue.JString s)) {
                throw new IllegalArgumentException("audit record " + r.sequence() + ": field values must be strings");
            }
            f.put(k, s.value());
        }
        return new AuditEvent(r.sequence(), r.at(), r.type(), r.actor(), f);
    }

    /** The value of a field, if the record has it. */
    public Optional<String> field(String name) {
        return Optional.ofNullable(fields.get(name));
    }
}

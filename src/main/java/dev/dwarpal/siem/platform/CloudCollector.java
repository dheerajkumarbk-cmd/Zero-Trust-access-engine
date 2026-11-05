package dev.dwarpal.siem.platform;

import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;

import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Collects a cloud application's audit export: one flat JSON object per line, for example
 * {@code {"time":"...","app":"drive","user":"u9","ip":"10.20.0.10","op":"file.download","object":"/finance/a.zip",
 * "bytes":31000000,"share":"none"}}. Events carry {@link SecurityEvent.Provenance#COLLECTED}: an exported file
 * proves nothing about who wrote it.
 *
 * <p>{@code time}, {@code user} and {@code op} are required; {@code op} becomes the event's action and must be
 * lower case and dotted; {@code bytes} must be a whole number. Nested values, duplicate keys, oversized lines and
 * anything else unexpected are refused and kept as {@code parse.failure} events. The device behind the address
 * comes from the leases given to the collector, so cloud activity links to the laptop it came from.
 */
public final class CloudCollector extends CollectorBase {

    public static final String DATASET = "cloud";
    public static final int MAX_LINE = 16_384;
    private static final JsonReader READER = new JsonReader(new JsonLimits(MAX_LINE, 1, 4_096, 48, 1, 20, 64));
    private static final Set<String> STRINGS = Set.of("time", "app", "user", "ip", "op", "object", "share", "result",
            "target", "userAgent", "country");

    private final Map<String, String> leases;

    public CloudCollector(String runId, Map<String, String> leases) {
        super(DATASET, "cl", runId(runId));
        Objects.requireNonNull(leases, "leases");
        if (leases.size() > FirewallCollector.MAX_LEASES) {
            throw new IllegalArgumentException("at most " + FirewallCollector.MAX_LEASES + " leases");
        }
        Map<String, String> copy = new HashMap<>();
        leases.forEach((ip, device) -> copy.put(Objects.requireNonNull(ip, "lease ip"),
                new Entity(Entity.Kind.DEVICE, device).id()));
        this.leases = Map.copyOf(copy);
    }

    /** Takes one line; false if it was refused (counted and kept as a {@code parse.failure} event). */
    public boolean offer(String line, Instant receivedAt) {
        Objects.requireNonNull(line, "line");
        seen(receivedAt);
        if (line.length() > MAX_LINE) {
            parseFailure(receivedAt, "line longer than " + MAX_LINE, line);
            return false;
        }
        try {
            enqueue(parse(line));
            return true;
        } catch (IllegalArgumentException | JsonException | DateTimeException bad) {
            String why = bad instanceof FirewallCollector.Malformed m ? m.getMessage() : "malformed line";
            parseFailure(receivedAt, why, line);
            return false;
        }
    }

    private SecurityEvent parse(String line) {
        if (!(READER.read(line) instanceof JsonValue.JObject o)) {
            throw new FirewallCollector.Malformed("line is not an object");
        }
        Map<String, String> raw = new LinkedHashMap<>();
        long bytes = -1;
        int extra = 0;
        for (String k : o.keys()) {
            JsonValue v = o.get(k).orElseThrow();
            if (k.equals("bytes")) {
                if (!(v instanceof JsonValue.JNumber n)) {
                    throw new FirewallCollector.Malformed("bytes must be a number");
                }
                bytes = n.asLong();
                if (bytes < 0) {
                    throw new FirewallCollector.Malformed("bytes must not be negative");
                }
            } else if (STRINGS.contains(k)) {
                if (!(v instanceof JsonValue.JString s)) {
                    throw new FirewallCollector.Malformed(k + " must be a string");
                }
                raw.put(k, s.value());
            } else {
                extra++;
            }
        }
        String time = raw.get("time");
        String user = raw.get("user");
        String op = raw.get("op");
        if (time == null || user == null || op == null) {
            throw new FirewallCollector.Malformed("time, user and op are required");
        }
        Instant at = FirewallCollector.parseIso(time);
        String action;
        try {
            action = SecurityEvent.action(op);
        } catch (IllegalArgumentException e) {
            throw new FirewallCollector.Malformed("bad op");
        }
        List<Entity> entities = new ArrayList<>(4);
        addEntity(entities, Entity.Kind.SUBJECT, user);
        if (entities.isEmpty()) {
            throw new FirewallCollector.Malformed("user is not an id");
        }
        String ip = raw.get("ip");
        if (ip != null && address(ip)) {
            addEntity(entities, Entity.Kind.IP, ip);
            String device = leases.get(ip);
            if (device != null) {
                addEntity(entities, Entity.Kind.DEVICE, device);
            }
        }
        String object = raw.get("object");
        if (object != null) {
            addEntity(entities, Entity.Kind.RESOURCE, object);
        }
        Map<String, String> fields = new LinkedHashMap<>();
        for (Map.Entry<String, String> x : raw.entrySet()) {
            if (!x.getKey().equals("time")) {
                fields.put(x.getKey(), x.getValue());
            }
        }
        if (bytes >= 0) {
            fields.put("bytes", Long.toString(bytes));
        }
        if (extra > 0) {
            fields.put("extraFields", Integer.toString(extra));
        }
        SecurityEvent.EventOutcome outcome = switch (raw.getOrDefault("result", "")) {
            case "success", "ok" -> SecurityEvent.EventOutcome.SUCCESS;
            case "failure", "denied", "error" -> SecurityEvent.EventOutcome.FAILURE;
            default -> SecurityEvent.EventOutcome.UNKNOWN;
        };
        return event(at, SecurityEvent.Category.CLOUD, action, outcome, SecurityEvent.Provenance.COLLECTED,
                entities, fields);
    }
}

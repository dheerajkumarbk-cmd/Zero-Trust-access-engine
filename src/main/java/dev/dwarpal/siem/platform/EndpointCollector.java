package dev.dwarpal.siem.platform;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;

import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Collects endpoint telemetry: batches of JSON lines that a device agent signs with its own
 * {@link KeyPurpose#DEVICE_AGENT} key over {@link SignedMessages#endpointTelemetry} (device, batch number, time and
 * the body's SHA-256). Events from an accepted batch carry {@link SecurityEvent.Provenance#SIGNED_SENSOR}.
 *
 * <p>A batch is accepted only if, in this order:
 * <ol>
 *   <li>it is within the size limits ({@link #MAX_BODY} bytes, {@link #MAX_LINES} lines);</li>
 *   <li>the signature verifies with a key bound to the device the batch names, at most {@link #MAX_AGE} old and
 *       not from the future (so a batch cannot be moved to another device or edited);</li>
 *   <li>its number is greater than the last accepted number for that device (single use and in order: a
 *       replayed or reordered batch is refused). A jump in numbers is accepted but reported by a
 *       {@code telemetry.gap} event, because missing batches may hide activity.</li>
 * </ol>
 * Each line must name the batch's own device and a time within the batch's hour (from {@link #MAX_SPAN} before
 * the seal to {@link #MAX_SKEW} after it); a line that does not is refused on its own, as a
 * {@code parse.failure} event about the device (the batch was signed, so the device really sent it).
 * Refused batches become {@code telemetry.refused} events with {@code COLLECTED} provenance: nothing in them is
 * proven, so the device they claim is a field, never an entity.
 */
public final class EndpointCollector extends CollectorBase {

    public static final String DATASET = "endpoint";
    public static final int MAX_BODY = 1024 * 1024;
    public static final int MAX_LINES = 5_000;
    public static final int MAX_LINE = 8_192;
    public static final int MAX_DEVICES = 100_000;
    public static final Duration MAX_AGE = Duration.ofHours(2);
    public static final Duration MAX_SPAN = Duration.ofMinutes(70);
    public static final Duration MAX_SKEW = Duration.ofMinutes(2);
    private static final JsonReader LINE = new JsonReader(new JsonLimits(MAX_LINE, 1, 2_048, 48, 1, 24, 64));

    /** One batch as it arrives from a device agent. */
    public record Batch(String deviceId, String keyId, long number, Instant sealedAt, String body, String signature) {
        public Batch {
            Objects.requireNonNull(deviceId, "deviceId");
            Objects.requireNonNull(keyId, "keyId");
            Objects.requireNonNull(sealedAt, "sealedAt");
            Objects.requireNonNull(body, "body");
            Objects.requireNonNull(signature, "signature");
        }
    }

    private final KeyRing keys;
    private final Map<String, Long> lastBatch = new HashMap<>();

    public EndpointCollector(String runId, KeyRing keys) {
        super(DATASET, "ep", runId);
        this.keys = Objects.requireNonNull(keys, "keys");
    }

    /**
     * Continues after a restart: the last accepted batch number of each device, from a trusted checkpoint
     * (the collector's own saved state or the audit trail), so batches seen before the restart stay used.
     */
    public synchronized void resume(Map<String, Long> lastAccepted) {
        if (lastBatch.size() + lastAccepted.size() > MAX_DEVICES) {
            throw new IllegalArgumentException("at most " + MAX_DEVICES + " devices");
        }
        lastAccepted.forEach((d, n) -> lastBatch.merge(Validate.id(d, "device"), n, Math::max));
    }

    /**
     * The last batch number used by each device, rebuilt from the verified audit trail (every event of an
     * accepted batch carries its number), for {@link #resume} after a restart: without it a batch captured before
     * the restart would be accepted again (red-team finding rD7).
     *
     * @param cursor     a keyed cursor from the start of the trail
     * @param maxRecords how many records to read at most
     * @throws IllegalStateException if the trail is broken or longer than {@code maxRecords}: the collector cannot
     *                               know which batches were used, so it must not start
     */
    public static Map<String, Long> lastBatches(dev.dwarpal.audit.AuditCursor cursor, long maxRecords) {
        Map<String, Long> last = new HashMap<>();
        long read = 0;
        while (true) {
            dev.dwarpal.audit.AuditCursor.Batch b = cursor.next(dev.dwarpal.audit.AuditSource.MAX_BATCH);
            if (b.problem().isPresent()) {
                throw new IllegalStateException("audit trail broken: used batch numbers unknown");
            }
            if (b.events().isEmpty()) {
                return Map.copyOf(last);
            }
            read += b.events().size();
            if (read > maxRecords) {
                throw new IllegalStateException("trail longer than " + maxRecords + " records");
            }
            for (dev.dwarpal.audit.AuditEvent a : b.events()) {
                if (!a.type().equals(dev.dwarpal.soc.SecurityEvents.RECORD_TYPE)
                        || !a.actor().equals(dev.dwarpal.soc.SecurityEvents.collectorActor(DATASET))) {
                    continue;
                }
                SecurityEvent e;
                try {
                    e = dev.dwarpal.soc.SecurityEvents.fromAudit(a).event();
                } catch (IllegalArgumentException malformed) {
                    continue;
                }
                long n = e.provenance() == SecurityEvent.Provenance.SIGNED_SENSOR
                        ? count(e.field("batch").orElse("")) : -1;
                Optional<Entity> d = e.first(Entity.Kind.DEVICE);
                if (n > 0 && d.isPresent() && (last.size() < MAX_DEVICES || last.containsKey(d.get().id()))) {
                    last.merge(d.get().id(), n, Math::max);
                }
            }
        }
    }

    /** The last accepted batch number of each device (save it to {@link #resume} after a restart). */
    public synchronized Map<String, Long> checkpoint() {
        return Map.copyOf(lastBatch);
    }

    /**
     * Takes one batch.
     *
     * @return how many events it produced (0 if the batch was refused; refusals are counted and kept)
     */
    public synchronized int offer(Batch b, Instant receivedAt) {
        Objects.requireNonNull(b, "batch");
        seen(receivedAt);
        String claimed = b.deviceId().length() <= 128 ? b.deviceId() : b.deviceId().substring(0, 128);
        if (b.body().length() > MAX_BODY || b.body().getBytes(StandardCharsets.UTF_8).length > MAX_BODY) {
            return refuseBatch(b, receivedAt, "body larger than " + MAX_BODY + " bytes", claimed);
        }
        String device;
        SignatureProof proof;
        try {
            device = Validate.id(b.deviceId(), "device");
            proof = new SignatureProof(b.keyId(), b.sealedAt(), b.signature());
        } catch (IllegalArgumentException e) {
            return refuseBatch(b, receivedAt, "malformed batch header", claimed);
        }
        byte[] message = SignedMessages.endpointTelemetry(device, b.number(), b.sealedAt(),
                Digests.sha256Hex(b.body()));
        KeyRing.Result r = keys.verify(KeyPurpose.DEVICE_AGENT, device, proof, message, receivedAt, MAX_AGE);
        if (!r.valid()) {
            return refuseBatch(b, receivedAt, "signature not accepted", claimed);
        }
        Long last = lastBatch.get(device);
        if (last == null && lastBatch.size() >= MAX_DEVICES) {
            return refuseBatch(b, receivedAt, "too many devices", claimed);
        }
        if (b.number() < 1 || (last != null && b.number() <= last)) {
            return refuseBatch(b, receivedAt, "batch number replayed or out of order", claimed);
        }
        lastBatch.put(device, b.number());
        List<Entity> deviceOnly = List.of(new Entity(Entity.Kind.DEVICE, device));
        int produced = 0;
        if (last != null && b.number() > last + 1) {
            enqueue(event(receivedAt, SecurityEvent.Category.SYSTEM, "telemetry.gap", SecurityEvent.EventOutcome.FAILURE,
                    SecurityEvent.Provenance.SIGNED_SENSOR, deviceOnly,
                    Map.of("missing", Long.toString(b.number() - last - 1), "batch", Long.toString(b.number()))));
            produced++;
        }
        String body = b.body();
        int lines = 0;
        int start = 0;
        while (start < body.length()) {
            int end = body.indexOf('\n', start);
            end = end < 0 ? body.length() : end;
            String line = body.substring(start, end);
            start = end + 1;
            if (line.isEmpty()) {
                continue;
            }
            if (++lines > MAX_LINES) {
                refuse(receivedAt, "parse.failure", "more than " + MAX_LINES + " lines", line,
                        SecurityEvent.Provenance.SIGNED_SENSOR, deviceOnly, Map.of());
                break;
            }
            try {
                if (enqueue(line(device, b, line))) {
                    produced++;
                }
            } catch (IllegalArgumentException | JsonException | DateTimeException bad) {
                String why = bad instanceof FirewallCollector.Malformed m ? m.getMessage() : "malformed line";
                refuse(receivedAt, "parse.failure", why, line, SecurityEvent.Provenance.SIGNED_SENSOR, deviceOnly,
                        Map.of("batch", Long.toString(b.number())));
            }
        }
        return produced;
    }

    private int refuseBatch(Batch b, Instant receivedAt, String reason, String claimed) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("claimedDevice", claimed);
        f.put("batch", Long.toString(b.number()));
        refuse(receivedAt, "telemetry.refused", reason, b.body(), SecurityEvent.Provenance.COLLECTED, List.of(), f);
        return 0;
    }

    private SecurityEvent line(String device, Batch b, String line) {
        if (line.length() > MAX_LINE) {
            throw new FirewallCollector.Malformed("line longer than " + MAX_LINE);
        }
        if (!(LINE.read(line) instanceof JsonValue.JObject o)) {
            throw new FirewallCollector.Malformed("line is not an object");
        }
        Map<String, String> raw = new LinkedHashMap<>();
        for (String k : o.keys()) {
            if (!(o.get(k).orElseThrow() instanceof JsonValue.JString s)) {
                throw new FirewallCollector.Malformed("values must be strings");
            }
            raw.put(k, s.value());
        }
        String ts = raw.remove("ts");
        String named = raw.remove("device");
        String type = raw.remove("type");
        if (ts == null || named == null || type == null) {
            throw new FirewallCollector.Malformed("ts, device and type are required");
        }
        if (!named.equals(device)) {
            throw new FirewallCollector.Malformed("line names another device");
        }
        Instant at = FirewallCollector.parseIso(ts);
        if (at.isBefore(b.sealedAt().minus(MAX_SPAN)) || at.isAfter(b.sealedAt().plus(MAX_SKEW))) {
            throw new FirewallCollector.Malformed("event time outside its batch");
        }
        String action;
        try {
            action = SecurityEvent.action(type);
        } catch (IllegalArgumentException e) {
            throw new FirewallCollector.Malformed("bad type");
        }
        List<Entity> entities = new ArrayList<>(4);
        entities.add(new Entity(Entity.Kind.DEVICE, device));
        String user = raw.remove("user");
        if (user != null) {
            addEntity(entities, Entity.Kind.SUBJECT, user);
        }
        Map<String, String> fields = new LinkedHashMap<>();
        if (user != null) {
            fields.put("user", user);
        }
        fields.put("batch", Long.toString(b.number()));
        int extra = 0;
        for (Map.Entry<String, String> x : raw.entrySet()) {
            if (reserved(x.getKey())) {
                throw new FirewallCollector.Malformed("reserved key in line");
            }
            if (!fieldName(x.getKey()) || fields.size() >= MAX_COPIED_FIELDS) {
                extra++;
                continue;
            }
            fields.put(x.getKey(), x.getValue());
        }
        if (extra > 0) {
            fields.put("extraFields", Integer.toString(extra));
        }
        String dst = fields.get("dst");
        if (dst != null && address(dst)) {
            addEntity(entities, Entity.Kind.IP, dst);
        }
        return event(at, category(action), action, SecurityEvent.EventOutcome.UNKNOWN,
                SecurityEvent.Provenance.SIGNED_SENSOR, entities, fields);
    }

    static SecurityEvent.Category category(String action) {
        if (action.startsWith("process.")) {
            return SecurityEvent.Category.PROCESS;
        }
        if (action.startsWith("network.") || action.startsWith("dns.")) {
            return SecurityEvent.Category.NETWORK;
        }
        if (action.startsWith("file.") || action.startsWith("usb.")) {
            return SecurityEvent.Category.FILE;
        }
        if (action.startsWith("login.") || action.startsWith("logon.")) {
            return SecurityEvent.Category.AUTHENTICATION;
        }
        return SecurityEvent.Category.SYSTEM;
    }
}

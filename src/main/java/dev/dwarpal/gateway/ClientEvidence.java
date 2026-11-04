package dev.dwarpal.gateway;

import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.domain.Evidence;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.edge.EdgeHttp;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.WireFormat;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonValue.JObject;
import dev.dwarpal.wire.JsonWriter;

import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * The {@code Dwarpal-Evidence} header: the device's claimed posture and the signed evidence (posture
 * report, key-bound MFA proof) that travel with a request on a session. Base64url of
 * {@code {"posture":{...},"evidence":{...}}}, with exactly the members and strictness of
 * {@link WireFormat}'s request object: the gateway parses it with {@link WireFormat#readRequest}, so the
 * two can never disagree. Like every {@code Dwarpal-} header it is removed before forwarding.
 */
public final class ClientEvidence {

    public static final String HEADER = "Dwarpal-Evidence";

    /** What the header carries. */
    public record Claims(DevicePosture posture, Evidence evidence) {
    }

    private static final NetworkContext NO_NETWORK = new NetworkContext("0.0.0.0", "AS0", "ZZ", 0, 0, 0);
    private static final Set<String> MEMBERS = Set.of("posture", "evidence");

    private ClientEvidence() {
    }

    public static String encode(DevicePosture posture, Evidence evidence) {
        JObject r = WireFormat.request(new EdgeRequest("x", Instant.EPOCH, "x", "x", posture, "x", Action.READ,
                NO_NETWORK, "x", evidence));
        JObject o = JsonValue.object().put("posture", r.get("posture").orElseThrow())
                .put("evidence", r.get("evidence").orElseThrow()).build();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(JsonWriter.bytes(o));
    }

    /** The claims, or empty for anything malformed (the request is then refused). */
    public static Optional<Claims> decode(String header) {
        if (header == null || !EdgeHttp.safeHeaderValue(header)) {
            return Optional.empty();
        }
        try {
            JsonValue v = new JsonReader().read(Base64.getUrlDecoder().decode(header));
            if (!(v instanceof JObject o) || !new HashSet<>(o.keys()).equals(MEMBERS)) {
                return Optional.empty();
            }
            JObject template = WireFormat.request(new EdgeRequest("x", Instant.EPOCH, "x", "x",
                    new DevicePosture(false, false, false, AssuranceLevel.SELF_REPORTED), "x",
                    Action.READ, NO_NETWORK, "x", Evidence.none()));
            JObject.Builder full = JsonValue.object();
            for (String k : template.keys()) {
                full.put(k, MEMBERS.contains(k) ? o.get(k).orElseThrow() : template.get(k).orElseThrow());
            }
            EdgeRequest parsed = WireFormat.readRequest(full.build());
            return Optional.of(new Claims(parsed.claimedPosture(), parsed.evidence()));
        } catch (JsonException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}

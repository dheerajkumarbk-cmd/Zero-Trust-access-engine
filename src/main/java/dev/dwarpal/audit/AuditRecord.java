package dev.dwarpal.audit;

import dev.dwarpal.domain.Validate;

import java.time.Instant;
import java.util.Objects;

/**
 * One entry of the tamper-evident audit chain.
 *
 * @param sequence    1, 2, 3, ... with no gaps
 * @param type        event type, e.g. ACCESS_DECISION, POLICY_INSTALLED
 * @param actor       who caused the event (the PDP, or an administrator id)
 * @param payloadJson event details as a JSON object
 * @param previousMac MAC of the previous record (all zeros for the first)
 * @param mac         HMAC-SHA256 over all fields above, including {@code previousMac}
 */
public record AuditRecord(long sequence, Instant at, String type, String actor, String payloadJson,
                          String previousMac, String mac) {

    public AuditRecord {
        if (sequence < 1) {
            throw new IllegalArgumentException("sequence starts at 1");
        }
        Objects.requireNonNull(at, "at");
        Validate.id(type, "type");
        Validate.id(actor, "actor");
        Objects.requireNonNull(payloadJson, "payloadJson");
        Objects.requireNonNull(previousMac, "previousMac");
        Objects.requireNonNull(mac, "mac");
    }

    /** One JSON line, ready for a file or a SIEM shipper. */
    public String toJsonLine() {
        return "{\"seq\":" + sequence + ",\"at\":\"" + at + "\",\"type\":\"" + type + "\",\"actor\":\"" + actor
                + "\",\"payload\":" + payloadJson + ",\"prev\":\"" + previousMac + "\",\"mac\":\"" + mac + "\"}";
    }
}

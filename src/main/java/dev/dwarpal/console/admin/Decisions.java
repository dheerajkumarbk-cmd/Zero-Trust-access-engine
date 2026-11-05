package dev.dwarpal.console.admin;

import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Reads the engine's {@code ACCESS_DECISION} records from the audit chain and explains them, once for the person who
 * was decided about and once for an administrator.
 *
 * <p>The person's view is the engine's own rule: {@code Decision.userMessage()} says nothing about which signal fired,
 * because "denied: new country" teaches an attacker which VPN exit to choose. So this page gives the outcome, the
 * reference, the time, the resource and what to do next, and nothing else: no policy name, no score, no factor, no
 * threshold, no address, no other person's data. The administrator's view has the record's full reasoning.
 */
final class Decisions {

    static final String TYPE = "ACCESS_DECISION";
    private static final JsonReader PAYLOAD = new JsonReader(new JsonLimits(1 << 20, 4, 1 << 16, 64, 8, 32, 512));

    /** One decision as the chain holds it. */
    record Row(long sequence, String requestId, Instant at, String subject, String device, String resource,
               String action, String outcome, boolean restricted, boolean deviceVerified, String policy,
               String policyVersion, String sourceIp, String pAttack, String signals, String reasons) {
    }

    /** What the person who was decided about may see. */
    record Explanation(String reference, Instant at, String outcome, String message, String resource, String action,
                       List<String> whatToDo) {
    }

    private Decisions() {
    }

    /** Decisions among {@code records}, oldest first; records that are not decisions or are malformed are skipped. */
    static List<Row> rows(List<AuditRecord> records) {
        List<Row> out = new ArrayList<>();
        for (AuditRecord r : records) {
            if (!r.type().equals(TYPE)) {
                continue;
            }
            try {
                out.add(row(r));
            } catch (RuntimeException malformed) {
                // skipped: a record we cannot read is never guessed at
            }
        }
        return out;
    }

    private static Row row(AuditRecord r) {
        Map<String, String> f = new LinkedHashMap<>();
        JsonValue.JObject o = (JsonValue.JObject) PAYLOAD.read(r.payloadJson());
        for (String k : o.keys()) {
            if (o.get(k).orElseThrow() instanceof JsonValue.JString s) {
                f.put(k, s.value());
            }
        }
        return new Row(r.sequence(), f.getOrDefault("requestId", ""), r.at(), f.getOrDefault("subject", ""),
                f.getOrDefault("device", ""), f.getOrDefault("resource", ""), f.getOrDefault("action", ""),
                f.getOrDefault("outcome", ""), Boolean.parseBoolean(f.getOrDefault("restricted", "false")),
                Boolean.parseBoolean(f.getOrDefault("deviceVerified", "false")), f.getOrDefault("policy", ""),
                f.getOrDefault("policyVersion", ""), f.getOrDefault("sourceIp", ""), f.getOrDefault("pAttack", ""),
                f.getOrDefault("signals", ""), f.getOrDefault("reasons", ""));
    }

    /** The newest decisions about one person, newest first. */
    static List<Row> about(List<Row> rows, String subject, int max) {
        List<Row> mine = new ArrayList<>();
        for (int i = rows.size() - 1; i >= 0 && mine.size() < max; i--) {
            if (rows.get(i).subject().equals(subject)) {
                mine.add(rows.get(i));
            }
        }
        return mine;
    }

    /** One decision by its reference, only if it is about {@code subject}: someone else's reference is "not found". */
    static Optional<Row> own(List<Row> rows, String subject, String reference) {
        for (int i = rows.size() - 1; i >= 0; i--) {
            Row r = rows.get(i);
            if (r.requestId().equals(reference)) {
                return r.subject().equals(subject) ? Optional.of(r) : Optional.empty();
            }
        }
        return Optional.empty();
    }

    static Optional<Row> any(List<Row> rows, String reference) {
        for (int i = rows.size() - 1; i >= 0; i--) {
            if (rows.get(i).requestId().equals(reference)) {
                return Optional.of(rows.get(i));
            }
        }
        return Optional.empty();
    }

    /** The outcome as the person sees it: ALLOW, ALLOW_LIMITED, STEP_UP or DENY (an unknown word is a DENY). */
    static String shown(Row r) {
        return switch (r.outcome()) {
            case "ALLOW" -> r.restricted() ? "ALLOW_LIMITED" : "ALLOW";
            case "ALLOW_LIMITED", "STEP_UP" -> r.outcome();
            default -> "DENY";
        };
    }

    /** The same words as {@code Decision.userMessage()}, built from the stored record. */
    static String message(Row r) {
        return switch (shown(r)) {
            case "ALLOW" -> "Access granted.";
            case "ALLOW_LIMITED" -> "Access granted with restrictions. Reference: " + r.requestId();
            case "STEP_UP" -> "Additional verification required. Reference: " + r.requestId();
            default -> "Access denied. Contact your administrator with reference: " + r.requestId();
        };
    }

    static Explanation explain(Row r) {
        List<String> todo = switch (shown(r)) {
            case "ALLOW" -> List.of("Nothing: this request was allowed.");
            case "ALLOW_LIMITED" -> List.of("The access works with limits, for example read-only.",
                    "If you need more, ask your administrator and quote the reference.");
            case "STEP_UP" -> List.of("Complete the extra verification (your second factor) when it is asked for, then try again.");
            default -> List.of("Contact your administrator and quote the reference.",
                    "Please do not keep trying: repeated attempts can lock the account.");
        };
        return new Explanation(r.requestId(), r.at(), shown(r), message(r), r.resource(), r.action(), todo);
    }
}

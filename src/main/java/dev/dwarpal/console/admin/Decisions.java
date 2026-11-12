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
 * <p>The person's view gives the outcome, a reason in plain words, the reference, the time, the resource and what to do
 * next. A person is owed the reason; an attacker must not learn the method. So the reason says what kind of thing stopped
 * the request, and never which signal fired: "denied: new country" would teach an attacker which VPN exit to choose. There
 * is no policy name, score, factor, threshold, address or other person's data here. The administrator's view has the
 * record's full reasoning.
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
    record Explanation(String reference, Instant at, String outcome, String message, String reason, String resource,
                       String action, List<String> whatToDo) {
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

    /** Why, as the person sees it: the kind of thing that decided this, never which check or signal. */
    static String reason(Row r) {
        String policy = r.policy();
        return switch (shown(r)) {
            case "ALLOW" -> "Your role allows this.";
            case "ALLOW_LIMITED" -> "You can use this with limits, because of the device you used.";
            case "STEP_UP" -> "This needs you to confirm who you are before it goes ahead.";
            default -> {
                if (policy.equals("default")) {
                    yield "Your role does not give you access to this.";
                } else if (policy.equals("unknown-subject")) {
                    yield "Your account was not found in the company directory.";
                } else if (policy.equals("unknown-resource")) {
                    yield "This is not something the company lists for access.";
                } else if (policy.startsWith("P-03")) {
                    yield "This needs a healthy company device, and yours could not be confirmed.";
                } else if (policy.startsWith("hard-gate:")) {
                    yield "Access from this account or device is blocked for now.";
                } else if (policy.equals("fail-closed") || policy.equals("engine-error") || policy.equals("audit-failure")) {
                    yield "A safety check could not run, so the request was refused. This is not your fault.";
                }
                yield "This request did not look like your usual activity, so it was stopped as a precaution.";
            }
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
        return new Explanation(r.requestId(), r.at(), shown(r), message(r), reason(r), r.resource(), r.action(), todo);
    }
}

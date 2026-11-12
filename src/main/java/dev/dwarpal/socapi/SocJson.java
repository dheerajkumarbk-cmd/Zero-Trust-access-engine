package dev.dwarpal.socapi;

import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.soar.CaseView;
import dev.dwarpal.soar.DeviceIsolation;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.ChainedEvent;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EntityRisk;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.Technique;
import dev.dwarpal.soc.Verdict;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonValue.JObject;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The SOC API's JSON: strict readers for the few bodies it accepts and writers for what it shows. Every request body
 * is an object with {@code "v":1} and exactly the listed members; anything else is refused.
 *
 * <pre>
 * note        {"v":1,"text":"..."}                                   (1 to 2,000 characters)
 * assignment  {"v":1,"assignee":"ben"}
 * verdict     {"v":1,"alertId","analystId","outcome":"TRUE_POSITIVE|FALSE_POSITIVE|BENIGN",
 *              "proof":{"keyId","signedAt","signature"}}
 * search      {"v":1,"query","from","to","limit"}                     (ISO-8601 times, limit 1 to 1,000)
 * </pre>
 */
final class SocJson {

    static final int MAX_TEXT = 4_000;
    static final int MAX_QUERY = 2_000;
    private static final int MAX_ID = 128;
    private static final int MAX_TIME = 40;

    private SocJson() {
    }

    record Search(String query, Instant from, Instant to, int limit) {
    }

    // ---- readers ----------------------------------------------------------------------------------------------

    static String readNote(JsonValue v) {
        JObject o = object(v);
        only(o, Set.of("v", "text"));
        return string(o, "text", MAX_TEXT);
    }

    static String readAssignment(JsonValue v) {
        JObject o = object(v);
        only(o, Set.of("v", "assignee"));
        return Validate.id(string(o, "assignee", MAX_ID), "assignee");
    }

    static Verdict readVerdict(JsonValue v) {
        JObject o = object(v);
        only(o, Set.of("v", "alertId", "analystId", "outcome", "proof"));
        String outcome = string(o, "outcome", 20);
        Verdict.Outcome out = switch (outcome) {
            case "TRUE_POSITIVE" -> Verdict.Outcome.TRUE_POSITIVE;
            case "FALSE_POSITIVE" -> Verdict.Outcome.FALSE_POSITIVE;
            case "BENIGN" -> Verdict.Outcome.BENIGN;
            default -> throw new JsonException("unknown outcome");
        };
        JObject p = object(member(o, "proof"));
        if (p.size() != 3) {
            throw new JsonException("proof has keyId, signedAt and signature");
        }
        SignatureProof proof = new SignatureProof(string(p, "keyId", MAX_ID), time(p, "signedAt"),
                string(p, "signature", SignatureProof.MAX_SIGNATURE_CHARS));
        return new Verdict(string(o, "alertId", MAX_ID), string(o, "analystId", MAX_ID), out, proof);
    }

    static Search readSearch(JsonValue v) {
        JObject o = object(v);
        only(o, Set.of("v", "query", "from", "to", "limit"));
        JsonValue limit = member(o, "limit");
        if (!(limit instanceof JsonValue.JNumber n)) {
            throw new JsonException("limit must be a number");
        }
        long l = n.asLong();
        if (l < 1 || l > 1_000) {
            throw new JsonException("limit is 1 to 1000");
        }
        JsonValue q = member(o, "query");
        if (!(q instanceof JsonValue.JString qs) || qs.value().length() > MAX_QUERY) {
            throw new JsonException("query must be text of at most " + MAX_QUERY + " characters");
        }
        return new Search(qs.value(), time(o, "from"), time(o, "to"), (int) l);
    }

    static Search readCounts(JsonValue v) {
        JObject o = object(v);
        only(o, Set.of("v", "query", "from", "to"));
        JsonValue q = member(o, "query");
        if (!(q instanceof JsonValue.JString qs) || qs.value().length() > MAX_QUERY) {
            throw new JsonException("query must be text of at most " + MAX_QUERY + " characters");
        }
        return new Search(qs.value(), time(o, "from"), time(o, "to"), 1);
    }

    // ---- writers ----------------------------------------------------------------------------------------------

    static JObject error(String text) {
        return JsonValue.object().put("error", text).build();
    }

    static JObject caseSummary(CaseView c) {
        JsonValue.JObject.Builder b = JsonValue.object()
                .put("id", c.id())
                .put("key", entity(c.key()))
                .put("state", c.state().name())
                .put("priority", c.priority().name())
                .put("score", num(c.score()))
                .put("openedAt", c.openedAt().toString())
                .put("deadline", c.deadline().toString())
                .put("acknowledgedAt", c.acknowledgedAt().<JsonValue>map(t -> JsonValue.str(t.toString()))
                        .orElse(JsonValue.nul()))
                .put("breached", JsonValue.bool(c.breached()))
                .put("assignee", c.assignee().<JsonValue>map(JsonValue::str).orElse(JsonValue.nul()))
                .put("holdsActions", JsonValue.bool(c.holdsActions()))
                .put("awaitingSecondAnalyst", JsonValue.bool(c.awaitingSecond()))
                .put("alerts", JsonValue.num(c.alerts().size()));
        return b.build();
    }

    static JObject caseDetail(CaseView c) {
        List<JsonValue> alerts = new ArrayList<>();
        for (RankedAlert r : c.alerts()) {
            alerts.add(ranked(r));
        }
        List<JsonValue> notes = new ArrayList<>();
        for (CaseView.Note n : c.notes()) {
            notes.add(JsonValue.object().put("id", n.id()).put("author", n.author()).put("at", n.at().toString())
                    .put("text", n.text()).build());
        }
        return JsonValue.object()
                .put("case", caseSummary(c))
                .put("entities", entities(c.entities()))
                .put("rankedAlerts", new JsonValue.JArray(alerts))
                .put("notes", new JsonValue.JArray(notes))
                .put("links", strings(c.links()))
                .build();
    }

    static JObject timeline(CaseView c) {
        List<JsonValue> out = new ArrayList<>();
        for (CaseView.TimelineEntry t : c.timeline()) {
            out.add(JsonValue.object().put("at", t.at().toString())
                    .put("kind", t.kind().name().toLowerCase(Locale.ROOT)).put("actor", t.actor())
                    .put("detail", t.detail()).build());
        }
        return JsonValue.object().put("case", c.id()).put("entries", new JsonValue.JArray(out))
                .put("dropped", JsonValue.num(c.timelineDropped())).build();
    }

    static JObject ranked(RankedAlert r) {
        Alert a = r.alert();
        List<JsonValue> techniques = new ArrayList<>();
        for (Technique t : r.techniques()) {
            techniques.add(JsonValue.object().put("id", t.id()).put("name", t.name()).put("tactic", t.tactic()).build());
        }
        List<JsonValue> evidence = new ArrayList<>();
        a.evidence().forEach(s -> evidence.add(JsonValue.num(s)));
        return JsonValue.object()
                .put("id", a.id()).put("rule", a.rule()).put("severity", a.severity().name())
                .put("raisedAt", a.raisedAt().toString()).put("count", JsonValue.num(a.count()))
                .put("summary", a.summary())
                .put("entities", entities(a.entities()))
                .put("evidence", new JsonValue.JArray(evidence))
                .put("priority", r.priority().name()).put("score", num(r.score()))
                .put("actionable", JsonValue.bool(r.actionable()))
                .put("techniques", new JsonValue.JArray(techniques))
                .put("reasons", strings(r.reasons()))
                .build();
    }

    static JObject risk(EntityRisk.RiskView v) {
        List<JsonValue> cs = new ArrayList<>();
        for (EntityRisk.Contribution c : v.contributions()) {
            List<JsonValue> ev = new ArrayList<>();
            c.evidence().forEach(s -> ev.add(JsonValue.num(s)));
            cs.add(JsonValue.object().put("source", c.source()).put("weight", num(c.weight()))
                    .put("at", c.at().toString()).put("evidence", new JsonValue.JArray(ev)).put("reason", c.reason())
                    .build());
        }
        return JsonValue.object().put("entity", entity(v.entity())).put("score", num(v.score()))
                .put("level", v.level().name()).put("asOf", v.asOf().toString())
                .put("contributions", new JsonValue.JArray(cs)).build();
    }

    static JObject event(ChainedEvent c) {
        SecurityEvent e = c.event();
        JsonValue.JObject.Builder fields = JsonValue.object();
        for (Map.Entry<String, String> f : e.fields().entrySet()) {
            fields.put(f.getKey(), f.getValue());
        }
        return JsonValue.object()
                .put("sequence", JsonValue.num(c.sequence())).put("recordedAt", c.recordedAt().toString())
                .put("id", e.id()).put("at", e.at().toString()).put("dataset", e.dataset())
                .put("category", e.category().name()).put("action", e.action()).put("outcome", e.outcome().name())
                .put("provenance", e.provenance().name()).put("entities", entities(e.entities()))
                .put("fields", fields.build()).build();
    }

    static JObject isolation(DeviceIsolation.Isolation i, Collection<String> visibleCases) {
        return JsonValue.object().put("device", i.deviceId()).put("state", i.state().name())
                .put("since", i.since().toString()).put("delivered", JsonValue.bool(i.delivered()))
                .put("overdue", JsonValue.bool(i.overdue())).put("cases", strings(visibleCases)).build();
    }

    static JsonValue entity(Entity e) {
        return JsonValue.object().put("kind", e.kind().name().toLowerCase(Locale.ROOT)).put("id", e.id()).build();
    }

    static JsonValue entities(Collection<Entity> es) {
        List<JsonValue> out = new ArrayList<>();
        es.stream().sorted(java.util.Comparator.comparing(Entity::kind).thenComparing(Entity::id))
                .forEach(e -> out.add(entity(e)));
        return new JsonValue.JArray(out);
    }

    static JsonValue strings(Collection<String> s) {
        List<JsonValue> out = new ArrayList<>();
        s.forEach(x -> out.add(JsonValue.str(x)));
        return new JsonValue.JArray(out);
    }

    /** A score or weight with one decimal (the reader's precision; no exponent forms). */
    static JsonValue num(double d) {
        if (!Double.isFinite(d)) {
            throw new IllegalArgumentException("not a finite number");
        }
        return new JsonValue.JNumber(String.format(Locale.ROOT, "%.1f", d));
    }

    // ---- strict helpers ---------------------------------------------------------------------------------------

    private static JObject object(JsonValue v) {
        if (!(v instanceof JObject o)) {
            throw new JsonException("an object was expected");
        }
        return o;
    }

    private static void only(JObject o, Set<String> keys) {
        if (o.size() != keys.size() || !Set.copyOf(o.keys()).equals(keys)) {
            throw new JsonException("members must be exactly " + new java.util.TreeSet<>(keys));
        }
        JsonValue ver = member(o, "v");
        if (!(ver instanceof JsonValue.JNumber n) || n.asLong() != 1) {
            throw new JsonException("unsupported version");
        }
    }

    private static JsonValue member(JObject o, String key) {
        return o.get(key).orElseThrow(() -> new JsonException("missing " + key));
    }

    private static String string(JObject o, String key, int max) {
        JsonValue v = member(o, key);
        if (!(v instanceof JsonValue.JString s) || s.value().isEmpty() || s.value().length() > max) {
            throw new JsonException(key + " must be text of 1 to " + max + " characters");
        }
        return s.value();
    }

    private static Instant time(JObject o, String key) {
        String s = string(o, key, MAX_TIME);
        try {
            return Instant.parse(s);
        } catch (DateTimeParseException e) {
            throw new JsonException(key + " must be an ISO-8601 instant");
        }
    }
}

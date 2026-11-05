package dev.dwarpal.lab.scenarios;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.lab.LabWorld;
import dev.dwarpal.soc.ChainedEvent;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.SecurityEvents;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * A recorded run as sanitised JSON, for a static replay site (part K) that has no server and no secrets.
 *
 * <p><b>What leaves, and what does not.</b> The export holds the lab's setting (seed, size, time range), the launches,
 * the ranked alerts with their reasons and techniques, and the events those alerts cite. It never holds keys,
 * certificates, audit MACs, the lab directory, the host's name or user name, or any value that looks like a secret:
 * <ul>
 *   <li>every person, device and address is replaced by a stable pseudonym ({@code person-1}, {@code device-1},
 *       {@code ip-1}); only addresses in the documentation ranges (RFC 5737) are kept;</li>
 *   <li>event fields are an allow-list, never a copy; long values are cut; values that look like keys are removed;</li>
 *   <li>a final scan of the finished text for key material, hashes and this host's own names fails the export
 *       ({@link Refused}) rather than letting it through.</li>
 * </ul>
 * The data is simulated; the export says so in its first field, as every figure in the lab does.
 */
public final class RunExport {

    public static final String FORMAT = "dwarpal-replay/1";
    public static final int MAX_ALERTS = 500;
    public static final int MAX_EVENTS = 3_000;
    public static final int MAX_EVIDENCE_PER_ALERT = 40;
    public static final int MAX_VALUE = 200;

    /** The export would have carried something it must not; nothing is returned. */
    public static final class Refused extends RuntimeException {
        private static final long serialVersionUID = 1L;

        Refused(String message) {
            super(message);
        }
    }

    private static final Set<String> FIELDS = Set.of("process", "parent", "cmd", "signer", "vendor", "op", "bytes",
            "dport", "proto", "rule", "path", "count", "share", "object", "app", "outcome", "policy", "signals",
            "auditType", "resource", "action", "missing", "reason", "lost");
    /** Fields that name a person, a device or an address: pseudonymised, never copied. */
    private static final Map<String, Entity.Kind> NAMING = Map.of("user", Entity.Kind.SUBJECT,
            "device", Entity.Kind.DEVICE, "dst", Entity.Kind.IP, "src", Entity.Kind.IP, "ip", Entity.Kind.IP);
    private static final Pattern HEX = Pattern.compile("[0-9a-fA-F]{32,}");
    private static final Pattern BASE64 = Pattern.compile("(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*[a-z])(?=[A-Za-z0-9+/]*[0-9])[A-Za-z0-9+/]{32,}={0,2}");
    private static final Pattern PEM = Pattern.compile("-----BEGIN");
    private static final Pattern IPV4 = Pattern.compile("\\b(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\b");

    private final Set<String> hostNames;

    public RunExport() {
        this(Set.of(System.getProperty("user.name", ""), System.getProperty("user.home", ""),
                System.getProperty("java.home", ""), hostName()));
    }

    /** For tests: the names of this host that must never appear in an export. */
    RunExport(Set<String> secretsOfTheHost) {
        Set<String> s = new TreeSet<>();
        for (String x : secretsOfTheHost) {
            if (x != null && x.length() >= 3) {
                s.add(x);
            }
        }
        this.hostNames = Set.copyOf(s);
    }

    private static String hostName() {
        try {
            return java.net.InetAddress.getLocalHost().getHostName();
        } catch (java.io.IOException | RuntimeException e) {
            return "";
        }
    }

    /** Stable pseudonyms in order of first appearance. */
    private static final class Names {
        private final Map<String, String> byKey = new LinkedHashMap<>();
        private final Map<Entity.Kind, Integer> counters = new java.util.EnumMap<>(Entity.Kind.class);

        String of(Entity.Kind kind, String id) {
            if (kind == Entity.Kind.IP && documentation(id)) {
                return id;
            }
            return byKey.computeIfAbsent(kind + "/" + id, k -> {
                int n = counters.merge(kind, 1, Integer::sum);
                return (kind == Entity.Kind.SUBJECT ? "person" : kind.name().toLowerCase(Locale.ROOT)) + "-" + n;
            });
        }

        /** Replaces every known real id inside free text (longest first, so "u1" never eats "u12"). */
        String scrub(String text) {
            String out = text;
            List<Map.Entry<String, String>> all = new ArrayList<>(byKey.entrySet());
            all.sort(Comparator.comparingInt((Map.Entry<String, String> e) -> e.getKey().length()).reversed());
            for (Map.Entry<String, String> e : all) {
                String real = e.getKey().substring(e.getKey().indexOf('/') + 1);
                if (!real.equals(e.getValue())) {
                    out = out.replaceAll("(?<![A-Za-z0-9._-])" + Pattern.quote(real) + "(?![A-Za-z0-9_-])",
                            java.util.regex.Matcher.quoteReplacement(e.getValue()));
                }
            }
            return out;
        }
    }

    private static boolean documentation(String ip) {
        return ip.startsWith("192.0.2.") || ip.startsWith("198.51.100.") || ip.startsWith("203.0.113.");
    }

    /** The run so far as JSON text. */
    public String export(LabWorld world, List<ScenarioRunner.Launch> launches) {
        Names names = new Names();
        // register every entity of the exported alerts first, so free text can be scrubbed consistently
        List<LabWorld.Raised> raised = new ArrayList<>(world.raised);
        if (raised.size() > MAX_ALERTS) {
            raised = raised.subList(raised.size() - MAX_ALERTS, raised.size());
        }
        Set<Long> wanted = new TreeSet<>();
        for (LabWorld.Raised r : raised) {
            r.alert().entities().forEach(e -> names.of(e.kind(), e.id()));
            r.alert().evidence().stream().limit(MAX_EVIDENCE_PER_ALERT).forEach(wanted::add);
        }
        for (ScenarioRunner.Launch l : launches) {
            if (!l.person().isEmpty()) {
                names.of(Entity.Kind.SUBJECT, l.person());
            }
            l.devices().forEach(d -> names.of(Entity.Kind.DEVICE, d));
        }
        List<JsonValue> alerts = new ArrayList<>();
        for (LabWorld.Raised r : raised) {
            RankedAlert ra = world.cases.ranked(r.alert().id()).orElse(null);
            JsonValue.JObject.Builder o = JsonValue.object().put("id", r.alert().id()).put("rule", r.alert().rule())
                    .put("engine", r.engine()).put("severity", r.alert().severity().name())
                    .put("raisedAt", r.alert().raisedAt().toString())
                    .put("count", JsonValue.num(r.alert().count()))
                    .put("summary", clean(names, r.alert().summary()))
                    .put("entities", array(r.alert().entities().stream().map(e -> (JsonValue) JsonValue.object()
                            .put("kind", e.kind().name().toLowerCase(Locale.ROOT)).put("ref", names.of(e.kind(), e.id()))
                            .build()).toList()))
                    .put("evidence", array(r.alert().evidence().stream().limit(MAX_EVIDENCE_PER_ALERT)
                            .map(n -> (JsonValue) JsonValue.num(n)).toList()));
            if (ra != null) {
                o.put("priority", ra.priority().name()).put("score", new JsonValue.JNumber(
                        String.format(Locale.ROOT, "%.1f", ra.score()))).put("actionable", JsonValue.bool(ra.actionable()))
                        .put("techniques", array(ra.techniques().stream().map(t -> (JsonValue) JsonValue.str(t.id()
                                + " " + t.name())).toList()))
                        .put("reasons", array(ra.reasons().stream().map(x -> (JsonValue) JsonValue.str(
                                clean(names, x))).toList()));
            }
            alerts.add(o.build());
        }
        List<JsonValue> events = events(world, wanted, names);
        List<JsonValue> runs = new ArrayList<>();
        for (ScenarioRunner.Launch l : launches) {
            runs.add(JsonValue.object().put("number", JsonValue.num(l.number())).put("scenario", l.scenario())
                    .put("person", l.person().isEmpty() ? "" : names.of(Entity.Kind.SUBJECT, l.person()))
                    .put("startsAt", l.startsAt().toString()).put("endsAt", l.endsAt().toString()).build());
        }
        JsonValue.JObject doc = JsonValue.object()
                .put("format", FORMAT)
                .put("data", "simulated organisation; every number measures consistency with the lab's own threat model, "
                        + "not real-world accuracy")
                .put("lab", JsonValue.object().put("seed", JsonValue.num(world.config.seed()))
                        .put("users", JsonValue.num(world.config.users()))
                        .put("scriptStart", world.scriptStart.toString()).put("now", world.now().toString()).build())
                .put("launches", array(runs)).put("alerts", array(alerts)).put("events", array(events)).build();
        String text = JsonWriter.write(doc);
        guard(text);
        return text;
    }

    private List<JsonValue> events(LabWorld world, Set<Long> wanted, Names names) {
        List<JsonValue> out = new ArrayList<>();
        if (wanted.isEmpty()) {
            return out;
        }
        AuditCursor cursor = AuditCursor.fromStart(world.org.sink, world.org.auditKey);
        while (out.size() < MAX_EVENTS) {
            AuditCursor.Batch b = cursor.next(5_000);
            if (b.events().isEmpty() || b.problem().isPresent()) {
                break;
            }
            for (AuditEvent a : b.events()) {
                if (!wanted.contains(a.sequence()) || out.size() >= MAX_EVENTS) {
                    continue;
                }
                ChainedEvent c;
                try {
                    c = SecurityEvents.fromAudit(a);
                } catch (IllegalArgumentException malformed) {
                    continue;
                }
                out.add(event(c, names));
            }
        }
        return out;
    }

    private JsonValue event(ChainedEvent c, Names names) {
        SecurityEvent e = c.event();
        JsonValue.JObject.Builder fields = JsonValue.object();
        for (Map.Entry<String, String> f : e.fields().entrySet()) {
            Entity.Kind kind = NAMING.get(f.getKey());
            if (kind != null) {
                fields.put(f.getKey(), names.of(kind, f.getValue()));
            } else if (FIELDS.contains(f.getKey())) {
                fields.put(f.getKey(), clean(names, f.getValue()));
            }
        }
        return JsonValue.object().put("seq", JsonValue.num(c.sequence())).put("at", e.at().toString())
                .put("dataset", e.dataset()).put("category", e.category().name()).put("action", e.action())
                .put("outcome", e.outcome().name()).put("provenance", e.provenance().name())
                .put("entities", array(e.entities().stream().map(x -> (JsonValue) JsonValue.object()
                        .put("kind", x.kind().name().toLowerCase(Locale.ROOT)).put("ref", names.of(x.kind(), x.id()))
                        .build()).toList()))
                .put("fields", fields.build()).build();
    }

    /** Free text: known ids replaced, other addresses pseudonymised, key-like runs removed, length cut. */
    private String clean(Names names, String text) {
        String t = names.scrub(text);
        java.util.regex.Matcher m = IPV4.matcher(t);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String ip = m.group();
            m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(documentation(ip) ? ip
                    : names.of(Entity.Kind.IP, ip)));
        }
        m.appendTail(sb);
        t = HEX.matcher(sb.toString()).replaceAll("[removed]");
        t = BASE64.matcher(t).replaceAll("[removed]");
        for (String h : hostNames) {
            t = t.replace(h, "[removed]");
        }
        return t.length() > MAX_VALUE ? t.substring(0, MAX_VALUE) : t;
    }

    /** The last line of defence: whatever got this far must hold nothing that looks like key material or this host. */
    private void guard(String text) {
        if (PEM.matcher(text).find() || HEX.matcher(text).find() || BASE64.matcher(text).find()) {
            throw new Refused("the export would carry key-like material and was refused");
        }
        for (String h : hostNames) {
            if (text.contains(h)) {
                throw new Refused("the export would carry this host's own name and was refused");
            }
        }
    }

    private static JsonValue array(List<JsonValue> items) {
        return new JsonValue.JArray(items);
    }

    /** The newest time in a launch list, for file names. */
    static Instant latest(List<ScenarioRunner.Launch> l) {
        return l.stream().map(ScenarioRunner.Launch::endsAt).max(Comparator.naturalOrder()).orElse(Instant.EPOCH);
    }
}

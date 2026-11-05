package dev.dwarpal.ueba;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.sim.SimTelemetry;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.SecurityEvents;

/**
 * Test helper standing in for part D's collectors: turns {@link SimTelemetry} into {@link SecurityEvent}s (a
 * deliberately small parser for the simulator's own formats, not a production normaliser) and writes them into the
 * organisation's audit chain as {@code SECURITY_EVENT} records under {@code collector:<dataset>}. Endpoint batches
 * become {@code SIGNED_SENSOR} only if the device agent's signature verifies; firewall and cloud lines are
 * {@code COLLECTED}. The ground-truth label of each record is kept beside the chain, never in it.
 */
final class SimTrail {

    record Label(SimTelemetry.Activity activity, String userId) {
    }

    final SimOrganisation org;
    final SimTelemetry telemetry;
    final Map<Long, Label> labels = new HashMap<>();
    int refused;

    private SimTrail(SimOrganisation org, SimTelemetry telemetry) {
        this.org = org;
        this.telemetry = telemetry;
    }

    /** The reference organisation (seed 7, 60 users) with its telemetry written into the chain. */
    static SimTrail reference() {
        SimOrganisation org = SimOrganisation.create(7, 60);
        SimTrail t = new SimTrail(org, SimTelemetry.of(org, org.traffic()));
        t.writeAll();
        return t;
    }

    AuditCursor cursor() {
        return AuditCursor.fromStart(org.sink, org.auditKey);
    }

    Instant end() {
        return SimOrganisation.DAY_ZERO.plus(Duration.ofDays(8));
    }

    private void writeAll() {
        Map<String, String> leases = telemetry.leases();
        for (SimTelemetry.Item i : telemetry.items()) {
            switch (i) {
                case SimTelemetry.RawLine r -> {
                    SecurityEvent e = r.source() == SimTelemetry.Source.FIREWALL ? firewall(r.text(), leases)
                            : cloud(r.text());
                    if (e == null) {
                        refused++;
                    } else {
                        write(e, r.at(), new Label(r.activity(), r.userId()));
                    }
                }
                case SimTelemetry.EndpointBatch b -> endpoint(b);
            }
        }
    }

    void write(SecurityEvent e, Instant recordedAt, Label label) {
        AuditRecord rec = org.audit.append(SecurityEvents.RECORD_TYPE, SecurityEvents.collectorActor(e.dataset()),
                recordedAt, SecurityEvents.toAuditFields(e));
        labels.put(rec.sequence(), label);
    }

    static SecurityEvent firewall(String line, Map<String, String> leases) {
        String[] t = line.split(" ");
        if (t.length < 9 || !t[0].startsWith("<")) {
            return null;
        }
        Map<String, String> kv = new LinkedHashMap<>();
        for (int k = 7; k < t.length; k++) {
            int eq = t[k].indexOf('=');
            if (eq > 0) {
                kv.put(t[k].substring(0, eq), t[k].substring(eq + 1));
            }
        }
        try {
            Instant at = Instant.parse(t[1]);
            Integer.parseInt(kv.getOrDefault("dport", "x"));
            Long.parseLong(kv.getOrDefault("bytes", "x"));
            String src = kv.get("src");
            List<Entity> ents = new ArrayList<>();
            ents.add(Entity.ip(src));
            if (leases.containsKey(src)) {
                ents.add(Entity.device(leases.get(src)));
            }
            Map<String, String> f = new LinkedHashMap<>();
            for (String n : List.of("dst", "dport", "bytes", "rule")) {
                f.put(n, kv.get(n));
            }
            return new SecurityEvent("fw-" + t[4], at, "firewall", SecurityEvent.Category.NETWORK, "network.flow",
                    "allow".equals(kv.get("action")) ? SecurityEvent.EventOutcome.SUCCESS
                            : SecurityEvent.EventOutcome.FAILURE, SecurityEvent.Provenance.COLLECTED, ents, f);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    /** A flat JSON object of string and number values, as the simulator writes it. */
    static Map<String, String> flatJson(String s) {
        String x = s.strip();
        if (!x.startsWith("{") || !x.endsWith("}")) {
            return null;
        }
        Map<String, String> m = new LinkedHashMap<>();
        for (String part : x.substring(1, x.length() - 1).split(",")) {
            int c = part.indexOf("\":");
            if (c < 1 || part.charAt(0) != '"') {
                return null;
            }
            String v = part.substring(c + 2);
            m.put(part.substring(1, c), v.startsWith("\"") && v.endsWith("\"") && v.length() >= 2
                    ? v.substring(1, v.length() - 1) : v);
        }
        return m;
    }

    static SecurityEvent cloud(String line) {
        Map<String, String> j = flatJson(line);
        if (j == null) {
            return null;
        }
        try {
            Map<String, String> f = new LinkedHashMap<>();
            f.put("object", j.get("object"));
            f.put("bytes", j.get("bytes"));
            f.put("share", j.get("share"));
            f.put("app", j.get("app"));
            return new SecurityEvent("cl-" + Integer.toHexString(line.hashCode()) + "-" + j.get("time").hashCode(),
                    Instant.parse(j.get("time")), "cloud", SecurityEvent.Category.CLOUD, j.get("op"),
                    SecurityEvent.EventOutcome.SUCCESS, SecurityEvent.Provenance.COLLECTED,
                    List.of(Entity.subject(j.get("user")), Entity.ip(j.get("ip"))), f);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private void endpoint(SimTelemetry.EndpointBatch b) {
        boolean signed = org.keys.verify(KeyPurpose.DEVICE_AGENT, b.deviceId(), b.proof(), b.signedMessage(), b.at(),
                Duration.ofMinutes(5)).valid();
        String[] lines = b.body().split("\n");
        for (int k = 0; k < lines.length; k++) {
            Map<String, String> j = flatJson(lines[k]);
            if (j == null) {
                refused++;
                continue;
            }
            String type = j.get("type");
            Map<String, String> f = new LinkedHashMap<>();
            for (Map.Entry<String, String> x : j.entrySet()) {
                if (!List.of("ts", "device", "user", "type").contains(x.getKey())) {
                    f.put(x.getKey(), x.getValue());
                }
            }
            SecurityEvent.Category c = type.startsWith("process") ? SecurityEvent.Category.PROCESS
                    : type.startsWith("network") ? SecurityEvent.Category.NETWORK : SecurityEvent.Category.FILE;
            SecurityEvent e = new SecurityEvent("ep-" + b.deviceId() + "-" + b.batch() + "-" + k, Instant.parse(j.get("ts")),
                    "endpoint", c, type, SecurityEvent.EventOutcome.SUCCESS,
                    signed ? SecurityEvent.Provenance.SIGNED_SENSOR : SecurityEvent.Provenance.COLLECTED,
                    List.of(Entity.subject(j.get("user")), Entity.device(b.deviceId())), f);
            write(e, b.at(), new Label(b.activities().get(k), b.userId()));
        }
    }
}

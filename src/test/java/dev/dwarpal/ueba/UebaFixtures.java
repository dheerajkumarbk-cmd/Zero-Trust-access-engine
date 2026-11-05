package dev.dwarpal.ueba;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.ChainedEvent;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.SecurityEvent;

/** Small builders for unit, abuse and red-team tests: events without an audit chain, numbered by hand. */
final class UebaFixtures {

    static final Instant T0 = Instant.parse("2026-10-01T00:00:00Z");

    private long seq;
    final List<Alert> alerts = new ArrayList<>();
    final List<Anomaly> anomalies = new ArrayList<>();
    final EvidenceIndex index = new EvidenceIndex(1_000_000);
    final UebaRisk risk = new UebaRisk(UebaRisk.Settings.reference(), index);
    final UebaEngine engine;

    UebaFixtures(UebaSettings settings, PeerGroups peers) {
        engine = new UebaEngine(settings, peers, index, a -> {
            anomalies.add(a);
            risk.add(a);
        }, alerts::add);
    }

    UebaFixtures() {
        this(UebaSettings.reference(), PeerGroups.none());
    }

    static SecurityEvent event(String id, Instant at, String action, SecurityEvent.Provenance p, List<Entity> ents,
                               String... kv) {
        Map<String, String> f = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            f.put(kv[i], kv[i + 1]);
        }
        return new SecurityEvent(id, at, p == SecurityEvent.Provenance.VERIFIED_AUDIT ? "dwarpal.audit" : "test",
                SecurityEvent.Category.CLOUD, action, SecurityEvent.EventOutcome.SUCCESS, p, ents, f);
    }

    /** Observes one event recorded at its own time. */
    List<Anomaly> see(Instant at, String action, SecurityEvent.Provenance p, Entity who, String... kv) {
        return see(at, at, action, p, who, kv);
    }

    List<Anomaly> see(Instant at, Instant recorded, String action, SecurityEvent.Provenance p, Entity who,
                      String... kv) {
        long s = ++seq;
        return engine.observe(new ChainedEvent(s, recorded, event("e" + s, at, action, p, List.of(who), kv)));
    }

    long lastSequence() {
        return seq;
    }

    /**
     * {@code days} ordinary days for {@code who}: 8 working hours from 09:00, {@code perHour} downloads of 1 MB each
     * hour, processes from a small set.
     */
    void ordinaryDays(Entity who, int fromDay, int days, int perHour) {
        String[] apps = {"code.exe", "chrome.exe", "teams.exe", "outlook.exe"};
        for (int d = fromDay; d < fromDay + days; d++) {
            for (int h = 9; h < 17; h++) {
                for (int k = 0; k < perHour; k++) {
                    Instant t = T0.plus(Duration.ofDays(d)).plus(Duration.ofHours(h)).plusSeconds(60L * k * 60 / perHour + 7);
                    see(t, "file.download", SecurityEvent.Provenance.COLLECTED, who, "bytes", "1000000");
                }
                Instant t = T0.plus(Duration.ofDays(d)).plus(Duration.ofHours(h)).plusSeconds(1800);
                see(t, "process.start", SecurityEvent.Provenance.SIGNED_SENSOR, who, "process", apps[(d + h) % apps.length],
                        "parent", "explorer.exe");
            }
        }
    }

    static Instant at(int day, int hour, int second) {
        return T0.plus(Duration.ofDays(day)).plus(Duration.ofHours(hour)).plusSeconds(second);
    }
}

package dev.dwarpal.siem;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertSink;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Test helpers: an audit trail with a key made at run time, and a list that collects alerts. */
final class Trails {

    static final Instant T0 = Instant.parse("2026-11-05T09:00:00Z");

    final SecretKey key = hmacKey();
    final InMemoryAuditSink sink = new InMemoryAuditSink();
    final AuditLog log = new AuditLog(key, sink);

    static SecretKey hmacKey() {
        try {
            return KeyGenerator.getInstance("HmacSHA256").generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static SecretKey aesKey() {
        try {
            KeyGenerator g = KeyGenerator.getInstance("AES");
            g.init(256);
            return g.generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** An ACCESS_DECISION as {@code AuditedDecisionPoint} writes it. */
    Trails decision(Instant at, String subject, String outcome, String ip, String... extra) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("requestId", "r-" + (sink.lastSequence() + 1));
        f.put("outcome", outcome);
        f.put("policy", "P-01-employees-internal-apps");
        f.put("subject", subject);
        f.put("device", "laptop-" + subject);
        f.put("resource", "wiki");
        f.put("action", "READ");
        f.put("sourceIp", ip);
        f.put("factors", "[RiskFactor[name=network-novelty, logLikelihoodRatio=-0.5, evidence=known IP " + ip + "]]");
        f.put("reasons", "test");
        for (int i = 0; i + 1 < extra.length; i += 2) {
            f.put(extra[i], extra[i + 1]);
        }
        log.append("ACCESS_DECISION", "pdp", at, f);
        return this;
    }

    Trails event(Instant at, String type, String actor, String... fields) {
        Map<String, String> f = new LinkedHashMap<>();
        for (int i = 0; i + 1 < fields.length; i += 2) {
            f.put(fields[i], fields[i + 1]);
        }
        log.append(type, actor, at, f);
        return this;
    }

    DetectionEngine engine(AlertSink alerts) {
        return new DetectionEngine(sink, key, alerts, Optional::empty, DetectionEngine.Settings.defaults());
    }

    /** Collects alerts; refuses while {@link #refusing} is set. */
    static final class Collected implements AlertSink {
        final List<Alert> alerts = new ArrayList<>();
        boolean refusing;

        @Override
        public boolean raise(Alert alert) {
            if (refusing) {
                return false;
            }
            alerts.add(alert);
            return true;
        }

        List<Alert> of(String rule) {
            return alerts.stream().filter(a -> a.rule().equals(rule)).toList();
        }
    }
}

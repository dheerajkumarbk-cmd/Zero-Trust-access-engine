package dev.dwarpal.siem.platform;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertSink;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.SecurityEvent;
import dev.dwarpal.soc.SecurityEvents;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Small helpers for part D's tests: a keyed trail, events, an alert list. */
final class Fx {

    static final Instant T0 = Instant.parse("2026-11-04T10:00:00Z");

    private Fx() {
    }

    static SecretKey key() {
        try {
            return KeyGenerator.getInstance("HmacSHA256").generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A trail: its key, sink and writer. */
    static final class Trail {
        final SecretKey key = key();
        final InMemoryAuditSink sink = new InMemoryAuditSink();
        final AuditLog log = new AuditLog(key, sink);

        AuditCursor cursor() {
            return AuditCursor.fromStart(sink, key);
        }

        /** Writes a collected event as its collector would. */
        long collected(SecurityEvent e, Instant now) {
            return log.append(SecurityEvents.RECORD_TYPE, SecurityEvents.collectorActor(e.dataset()), now,
                    SecurityEvents.toAuditFields(e)).sequence();
        }

        /** Writes one of Dwarpal's own records. */
        long nativeRecord(String type, String actor, Instant at, Map<String, String> fields) {
            return log.append(type, actor, at, fields).sequence();
        }

        long decision(String outcome, String subject, String device, String ip, Instant at) {
            return nativeRecord("ACCESS_DECISION", "pdp", at, Map.of("outcome", outcome, "subject", subject,
                    "device", device, "sourceIp", ip, "policy", "default", "resource", "app-1"));
        }
    }

    static SecurityEvent event(String id, Instant at, String dataset, String action, SecurityEvent.Provenance p,
                               List<Entity> entities, Map<String, String> fields) {
        return new SecurityEvent(id, at, dataset, SecurityEvent.Category.SYSTEM, action,
                SecurityEvent.EventOutcome.UNKNOWN, p, entities, fields);
    }

    /** An alert sink that keeps everything (or refuses while {@code refusing}). */
    static final class Alerts implements AlertSink {
        final List<Alert> list = new ArrayList<>();
        boolean refusing;

        @Override
        public boolean raise(Alert alert) {
            if (refusing) {
                return false;
            }
            list.add(alert);
            return true;
        }

        List<Alert> of(String rule) {
            return list.stream().filter(a -> a.rule().equals(rule)).toList();
        }
    }
}

package dev.dwarpal.response;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditSource;
import dev.dwarpal.casb.DataGuard;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.guard.RateLimiter;
import dev.dwarpal.pip.SignalFeed;

import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Feeds the SaaS data guard's findings back as risk evidence: every {@code casb.dlp} audit record adds
 * a decaying watch weight to the person who uploaded, so repeated attempts raise their risk and a
 * single mistake fades (half-life {@link #HALF_LIFE}).
 *
 * <p>Weights (assumptions, not calibrated; part C's calibration can replace them): a blocked upload
 * x4, a redacted one x2, one let through with audit x1.5; doubled for RESTRICTED data, x1.5 for
 * CONFIDENTIAL. DLP alone never takes a person above {@link #MAX_DLP_LOG_LR} (x100): it raises risk
 * towards step-up, but cannot by itself put someone at the deny level of a confirmed attack.
 *
 * <p>The trail is read through a keyed {@link AuditCursor}, so only records with a valid MAC count: an
 * attacker who can write to the audit store but lacks the key cannot raise an innocent person's risk.
 * At the first break the feedback stops for good and reports it. Updates are limited per person
 * ({@link #UPDATES_PER_HOUR}), and bounded through the {@link SignalLedger}.
 */
public final class DlpFeedback {

    public static final String ACTOR = "soc-dlp-feedback";
    public static final Duration HALF_LIFE = Duration.ofDays(7);
    public static final double MAX_DLP_LOG_LR = Math.log(100);
    public static final int UPDATES_PER_HOUR = 10;
    public static final int MAX_BATCH = 1_000;

    /** What one poll did. */
    public record Poll(int read, int applied, int skipped, int limited, Optional<String> problem) {
        public Poll {
            Objects.requireNonNull(problem, "problem");
        }
    }

    private final AuditCursor cursor;
    private final SignalLedger ledger;
    private final Clock clock;
    private final RateLimiter perPerson = new RateLimiter(UPDATES_PER_HOUR, Duration.ofHours(1), 100_000);

    /** Reads the trail from the start, checking every MAC with {@code auditKey}. */
    public DlpFeedback(AuditSource source, SecretKey auditKey, SignalLedger ledger, Clock clock) {
        this(AuditCursor.fromStart(source, Objects.requireNonNull(auditKey, "auditKey")), ledger, clock);
    }

    /** Resumes after a head verified earlier (a saved {@link #checkpoint()}). */
    public DlpFeedback(AuditSource source, SecretKey auditKey, AuditLog.Head verified, SignalLedger ledger, Clock clock) {
        this(AuditCursor.resume(source, Objects.requireNonNull(auditKey, "auditKey"), verified), ledger, clock);
    }

    private DlpFeedback(AuditCursor cursor, SignalLedger ledger, Clock clock) {
        this.cursor = cursor;
        this.ledger = Objects.requireNonNull(ledger, "ledger");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Reads up to {@code max} new records (at most {@link #MAX_BATCH}) and applies the DLP ones. */
    public synchronized Poll poll(int max) {
        AuditCursor.Batch b = cursor.next(Math.clamp(max, 1, MAX_BATCH));
        int applied = 0;
        int skipped = 0;
        int limited = 0;
        for (AuditEvent e : b.events()) {
            if (!DataGuard.AUDIT_TYPE.equals(e.type())) {
                continue;
            }
            double w = weight(e);
            String subject = e.actor();
            if (w <= 0 || !validId(subject)) {
                skipped++;
                continue;
            }
            double room = MAX_DLP_LOG_LR - ledger.weightOf(SignalLedger.DLP, SignalFeed.Kind.SUBJECT, subject);
            double add = Math.min(w, room);
            if (add < SignalFeed.FADED_LOG_LR) {
                skipped++;
                continue;
            }
            Instant now = clock.instant();
            if (!perPerson.tryAcquire(subject, now)) {
                limited++;
                continue;
            }
            if (ledger.watch(SignalLedger.DLP, SignalFeed.Kind.SUBJECT, subject, add, HALF_LIFE, ACTOR,
                    "DLP " + e.field("action").orElse("?") + " at audit record " + e.sequence())) {
                applied++;
            } else {
                skipped++;
            }
        }
        return new Poll(b.events().size(), applied, skipped, limited, b.problem());
    }

    /** Where to resume after a restart (store it where the audit writer cannot change it). */
    public AuditLog.Head checkpoint() {
        return cursor.checkpoint();
    }

    /** Why reading stopped, if the trail broke. */
    public Optional<String> broken() {
        return cursor.broken();
    }

    /** The log-likelihood ratio one DLP record adds, before the cap; 0 for a record it does not understand. */
    static double weight(AuditEvent e) {
        double base = switch (e.field("action").orElse("")) {
            case "BLOCK" -> Math.log(4);
            case "REDACT" -> Math.log(2);
            case "AUDIT" -> Math.log(1.5);
            default -> 0;
        };
        double scale = switch (e.field("classification").orElse("")) {
            case "RESTRICTED" -> 2;
            case "CONFIDENTIAL" -> 1.5;
            default -> 1;
        };
        return base * scale;
    }

    private static boolean validId(String id) {
        try {
            Validate.id(id, "subject");
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }
}

package dev.dwarpal.session;

import dev.dwarpal.behavior.FailureLog;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.guard.NonceCache;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The login service's way into the failure log, which drives the brute-force, password-spray and
 * attack-surge scorers.
 *
 * <p>Those scorers make the engine stricter for the accounts and addresses involved, so whoever can
 * write failures can lock users out. Only the identity provider may: each report must carry its
 * signature (an {@code IDENTITY_PROVIDER} key, domain-separated from its login proofs), be recent,
 * and be used once. A replayed report would otherwise count as many failures.
 */
public final class FailureReportReceiver {

    /** A signed report older than this is refused. */
    public static final Duration MAX_REPORT_AGE = Duration.ofMinutes(5);

    /** One failed login, as the identity provider saw it. */
    public record FailureReport(String reportId, String subjectId, String ip, Instant failedAt) {
        public FailureReport {
            Validate.id(reportId, "report.id");
            Validate.id(subjectId, "report.subjectId");
            Validate.id(ip, "report.ip");
            Objects.requireNonNull(failedAt, "report.failedAt");
        }
    }

    public record Result(boolean accepted, String reason) {
    }

    private final KeyRing keys;
    private final FailureLog failures;
    private final Clock clock;
    private final NonceCache seen;
    private final AtomicLong rejected = new AtomicLong();

    public FailureReportReceiver(KeyRing keys, FailureLog failures, Clock clock, int capacity) {
        this.keys = Objects.requireNonNull(keys, "keys");
        this.failures = Objects.requireNonNull(failures, "failures");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.seen = new NonceCache(MAX_REPORT_AGE.plus(KeyRing.MAX_CLOCK_SKEW), capacity);
    }

    public Result accept(FailureReport report, SignatureProof proof) {
        Objects.requireNonNull(report, "report");
        Objects.requireNonNull(proof, "proof");
        Instant now = clock.instant();
        KeyRing.Result r = keys.verify(KeyPurpose.IDENTITY_PROVIDER, null, proof,
                SignedMessages.authenticationFailure(report.reportId(), report.subjectId(), report.ip(),
                        report.failedAt(), proof.signedAt()),
                now, MAX_REPORT_AGE);
        if (!r.valid()) {
            return reject("signature rejected: " + r.reason());
        }
        if (report.failedAt().isAfter(proof.signedAt().plus(KeyRing.MAX_CLOCK_SKEW))) {
            return reject("failure dated after its own report");
        }
        if (Duration.between(report.failedAt(), now).compareTo(FailureLog.RETENTION) > 0) {
            return reject("failure older than the failure log keeps");
        }
        if (!seen.firstUse(report.reportId(), now)) {
            return reject("report already received (replay) or replay cache full");
        }
        failures.recordFailure(report.subjectId(), report.ip(), report.failedAt());
        return new Result(true, "recorded");
    }

    public long rejected() {
        return rejected.get();
    }

    private Result reject(String reason) {
        rejected.incrementAndGet();
        return new Result(false, reason);
    }
}

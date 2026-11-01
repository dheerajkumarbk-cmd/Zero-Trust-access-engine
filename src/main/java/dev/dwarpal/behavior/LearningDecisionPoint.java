package dev.dwarpal.behavior;

import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.risk.SignalSnapshot;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Decorator that turns decisions into behavioural baselines, guarded against poisoning.
 *
 * <p>If the engine learned from every request, an attacker could make their own country, network
 * and device "familiar" simply by trying repeatedly. Learning rules:
 * <ol>
 *   <li><b>Only a full ALLOW teaches.</b> STEP_UP, DENY and restricted (read-only) sessions never
 *       enter the baseline; nor does a decision made while a signal source was down. A full ALLOW
 *       means the engine was either already confident, or the user just passed verified, fresh MFA
 *       strong enough for the risk, so a legitimately travelling user's new location is learned
 *       after they prove themselves.</li>
 *   <li><b>Trust needs more.</b> A "good" reputation event is recorded only when the request was
 *       low-risk <em>before</em> any step-up ({@code P(attack) <= goodEventMaxRisk}).</li>
 *   <li><b>No automatic bad marks on users.</b> Ordinary DENYs are not held against the subject:
 *       anyone who knows a username can generate DENYs in that name, so doing so would let an
 *       attacker destroy a victim's reputation (a lock-out denial of service). Bad events come from
 *       near-certain evidence only: a honeytoken hit marks the <em>device</em>, and only a device that
 *       proved its identity; analysts confirm the rest.</li>
 *   <li><b>Devices by proof, not by name.</b> Unproven devices are learned as one "unverified" value
 *       and never earn device reputation.</li>
 *   <li><b>Only fresh requests teach.</b> A request whose timestamp is more than {@code maxSkew}
 *       from this component's own clock is not learned. Otherwise one future-dated ALLOW would
 *       become the user's "last login" and silence impossible-travel detection for them
 *       (found by red-teaming; regression test in BehaviorStoresTest).</li>
 * </ol>
 * Learning never changes the decision; if it fails, the decision still stands.
 */
public final class LearningDecisionPoint implements DecisionPoint {

    private final DecisionPoint delegate;
    private final InMemoryBehaviorHistory history;
    private final TrustLedger trust;
    private final double goodEventMaxRisk;
    private final Clock clock;
    private final Duration maxSkew;
    private final AtomicLong learningFailures = new AtomicLong();
    private final AtomicLong rejectedTimestamps = new AtomicLong();

    public LearningDecisionPoint(DecisionPoint delegate, InMemoryBehaviorHistory history, TrustLedger trust,
                                 double goodEventMaxRisk, Clock clock, Duration maxSkew) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.history = Objects.requireNonNull(history, "history");
        this.trust = Objects.requireNonNull(trust, "trust");
        this.goodEventMaxRisk = Validate.probability(goodEventMaxRisk, "goodEventMaxRisk");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.maxSkew = Objects.requireNonNull(maxSkew, "maxSkew");
        if (maxSkew.isNegative() || maxSkew.isZero()) {
            throw new IllegalArgumentException("maxSkew must be positive");
        }
    }

    @Override
    public Decision decide(AccessRequest request, SignalSnapshot signals) {
        Decision d = delegate.decide(request, signals);
        try {
            learn(request, d);
        } catch (RuntimeException e) {
            learningFailures.incrementAndGet();
        }
        return d;
    }

    private void learn(AccessRequest request, Decision d) {
        if (Duration.between(clock.instant(), request.timestamp()).abs().compareTo(maxSkew) > 0) {
            rejectedTimestamps.incrementAndGet();
            return;
        }
        if (d.outcome() == Outcome.DENY && "hard-gate:honeytoken".equals(d.matchedPolicyId())) {
            if (d.deviceVerified()) {
                // Only a proven device is marked: otherwise an attacker could use a honeytoken while
                // typing a victim's device id and get the victim's laptop flagged.
                trust.recordBad(TrustLedger.deviceKey(request.device().id()), request.timestamp());
            }
            return;
        }
        if (d.outcome() != Outcome.ALLOW || d.restricted() || d.risk().degraded()) {
            return;
        }
        history.record(LoginEvent.of(request, d.deviceVerified()));
        if (d.risk().posteriorAttack() <= goodEventMaxRisk) {
            trust.recordGood(TrustLedger.subjectKey(request.subject().id()), request.timestamp());
            if (d.deviceVerified()) {
                trust.recordGood(TrustLedger.deviceKey(request.device().id()), request.timestamp());
            }
        }
    }

    /** Requests not learned because their timestamp was stale or future-dated. */
    public long rejectedTimestamps() {
        return rejectedTimestamps.get();
    }

    /** Operational metric: learning errors are not security failures, but they should be visible. */
    public long learningFailures() {
        return learningFailures.get();
    }
}

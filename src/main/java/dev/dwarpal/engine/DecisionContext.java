package dev.dwarpal.engine;

import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.risk.RiskAssessment;
import dev.dwarpal.risk.SignalSnapshot;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Mutable state passed along the decision pipeline. It only ever becomes stricter:
 * {@link #escalate} can raise the outcome but never lower it, and once a stage restricts the
 * session the restriction cannot be removed by a later stage.
 */
final class DecisionContext {

    private AccessRequest request;
    private final SignalSnapshot signals;
    private final List<String> reasons = new ArrayList<>();
    private Outcome outcome = Outcome.ALLOW;
    private boolean restricted;
    private RiskAssessment risk;
    private String matchedPolicyId = "none";
    private boolean terminated;
    private AuthenticationContext verifiedAuthentication;

    DecisionContext(AccessRequest request, SignalSnapshot signals, RiskAssessment initialRisk) {
        this.request = request;
        this.signals = signals;
        this.risk = initialRisk;
    }

    AccessRequest request() {
        return request;
    }

    /** Used only by attribute resolution to swap claimed attributes for authoritative ones. */
    void request(AccessRequest resolved) {
        this.request = resolved;
    }

    SignalSnapshot signals() {
        return signals;
    }

    Outcome outcome() {
        return outcome;
    }

    boolean restricted() {
        return restricted;
    }

    RiskAssessment risk() {
        return risk;
    }

    void risk(RiskAssessment assessment) {
        this.risk = assessment;
    }

    String matchedPolicyId() {
        return matchedPolicyId;
    }

    void matchedPolicyId(String id) {
        this.matchedPolicyId = id;
    }

    List<String> reasons() {
        return reasons;
    }

    boolean terminated() {
        return terminated;
    }

    void escalate(Outcome candidate, String reason) {
        if (candidate == Outcome.ALLOW_LIMITED) {
            restricted = true;
        }
        outcome = Outcome.mostRestrictive(outcome, candidate);
        reasons.add(reason);
    }

    /** Adds an explanation line without changing the outcome. */
    void note(String reason) {
        reasons.add(reason);
    }

    Optional<AuthenticationContext> verifiedAuthentication() {
        return Optional.ofNullable(verifiedAuthentication);
    }

    /** Set only by evidence verification, after the identity provider's signature checked out. */
    void verifiedAuthentication(AuthenticationContext auth) {
        this.verifiedAuthentication = auth;
    }

    /**
     * The single controlled exception to monotonicity: a STEP_UP whose requirement is already met
     * by a verified, fresh authentication becomes ALLOW (or ALLOW_LIMITED if restricted).
     */
    void satisfyStepUp(String reason) {
        if (outcome != Outcome.STEP_UP) {
            throw new IllegalStateException("only a STEP_UP can be satisfied, outcome is " + outcome);
        }
        outcome = restricted ? Outcome.ALLOW_LIMITED : Outcome.ALLOW;
        reasons.add(reason);
    }

    /** Final answer; no later stage runs. */
    void terminate(Outcome finalOutcome, String policyId, String reason) {
        escalate(finalOutcome, reason);
        matchedPolicyId = policyId;
        terminated = true;
    }
}

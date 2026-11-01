package dev.dwarpal.audit;

import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.risk.SignalSnapshot;

import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Decorator that records every decision in the audit chain: the glass-box guarantee that any
 * decision can be reconstructed and explained later, with proof it was not edited.
 *
 * <p>No audit, no access: if the record cannot be written, the request is denied. An access
 * control system that keeps granting access while its audit trail is down gives an attacker a
 * way to act unseen (fail-secure audit, as in Common Criteria FAU_STG.4 and OWASP ASVS V7).
 *
 * <p>The record time comes from the PDP's own clock, not from the request, which the requester
 * influences; the request time is kept as a separate field.
 */
public final class AuditedDecisionPoint implements DecisionPoint {

    public static final String ACTOR = "pdp";

    private final DecisionPoint delegate;
    private final AuditLog audit;
    private final Clock clock;

    public AuditedDecisionPoint(DecisionPoint delegate, AuditLog audit, Clock clock) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public Decision decide(AccessRequest request, SignalSnapshot signals) {
        Decision d = delegate.decide(request, signals);
        try {
            audit.append("ACCESS_DECISION", ACTOR, clock.instant(), fields(request, d));
            return d;
        } catch (RuntimeException e) {
            List<String> reasons = new ArrayList<>(d.reasons());
            reasons.add("audit trail unavailable (" + e.getClass().getSimpleName() + "); failing closed");
            return new Decision(d.requestId(), Outcome.DENY, d.restricted(), d.deviceVerified(), "audit-failure",
                    d.policyVersion(),
                    d.risk(), reasons, d.decidedAt());
        }
    }

    private static Map<String, String> fields(AccessRequest r, Decision d) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("requestId", d.requestId());
        f.put("requestTime", d.decidedAt().toString());
        f.put("outcome", d.outcome().name());
        f.put("restricted", Boolean.toString(d.restricted()));
        f.put("policy", d.matchedPolicyId());
        f.put("policyVersion", d.policyVersion());
        f.put("pAttack", String.format(Locale.ROOT, "%.6f", d.risk().posteriorAttack()));
        f.put("subject", r.subject().id());
        f.put("device", r.device().id());
        f.put("deviceVerified", Boolean.toString(d.deviceVerified()));
        f.put("resource", r.resource().id());
        f.put("action", r.action().name());
        f.put("sourceIp", r.network().ip());
        f.put("pep", r.pepRegion());
        f.put("factors", d.risk().factors().toString());
        f.put("reasons", String.join(" | ", d.reasons()));
        return f;
    }
}

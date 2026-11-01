package dev.dwarpal.decision;

import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.risk.RiskAssessment;
import dev.dwarpal.risk.RiskFactor;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * The Policy Engine's answer, with its full reasoning.
 *
 * <p>{@code restricted} is an obligation that survives escalation: if any policy limited the
 * session (read-only, no download), a later STEP_UP does not lift that limit. The PEP and Policy
 * Administrator must honour it even after the user passes MFA.
 *
 * <p>There are two views on purpose: the requester gets a generic message plus a reference id,
 * because "denied: new country" teaches an attacker which VPN exit to pick. The analyst view has
 * every factor and the matching policy. Reasons are sanitised because they can quote input.
 */
public record Decision(String requestId, Outcome outcome, boolean restricted, String matchedPolicyId,
                       String policyVersion, RiskAssessment risk, List<String> reasons, Instant decidedAt) {

    public static final int MAX_REASON_LENGTH = 512;

    public Decision {
        Validate.id(requestId, "decision.requestId");
        Objects.requireNonNull(outcome, "decision.outcome");
        Objects.requireNonNull(matchedPolicyId, "decision.matchedPolicyId");
        Objects.requireNonNull(policyVersion, "decision.policyVersion");
        Objects.requireNonNull(risk, "decision.risk");
        reasons = reasons.stream().map(r -> Sanitize.text(r, MAX_REASON_LENGTH)).toList();
        Objects.requireNonNull(decidedAt, "decision.decidedAt");
        if (outcome == Outcome.ALLOW && restricted) {
            throw new IllegalArgumentException("a restricted decision cannot be a plain ALLOW");
        }
    }

    /** Safe to show the requester: reveals nothing about which signal fired. */
    public String userMessage() {
        return switch (outcome) {
            case ALLOW -> "Access granted.";
            case ALLOW_LIMITED -> "Access granted with restrictions. Reference: " + requestId;
            case STEP_UP -> "Additional verification required. Reference: " + requestId;
            case DENY -> "Access denied. Contact your administrator with reference: " + requestId;
        };
    }

    /** Full explanation for the SOC analyst console. Never shown to the requester. */
    public String analystReport() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format(Locale.ROOT, "[%s] %s%s  policy=%s@%s  P(attack)=%.4f (prior %.4f)%n",
                requestId, outcome, restricted ? " +RESTRICTED" : "", Sanitize.text(matchedPolicyId, 128),
                Sanitize.text(policyVersion, 128), risk.posteriorAttack(), risk.priorAttack()));
        for (RiskFactor f : risk.factors()) {
            sb.append(String.format(Locale.ROOT, "  %+.3f  %-24s x%.2f  %s%n",
                    f.logLikelihoodRatio(), f.name(), f.likelihoodRatio(), f.evidence()));
        }
        for (String failed : risk.failedScorers()) {
            sb.append("  !  signal unavailable: ").append(Sanitize.text(failed, 128)).append(System.lineSeparator());
        }
        for (String reason : reasons) {
            sb.append("  -> ").append(reason).append(System.lineSeparator());
        }
        return sb.toString();
    }
}

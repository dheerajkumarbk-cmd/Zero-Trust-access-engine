package dev.dwarpal.pam;

import dev.dwarpal.domain.AuthMethod;

import java.time.Duration;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * Limits of privileged access.
 *
 * @param maxElevation       longest just-in-time elevation that may be requested (at most 8 h)
 * @param requestTtl         a request nobody approves within this time lapses
 * @param approvalMaxAge     an approval, review or break-glass signature older than this is refused
 * @param mfaMaxAge          the requester's MFA must be at most this old
 * @param requestMethods     authenticators accepted for requesting privilege (phishing-resistant only by default)
 * @param breakGlassDuration how long an emergency elevation lasts
 * @param requestsPerHour    elevation requests per subject per hour
 * @param approvalsPerHour   approval attempts per approver per hour
 * @param breakGlassPerDay   break-glass uses per account per day
 * @param maxPending         bound on open requests
 * @param maxGrants          bound on active grants
 */
public record PamSettings(Duration maxElevation, Duration requestTtl, Duration approvalMaxAge, Duration mfaMaxAge,
                          Set<AuthMethod> requestMethods, Duration breakGlassDuration, int requestsPerHour,
                          int approvalsPerHour, int breakGlassPerDay, int maxPending, int maxGrants) {

    public static final Duration HARD_MAX_ELEVATION = Duration.ofHours(8);

    public PamSettings {
        positive(maxElevation, "maxElevation");
        if (maxElevation.compareTo(HARD_MAX_ELEVATION) > 0) {
            throw new IllegalArgumentException("maxElevation above " + HARD_MAX_ELEVATION + " is standing privilege in disguise");
        }
        positive(requestTtl, "requestTtl");
        positive(approvalMaxAge, "approvalMaxAge");
        positive(mfaMaxAge, "mfaMaxAge");
        requestMethods = Set.copyOf(Objects.requireNonNull(requestMethods, "requestMethods"));
        if (requestMethods.isEmpty() || requestMethods.stream().anyMatch(m -> !m.satisfiesStepUp())) {
            throw new IllegalArgumentException("requestMethods must be non-empty MFA methods");
        }
        positive(breakGlassDuration, "breakGlassDuration");
        if (requestsPerHour < 1 || approvalsPerHour < 1 || breakGlassPerDay < 1 || maxPending < 1 || maxGrants < 1) {
            throw new IllegalArgumentException("limits must be at least 1");
        }
    }

    /**
     * Elevations of at most 1 h, lapsing after 30 min unapproved; signatures at most 5 min old; MFA at
     * most 5 min old and WebAuthn only; break-glass for 30 min; 5 requests per subject and 20
     * approvals per approver per hour; 3 break-glass uses per account per day.
     */
    public static PamSettings defaults() {
        return new PamSettings(Duration.ofHours(1), Duration.ofMinutes(30), Duration.ofMinutes(5),
                Duration.ofMinutes(5), EnumSet.of(AuthMethod.WEBAUTHN), Duration.ofMinutes(30), 5, 20, 3,
                10_000, 10_000);
    }

    private static void positive(Duration d, String name) {
        Objects.requireNonNull(d, name);
        if (d.isNegative() || d.isZero()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
}

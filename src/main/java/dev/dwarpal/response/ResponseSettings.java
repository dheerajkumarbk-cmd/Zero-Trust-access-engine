package dev.dwarpal.response;

import dev.dwarpal.domain.Validate;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/**
 * The guard rails of the SOC response loop, fixed at deployment (never by an alert or a verdict).
 *
 * @param maxDeny                  the longest deny a playbook may set (at most {@link #HARD_MAX_DENY})
 * @param destructivePerHour       revocations and denies, all analysts together, per hour: a flood of
 *                                 alerts (or one stolen analyst key) cannot lock out the whole company
 * @param destructivePerAnalyst    the same, per analyst, per hour
 * @param secondAnalystWindow      how long a first verdict on a protected target waits for the second analyst
 * @param privilegedRoles          directory roles that make a subject privileged (two-person rule)
 * @param protectedSubjects        subjects always under the two-person rule (analysts, break-glass accounts,
 *                                 executives)
 * @param sharedAddresses          addresses shared by many people (office egress, VPN concentrators): denying
 *                                 one locks out everyone behind it, so it needs two analysts too
 * @param maxCases                 cases held (open and closed); when full of open cases, new alerts are refused
 * @param maxAlertsPerCase         alerts one case keeps; more are refused and counted
 */
public record ResponseSettings(Duration maxDeny, int destructivePerHour, int destructivePerAnalyst,
                               Duration secondAnalystWindow, Set<String> privilegedRoles,
                               Set<String> protectedSubjects, Set<String> sharedAddresses, int maxCases,
                               int maxAlertsPerCase) {

    /** The plan's ceiling: a playbook deny is never longer than a week, whatever the settings say. */
    public static final Duration HARD_MAX_DENY = Duration.ofDays(7);
    public static final int HARD_MAX_CASES = 100_000;

    public ResponseSettings {
        Objects.requireNonNull(maxDeny, "maxDeny");
        Objects.requireNonNull(secondAnalystWindow, "secondAnalystWindow");
        if (maxDeny.isNegative() || maxDeny.isZero() || maxDeny.compareTo(HARD_MAX_DENY) > 0) {
            throw new IllegalArgumentException("maxDeny must be more than zero and at most 7 days");
        }
        if (destructivePerHour < 1 || destructivePerAnalyst < 1 || destructivePerAnalyst > destructivePerHour) {
            throw new IllegalArgumentException("rate limits must be positive, per analyst no more than in total");
        }
        if (secondAnalystWindow.compareTo(Duration.ofMinutes(1)) < 0
                || secondAnalystWindow.compareTo(Duration.ofHours(24)) > 0) {
            throw new IllegalArgumentException("the second-analyst window is 1 minute to 24 hours");
        }
        if (maxCases < 1 || maxCases > HARD_MAX_CASES || maxAlertsPerCase < 1 || maxAlertsPerCase > 10_000) {
            throw new IllegalArgumentException("case limits out of range");
        }
        privilegedRoles = Set.copyOf(privilegedRoles);
        privilegedRoles.forEach(r -> Validate.label(r, "privilegedRole"));
        protectedSubjects = Set.copyOf(protectedSubjects);
        protectedSubjects.forEach(s -> Validate.id(s, "protectedSubject"));
        sharedAddresses = Set.copyOf(sharedAddresses);
        sharedAddresses.forEach(a -> Validate.id(a, "sharedAddress"));
    }

    /** One-week denies, 20 destructive actions an hour (10 per analyst), 1 h for the second analyst. */
    public static ResponseSettings defaults() {
        return new ResponseSettings(HARD_MAX_DENY, 20, 10, Duration.ofHours(1), Set.of("admin"), Set.of(), Set.of(),
                10_000, 100);
    }

    public ResponseSettings withProtected(Set<String> subjects, Set<String> addresses) {
        return new ResponseSettings(maxDeny, destructivePerHour, destructivePerAnalyst, secondAnalystWindow,
                privilegedRoles, subjects, addresses, maxCases, maxAlertsPerCase);
    }

    public ResponseSettings withLimits(int perHour, int perAnalyst, int cases, int alertsPerCase) {
        return new ResponseSettings(maxDeny, perHour, perAnalyst, secondAnalystWindow, privilegedRoles,
                protectedSubjects, sharedAddresses, cases, alertsPerCase);
    }
}

package dev.dwarpal.session;

import dev.dwarpal.decision.Decision;
import dev.dwarpal.domain.Sanitize;

import java.util.Objects;
import java.util.Optional;

/**
 * The Policy Administrator's answer to the enforcement point.
 *
 * @param status   what the enforcement point must do
 * @param grant    present only when a session was opened
 * @param decision the engine's decision, when the engine was consulted
 * @param reason   for the analyst; the user sees only the decision's generic message
 * @param sessionEnded true when this call closed the session (revocation, expiry)
 */
public record SessionResult(Status status, Optional<SessionGrant> grant, Optional<Decision> decision,
                            String reason, boolean sessionEnded) {

    public enum Status {
        /** A session was opened; the grant carries the token. */
        OPENED,
        /** This use is allowed. */
        GRANTED,
        /** This use is allowed read-only. */
        GRANTED_LIMITED,
        /** The subject must authenticate again (fresh, verified MFA) before continuing. */
        STEP_UP,
        /** The engine refused this request. */
        DENIED,
        /** The session or its proof is invalid; the engine was not consulted. */
        REJECTED
    }

    public static final int MAX_REASON_LENGTH = 512;

    public SessionResult {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(grant, "grant");
        Objects.requireNonNull(decision, "decision");
        reason = Sanitize.text(Objects.requireNonNull(reason, "reason"), MAX_REASON_LENGTH);
        if (grant.isPresent() != (status == Status.OPENED)) {
            throw new IllegalArgumentException("a grant comes with OPENED and only with OPENED");
        }
    }

    static SessionResult opened(SessionGrant grant, Decision d, String reason) {
        return new SessionResult(Status.OPENED, Optional.of(grant), Optional.of(d), reason, false);
    }

    static SessionResult of(Status status, Decision d, String reason, boolean ended) {
        return new SessionResult(status, Optional.empty(), Optional.ofNullable(d), reason, ended);
    }

    static SessionResult rejected(String reason, boolean ended) {
        return new SessionResult(Status.REJECTED, Optional.empty(), Optional.empty(), reason, ended);
    }

    public boolean allowed() {
        return status == Status.OPENED || status == Status.GRANTED || status == Status.GRANTED_LIMITED;
    }
}

package dev.dwarpal.edge;

import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;

import java.util.Objects;
import java.util.Optional;

/**
 * What an enforcement point is told: exactly enough to enforce, nothing an attacker could learn from.
 * The analyst's explanation (risk factors, matched policy, reasons) stays on the engine side, in the
 * audit trail; across the network there is only the status, a generic user message and a reference
 * the user can quote to the help desk.
 *
 * @param reference    the request id, for the user to quote
 * @param userMessage  generic text, safe to show the user
 * @param restricted   true when access is read-only
 * @param challenge    present only with STEP_UP: the authenticator to challenge with
 * @param grant        present only with OPENED
 * @param sessionEnded true when this request ended the session
 */
public record EdgeResult(Status status, String reference, String userMessage, boolean restricted,
                         Optional<AuthMethod> challenge, Optional<EdgeGrant> grant, boolean sessionEnded) {

    public enum Status {
        /** A session was opened; {@code grant} carries it. */
        OPENED,
        /** Allowed. */
        GRANTED,
        /** Allowed read-only. */
        GRANTED_LIMITED,
        /** The user must authenticate again with {@code challenge} first. */
        STEP_UP,
        /** The engine refused the request. */
        DENIED,
        /** The session or its proof is invalid. */
        REJECTED;

        public boolean allowed() {
            return this == OPENED || this == GRANTED || this == GRANTED_LIMITED;
        }
    }

    public static final int MAX_MESSAGE_LENGTH = 200;

    public EdgeResult {
        Objects.requireNonNull(status, "status");
        Validate.id(reference, "reference");
        userMessage = Sanitize.text(Objects.requireNonNull(userMessage, "userMessage"), MAX_MESSAGE_LENGTH);
        Objects.requireNonNull(challenge, "challenge");
        Objects.requireNonNull(grant, "grant");
        if (grant.isPresent() != (status == Status.OPENED)) {
            throw new IllegalArgumentException("a grant comes with OPENED and only with OPENED");
        }
        if (challenge.isPresent() != (status == Status.STEP_UP)) {
            throw new IllegalArgumentException("a challenge comes with STEP_UP and only with STEP_UP");
        }
        if (status == Status.GRANTED && restricted) {
            throw new IllegalArgumentException("a restricted grant is GRANTED_LIMITED");
        }
    }

    /** The generic message for a status, when the engine gave none. */
    public static String genericMessage(Status status, String reference) {
        return switch (status) {
            case OPENED, GRANTED -> "Access granted.";
            case GRANTED_LIMITED -> "Access granted with restrictions. Reference: " + reference;
            case STEP_UP -> "Additional verification required. Reference: " + reference;
            case DENIED, REJECTED -> "Access denied. Contact your administrator with reference: " + reference;
        };
    }
}

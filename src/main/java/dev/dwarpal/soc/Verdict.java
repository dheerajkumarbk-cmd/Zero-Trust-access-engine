package dev.dwarpal.soc;

import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.Validate;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * An analyst's decision on one alert. Verdicts can make playbooks revoke sessions or deny people, so
 * they count only when signed by a {@link KeyPurpose#SOC_ANALYST} key bound to the named analyst: a
 * stolen enforcement point, identity provider or policy-signing key cannot produce one.
 *
 * @param proof signature over {@link SignedMessages#socVerdict} (alert, analyst, outcome, time)
 */
public record Verdict(String alertId, String analystId, Outcome outcome, SignatureProof proof) {

    /** How old a verdict may be when it is acted on. */
    public static final Duration MAX_AGE = Duration.ofMinutes(15);

    public enum Outcome {
        /** The alert was right: act. */
        TRUE_POSITIVE,
        /** The alert was wrong: undo what was done on its account. */
        FALSE_POSITIVE,
        /** Real, but expected (an approved test, a known traveller): close without action. */
        BENIGN
    }

    public Verdict {
        Validate.id(alertId, "verdict.alertId");
        Validate.id(analystId, "verdict.analystId");
        Objects.requireNonNull(outcome, "verdict.outcome");
        Objects.requireNonNull(proof, "verdict.proof");
    }

    /** What the analyst signs. */
    public byte[] signedMessage() {
        return SignedMessages.socVerdict(alertId, analystId, outcome.name(), proof.signedAt());
    }

    /** Whether a key of the right purpose, bound to this analyst, signed exactly this verdict recently. */
    public KeyRing.Result verify(KeyRing keys, Instant now) {
        Objects.requireNonNull(keys, "keys");
        return keys.verify(KeyPurpose.SOC_ANALYST, analystId, proof, signedMessage(), now, MAX_AGE);
    }
}

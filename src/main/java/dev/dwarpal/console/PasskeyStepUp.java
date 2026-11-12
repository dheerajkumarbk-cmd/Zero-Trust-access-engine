package dev.dwarpal.console;

import java.util.Optional;

/**
 * The one place that proves a person holds their passkey. The unlock routes and the elevation ask only this, so the
 * kind of passkey (a typed secret in the tests and the fallback, the person's own device in the lab) is a choice made
 * once when the console is built, never in the callers.
 */
@FunctionalInterface
public interface PasskeyStepUp {

    /**
     * @param personId the person who is asking
     * @param evidence what the browser sent: the typed passkey, or the signed answer of the person's own device (as JSON text)
     * @param source   where the request came from, for the same growing wait after wrong guesses
     * @return OK with the person, FAILED, or LOCKED with a wait
     */
    ConsoleAuth.Authenticated verify(String personId, String evidence, String source);

    /** What the browser must do: {@code typed} (type the passkey) or {@code webauthn} (the person's own device signs). */
    default String kind() {
        return "typed";
    }

    /** Whether this person has a passkey registered; empty when the typed passkey store in the credentials decides. */
    default Optional<Boolean> isSet(String personId) {
        return Optional.empty();
    }

    /** Sets or replaces the person's passkey. Password and PIN prove who is asking. */
    default ConsoleAuth.Changed register(ConsoleAuth auth, String subject, String password, String pin, String evidence, String source) {
        return auth.setPasskey(subject, password, pin, evidence, source);
    }

    /** The typed passkey: a secret kept only as a salted hash. */
    static PasskeyStepUp typed(ConsoleAuth auth) {
        return auth::unlock;
    }
}

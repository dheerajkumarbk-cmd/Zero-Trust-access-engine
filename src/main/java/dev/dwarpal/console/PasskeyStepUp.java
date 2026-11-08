package dev.dwarpal.console;

/**
 * The one place that proves a person holds their passkey. The unlock routes and the elevation ask only this, so Stage 5
 * replaces the typed passkey with a real Windows Hello passkey by swapping the implementation, never the callers.
 */
@FunctionalInterface
public interface PasskeyStepUp {

    /**
     * @param personId the person who is asking
     * @param evidence what the browser sent: today the typed passkey, later the signed answer of the person's own device
     * @param source   where the request came from, for the same growing wait after wrong guesses
     * @return OK with the person, FAILED, or LOCKED with a wait
     */
    ConsoleAuth.Authenticated verify(String personId, String evidence, String source);

    /** Today's passkey: a typed secret kept only as a salted hash. */
    static PasskeyStepUp typed(ConsoleAuth auth) {
        return auth::unlock;
    }
}

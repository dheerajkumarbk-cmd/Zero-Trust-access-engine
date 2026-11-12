package dev.dwarpal.api;

import java.time.Instant;

/**
 * Edge-triggered alarm of an enforcement point's engine client: told once when the engine becomes
 * unreachable, and once when it answers again. It never changes an answer: while the engine is down every
 * call is already DENIED.
 */
public interface EngineAlarm {

    /** The engine failed {@code consecutiveFailures} calls in a row (called once per outage). */
    void engineDown(long consecutiveFailures, Instant at);

    /** The first acceptable answer after an outage (called once per outage). */
    void engineBack(Instant at);

    /** No alarm. */
    EngineAlarm NONE = new EngineAlarm() {
        @Override
        public void engineDown(long consecutiveFailures, Instant at) {
        }

        @Override
        public void engineBack(Instant at) {
        }
    };
}

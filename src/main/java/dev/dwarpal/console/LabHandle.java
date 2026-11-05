package dev.dwarpal.console;

import dev.dwarpal.lab.LabRunner;
import dev.dwarpal.lab.LabWorld;

/**
 * The one place the console asks "which lab is running now?". A reset of the lab builds a new {@link LabWorld} (new
 * audit chain, new SOC API port); everything in the console that reads the lab goes through this handle on every
 * call and keeps no reference to a world, so a reset needs no change here.
 */
public interface LabHandle {

    LabWorld world();

    /** The scenario clock, or null when none is running (a test). */
    LabRunner runner();

    /** A handle on one fixed world, for tests and for a launcher that never resets. */
    static LabHandle of(LabWorld world, LabRunner runner) {
        java.util.concurrent.atomic.AtomicReference<LabWorld> w = new java.util.concurrent.atomic.AtomicReference<>(world);
        java.util.concurrent.atomic.AtomicReference<LabRunner> r = new java.util.concurrent.atomic.AtomicReference<>(runner);
        return new LabHandle() {
            @Override
            public LabWorld world() {
                return w.get();
            }

            @Override
            public LabRunner runner() {
                return r.get();
            }
        };
    }
}

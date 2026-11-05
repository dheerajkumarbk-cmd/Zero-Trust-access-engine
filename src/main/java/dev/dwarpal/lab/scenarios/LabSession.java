package dev.dwarpal.lab.scenarios;

import dev.dwarpal.lab.LabConfig;
import dev.dwarpal.lab.LabRunner;
import dev.dwarpal.lab.LabWorld;

import java.io.IOException;
import java.time.Duration;
import java.util.function.Consumer;

/**
 * A running lab that can be reset to day zero: it owns the {@link LabWorld} and the {@link LabRunner} (the scenario
 * clock) and replaces both on {@link #reset()}. Everything that talks to the lab asks the session for the current
 * world each time and never keeps one, because a reset replaces it.
 *
 * <p>Reset forgets all in-memory SOC state (cases, risk, isolations, baselines, injected scenarios) and starts the
 * same organisation again from the same seed. Certificates in the lab directory are kept.
 */
public final class LabSession implements AutoCloseable {

    private final LabConfig config;
    private final Object lock = new Object();
    private final ScenarioRunner scenarios;
    private volatile LabWorld world;
    private volatile LabRunner runner;
    private volatile long generation;
    private Consumer<LabSession> afterReset = s -> { };
    private boolean closed;

    private LabSession(LabConfig config, LabWorld world, LabRunner runner, ScenarioRunner scenarios) {
        this.config = config;
        this.world = world;
        this.runner = runner;
        this.scenarios = scenarios;
    }

    /** Builds the lab, runs the warm-up days and starts the scenario clock. */
    public static LabSession open(LabConfig config) throws IOException, InterruptedException {
        LabWorld w = LabWorld.create(config);
        try {
            w.warmUp(config.warmupDays());
            LabRunner r = new LabRunner(w, config.speed()).start();
            return new LabSession(config, w, r, new ScenarioRunner());
        } catch (RuntimeException | Error e) {
            w.close();
            throw e;
        }
    }

    public LabConfig config() {
        return config;
    }

    /** The current world; a reset replaces it, so do not keep the answer. */
    public LabWorld world() {
        return world;
    }

    public LabRunner runner() {
        return runner;
    }

    public ScenarioRunner scenarios() {
        return scenarios;
    }

    /** Counts resets: 0 for the lab as started. */
    public long generation() {
        return generation;
    }

    /** The host's hook for rebuilding what hangs off the world (for example the SOC API address). */
    public void afterReset(Consumer<LabSession> hook) {
        synchronized (lock) {
            this.afterReset = hook;
        }
    }

    /**
     * Back to day zero: the scenario clock stops, the world is closed and rebuilt, the warm-up days run again and the
     * clock starts as it was (running or paused). Takes seconds; other callers wait.
     */
    public void reset() throws IOException, InterruptedException {
        synchronized (lock) {
            if (closed) {
                throw new IllegalStateException("the lab is closed");
            }
            boolean wasRunning = runner.state() == LabRunner.State.RUNNING;
            double speed = runner.speed();
            runner.close();
            world.close();
            LabWorld fresh = LabWorld.create(config);
            fresh.warmUp(config.warmupDays());
            LabRunner r = new LabRunner(fresh, speed).start();
            if (!wasRunning) {
                r.pause();
            }
            world = fresh;
            runner = r;
            generation++;
            scenarios.clear();
            afterReset.accept(this);
        }
    }

    /**
     * Moves scenario time forward by {@code by} in small steps (so the SOC API stays responsive between steps).
     *
     * @return the scenario time reached
     */
    public java.time.Instant fastForward(Duration by) {
        if (by.isNegative() || by.compareTo(Duration.ofHours(12)) > 0) {
            throw new IllegalArgumentException("fast-forward is 0 to 12 hours");
        }
        LabWorld w = world;
        java.time.Instant target = w.now().plus(by);
        while (w.now().isBefore(target)) {
            w.advanceTo(java.util.Collections.min(java.util.List.of(target, w.now().plus(Duration.ofMinutes(10)))));
        }
        return w.now();
    }

    @Override
    public void close() {
        synchronized (lock) {
            closed = true;
            runner.close();
            world.close();
        }
    }
}

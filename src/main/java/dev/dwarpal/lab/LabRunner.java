package dev.dwarpal.lab;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The scenario clock: moves the lab's time forward in small steps so events arrive as they would live. Speed is
 * simulated seconds per wall-clock second and can change while it runs. If a step fails the clock stops and says
 * why ({@link #failure()}); a lab that silently carries on after an error would show the analyst a false picture.
 */
public final class LabRunner implements AutoCloseable {

    public enum State { PAUSED, RUNNING, FINISHED, FAILED }

    /** Wall time between steps. */
    public static final Duration TICK = Duration.ofMillis(200);

    private final LabWorld world;
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "lab-clock");
        t.setDaemon(true);
        return t;
    });
    private final AtomicReference<State> state = new AtomicReference<>(State.PAUSED);
    private final AtomicReference<Throwable> failure = new AtomicReference<>();
    private volatile double speed;
    private volatile Instant last;
    private final Object lock = new Object();
    private ScheduledFuture<?> task;

    public LabRunner(LabWorld world, double speed) {
        this.world = world;
        setSpeed(speed);
    }

    public LabRunner start() {
        synchronized (lock) {
            if (task == null) {
                last = null;
                task = executor.scheduleAtFixedRate(this::step, TICK.toMillis(), TICK.toMillis(), TimeUnit.MILLISECONDS);
                state.compareAndSet(State.PAUSED, State.RUNNING);
            }
        }
        return this;
    }

    public void pause() {
        state.compareAndSet(State.RUNNING, State.PAUSED);
    }

    public void resume() {
        last = null;
        state.compareAndSet(State.PAUSED, State.RUNNING);
    }

    public void setSpeed(double v) {
        if (!(v > 0 && v <= LabConfig.MAX_SPEED)) {
            throw new IllegalArgumentException("speed must be above 0 and at most " + LabConfig.MAX_SPEED);
        }
        speed = v;
    }

    public double speed() {
        return speed;
    }

    public State state() {
        return state.get();
    }

    public Optional<Throwable> failure() {
        return Optional.ofNullable(failure.get());
    }

    /** One step: advance by the wall time since the last step, scaled by the speed. */
    void step() {
        try {
            if (state.get() != State.RUNNING) {
                last = null;
                return;
            }
            Instant wall = Instant.now();
            Instant before = last;
            last = wall;
            if (before == null) {
                return;
            }
            long millis = Duration.between(before, wall).toMillis();
            Instant target = world.now().plusMillis(Math.round(millis * speed));
            LabWorld.Progress p = world.advanceTo(target);
            if (p.finished()) {
                state.set(State.FINISHED);
            }
        } catch (RuntimeException | Error e) {
            failure.set(e);
            state.set(State.FAILED);
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            if (task != null) {
                task.cancel(false);
            }
        }
        executor.shutdownNow();
    }
}

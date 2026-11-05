package dev.dwarpal.lab;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertRanker;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EntityRisk;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.ueba.Ueba;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Part E's {@link Ueba} is built for one thread: it learns while it reads. In a running lab the scenario thread
 * feeds it and the SOC API's threads ask it for risk and ranking at the same time, so every call goes through one
 * lock. Calls are short; the lock is never held across anything that waits.
 */
public final class LockedUeba implements EntityRisk, AlertRanker {

    private final Ueba ueba;
    private final ReentrantLock lock = new ReentrantLock();

    public LockedUeba(Ueba ueba) {
        this.ueba = ueba;
    }

    public int poll(AuditCursor cursor, int max) {
        lock.lock();
        try {
            return ueba.poll(cursor, max);
        } finally {
            lock.unlock();
        }
    }

    public boolean raise(Alert alert) {
        lock.lock();
        try {
            return ueba.raise(alert);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public RiskView view(Entity entity, Instant now) {
        lock.lock();
        try {
            return ueba.view(entity, now);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public List<RiskView> top(int n, Instant now) {
        lock.lock();
        try {
            return ueba.top(n, now);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public RankedAlert rank(Alert alert, Instant now) {
        lock.lock();
        try {
            return ueba.rank(alert, now);
        } finally {
            lock.unlock();
        }
    }

    /** The wrapped facade, for code that already holds the lock through this class or runs on the scenario thread. */
    public Ueba unlocked() {
        return ueba;
    }

    /** Runs {@code action} on the facade while holding the lock. */
    public <T> T with(java.util.function.Function<Ueba, T> action) {
        lock.lock();
        try {
            return action.apply(ueba);
        } finally {
            lock.unlock();
        }
    }
}

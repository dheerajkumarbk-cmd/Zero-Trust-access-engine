package dev.dwarpal.console;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The console's writes into the audit chain, under the logged-in person (or {@code console} when nobody is). Records
 * carry the person, a hash of the console session id (never the id), the object and the outcome. Every value is
 * sanitised here, so nothing the browser sent can forge a line (CWE-117). A failed write is counted and returned to the
 * caller, which must not send data or act on a write whose record could not be made ("audit failure is itself
 * surfaced", as in the SOC API).
 */
final class ConsoleAudit {

    static final String ACTOR = "console";

    private final java.util.function.Supplier<AuditLog> log;
    private final java.util.function.Supplier<Clock> clock;
    private final AtomicLong failures = new AtomicLong();
    private final AtomicLong written = new AtomicLong();

    ConsoleAudit(java.util.function.Supplier<AuditLog> log, java.util.function.Supplier<Clock> scenarioClock) {
        this.log = log;
        this.clock = scenarioClock;
    }

    /** True when the record is in the chain. */
    boolean write(String type, String person, Map<String, String> fields) {
        Map<String, String> f = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : fields.entrySet()) {
            f.put(Sanitize.text(e.getKey(), 40), Sanitize.text(e.getValue() == null ? "" : e.getValue(), 300));
        }
        try {
            log.get().append(type, actor(person), clock.get().instant(), f);
            written.incrementAndGet();
            return true;
        } catch (RuntimeException e) {
            failures.incrementAndGet();
            return false;
        }
    }

    long failures() {
        return failures.get();
    }

    long written() {
        return written.get();
    }

    /** A short stable name for a session that cannot be turned back into the cookie value. */
    static String sessionTag(String sessionId) {
        return Digests.sha256Hex("dwarpal-console-session|" + sessionId).substring(0, 16);
    }

    private static String actor(String person) {
        try {
            return person == null ? ACTOR : Validate.id(person, "actor");
        } catch (IllegalArgumentException e) {
            return ACTOR;
        }
    }
}

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
    private static final int MAX_ACTIVITY = 20;
    private static final int MAX_PEOPLE = 500;
    private static final java.util.Set<String> OWN_ACTIVITY = java.util.Set.of("CONSOLE_LOGIN", "CONSOLE_LOGIN_FAILED", "CONSOLE_LOGOUT",
            "CONSOLE_RECOVERED", "CONSOLE_SESSION_REVOKED");

    private final java.util.function.Supplier<AuditLog> log;
    private final java.util.function.Supplier<Clock> clock;
    private final AtomicLong failures = new AtomicLong();
    private final AtomicLong written = new AtomicLong();
    private final Map<String, java.util.ArrayDeque<Activity>> recent = new java.util.HashMap<>();

    /** Something that happened on a person's own account, for their Home page. */
    record Activity(java.time.Instant at, String what) {
    }

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
            java.time.Instant at = clock.get().instant();
            log.get().append(type, actor(person), at, f);
            written.incrementAndGet();
            remember(type, person, f, at);
            return true;
        } catch (RuntimeException e) {
            failures.incrementAndGet();
            return false;
        }
    }

    /** Sign-ins and changes to the account itself, not everything a person reads. Newest last, a few per person. */
    private void remember(String type, String person, Map<String, String> f, java.time.Instant at) {
        String who = person == null ? f.get("user") : person;
        String route = f.getOrDefault("route", "");
        boolean write = "CONSOLE_WRITE".equals(type) && route.startsWith("profile/") && "200".equals(f.get("status"));
        if (who == null || !write && !OWN_ACTIVITY.contains(type)) {
            return;
        }
        synchronized (recent) {
            if (!recent.containsKey(who) && recent.size() >= MAX_PEOPLE) {
                return;
            }
            java.util.ArrayDeque<Activity> list = recent.computeIfAbsent(who, k -> new java.util.ArrayDeque<>());
            list.addLast(new Activity(at, write ? route : type));
            if (list.size() > MAX_ACTIVITY) {
                list.removeFirst();
            }
        }
    }

    /** A person's own recent activity, newest first. */
    java.util.List<Activity> activity(String person) {
        synchronized (recent) {
            java.util.ArrayList<Activity> out = new java.util.ArrayList<>(recent.getOrDefault(person, new java.util.ArrayDeque<>()));
            java.util.Collections.reverse(out);
            return out;
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

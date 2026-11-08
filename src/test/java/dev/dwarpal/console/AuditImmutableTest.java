package dev.dwarpal.console;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import dev.dwarpal.lab.LabAudit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Nobody edits or deletes an audit record, administrators included: the console has no call that does it, the audit code
 * has no method that does it, and a record changed by hand in the saved trail is found at the next start, which then refuses
 * to run on it.
 */
class AuditImmutableTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-08T10:00:00Z"), ZoneOffset.UTC);
    private static final List<String> CHANGING = List.of("update", "delete", "remove", "edit", "set", "clear", "truncate", "rewrite",
            "erase", "drop", "replace", "put", "overwrite", "modify", "reset");

    @TempDir
    Path dir;

    private ConsoleFixture f;

    @BeforeEach
    void start() throws Exception {
        f = ConsoleFixture.start();
    }

    @AfterEach
    void stop() {
        f.close();
    }

    private Resp send(String method, String path, Sess s) throws Exception {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("User-Agent", ConsoleFixture.UA);
        h.put("Origin", f.origin);
        h.put("Content-Type", "application/json");
        h.put("Cookie", ConsoleServer.COOKIE + "=" + s.cookie());
        h.put(ConsoleServer.CSRF_HEADER, s.csrf());
        return f.raw(method, path, h, "DELETE".equals(method) || "GET".equals(method) ? null : "{\"type\":\"CONSOLE_LOGIN\"}");
    }

    @Test
    void theConsoleHasNoCallThatEditsOrDeletesARecordForAnyRoleOrMethod() throws Exception {
        for (String who : new String[]{"cleo", "dana", "ana"}) {
            Sess s = f.login(who);
            long head = f.world.org.audit.head().sequence();
            dev.dwarpal.audit.AuditRecord first = f.world.org.sink.snapshot().getFirst();
            for (String path : new String[]{"/console/api/audit/records/1", "/console/api/audit/records"}) {
                for (String method : new String[]{"PUT", "PATCH", "DELETE", "POST"}) {
                    Resp r = send(method, path, s);
                    assertTrue(r.status() >= 400, who + " " + method + " " + path + " -> " + r.status());
                }
            }
            long afterwards = f.world.org.audit.head().sequence();
            // the only records added are the console's own notes about the refused calls, never a change to an old one
            assertTrue(afterwards >= head);
            assertEquals(first, f.world.org.sink.snapshot().getFirst(), "the oldest record is exactly what it was");
        }
        assertEquals(200, f.get("/console/api/audit/head", f.login("cleo")).status(), "and reading is still what it was");
    }

    @Test
    void theAuditCodeOffersNoMethodThatChangesOrRemovesARecord() {
        for (Class<?> c : new Class<?>[]{AuditLog.class, LabAudit.class, ConsoleTrail.class}) {
            List<String> names = Stream.of(c.getMethods()).filter(m -> m.getDeclaringClass() != Object.class).map(m -> m.getName()).toList();
            for (String name : names) {
                String lower = name.toLowerCase(Locale.ROOT);
                assertFalse(CHANGING.stream().anyMatch(lower::startsWith), c.getSimpleName() + "." + name + " would change the trail");
            }
        }
    }

    @Test
    void aRecordChangedByHandInTheSavedTrailIsFoundAndTheTrailRefusesToStart() throws Exception {
        try (ConsoleTrail t = ConsoleTrail.open(dir, CLOCK)) {
            t.log().append("ELEVATION_STARTED", "dana", CLOCK.instant(), Map.of("reason", "approving a request"));
            t.log().append("ACCESS_ROLE_ADDED", "dana", CLOCK.instant(), Map.of("person", "uma"));
        }
        Path store = dir.resolve(ConsoleTrail.STORE);
        byte[] bytes = Files.readAllBytes(store);
        bytes[bytes.length / 2] ^= 0x01;
        Files.write(store, bytes);
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> ConsoleTrail.open(dir, CLOCK));
        assertTrue(e.getMessage().contains("damaged") || e.getMessage().contains("was not accepted"), e.getMessage());
        assertTrue(Files.readAllBytes(store).length == bytes.length, "and it is left as it is, not repaired");
    }

    @Test
    void aRecordRemovedFromTheSavedTrailIsFoundToo() throws Exception {
        long afterOne;
        try (ConsoleTrail t = ConsoleTrail.open(dir, CLOCK)) {
            t.log().append("ELEVATION_STARTED", "dana", CLOCK.instant(), Map.of("reason", "one"));
            afterOne = Files.size(dir.resolve(ConsoleTrail.STORE));
            t.log().append("ACCESS_ROLE_ADDED", "dana", CLOCK.instant(), Map.of("person", "uma"));
        }
        try (java.nio.channels.FileChannel c = java.nio.channels.FileChannel.open(dir.resolve(ConsoleTrail.STORE),
                java.nio.file.StandardOpenOption.WRITE)) {
            c.truncate(afterOne);
        }
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> ConsoleTrail.open(dir, CLOCK));
        assertTrue(e.getMessage().contains("was not accepted"), e.getMessage());
    }
}

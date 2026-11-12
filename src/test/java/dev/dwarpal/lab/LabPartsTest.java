package dev.dwarpal.lab;

import dev.dwarpal.edge.DevPki;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The lab's smaller parts: certificates kept and renewed, the scenario clock, the launcher's options. */
class LabPartsTest {

    @Test
    void theLabKeepsItsCertificatesBetweenRunsAndRenewsThemBeforeTheyLapse() throws Exception {
        Path lab = Files.createTempDirectory("dwarpal-lab-pki");
        Instant t0 = Instant.parse("2026-11-05T09:00:00Z");
        List<String> names = List.of("soc-api", "ana");
        DevPki first = LabPki.ensure(lab, names, t0);
        byte[] ca = Files.readAllBytes(lab.resolve("pki/trust.p12"));
        char[] pass = first.password();

        DevPki again = LabPki.ensure(lab, names, t0.plus(Duration.ofDays(10)));
        assertArrayEquals(ca, Files.readAllBytes(lab.resolve("pki/trust.p12")), "a later start reuses the same authority");
        assertArrayEquals(pass, again.password());
        assertTrue(Files.isRegularFile(again.keyStore("ana")));

        LabPki.ensure(lab, names, t0.plus(LabPki.RENEW_AFTER).plusSeconds(1));
        assertTrue(Files.readAllBytes(lab.resolve("pki/trust.p12")).length > 0);
        assertNotEquals(new String(pass), Files.readString(lab.resolve("pki/pki.pass")).trim(),
                "a renewal makes a new authority with a new password");

        // a damaged stamp means: make it again, never fail to start
        Files.writeString(lab.resolve("pki/pki.created"), "not a time");
        LabPki.ensure(lab, names, t0);
    }

    @Test
    void secretsAreRandom() {
        assertNotEquals(LabPki.randomSecret(32), LabPki.randomSecret(32));
        assertEquals(43, LabPki.randomSecret(32).length());
    }

    @Test
    void theScenarioClockMovesTimeByTheSpeedPausesAndStopsOnAFailure() throws Exception {
        Path dir = Files.createTempDirectory("dwarpal-lab-clock");
        try (LabWorld w = LabWorld.create(LabConfig.defaults(dir).withPort(0));
             LabRunner runner = new LabRunner(w, 3_600)) {
            w.warmUp(1);
            assertEquals(LabRunner.State.PAUSED, runner.state());
            Instant before = w.now();
            runner.step();
            assertEquals(before, w.now(), "a paused clock does not move");

            runner.resume();
            runner.step(); // first step only starts the stopwatch
            Thread.sleep(300);
            runner.step();
            assertTrue(w.now().isAfter(before.plus(Duration.ofMinutes(10))), "an hour a second: " + w.now());
            assertEquals(LabRunner.State.RUNNING, runner.state());

            runner.pause();
            Instant paused = w.now();
            Thread.sleep(50);
            runner.step();
            assertEquals(paused, w.now());

            assertThrows(IllegalArgumentException.class, () -> runner.setSpeed(0));
            runner.setSpeed(60);
            assertEquals(60, runner.speed());

            w.advanceTo(w.scriptEnd);
            runner.resume();
            runner.step();
            Thread.sleep(50);
            runner.step();
            assertEquals(LabRunner.State.FINISHED, runner.state());
            assertTrue(runner.failure().isEmpty());
        }
    }

    @Test
    void theLauncherReadsItsOptionsStrictly() {
        LabConfig c = LabMain.parse(new String[]{"--dir", "x", "--seed", "9", "--users", "30", "--speed", "120",
                "--warmup-days", "2", "--port", "9443"});
        assertEquals(9, c.seed());
        assertEquals(30, c.users());
        assertEquals(120, c.speed());
        assertEquals(2, c.warmupDays());
        assertEquals(9443, c.port());
        assertEquals(Path.of("x"), c.dir());
        assertThrows(IllegalArgumentException.class, () -> LabMain.parse(new String[]{"--nonsense", "1"}));
        assertThrows(IllegalArgumentException.class, () -> LabMain.parse(new String[]{"--seed"}));
        assertThrows(IllegalArgumentException.class, () -> LabMain.parse(new String[]{"--users", "2"}));
    }

    @Test
    void theLauncherStartsPrintsWhereToConnectAndStopsOnInterrupt() throws Exception {
        Path dir = Files.createTempDirectory("dwarpal-lab-main");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(bytes, true, StandardCharsets.UTF_8);
        Thread t = new Thread(() -> {
            try {
                LabMain.run(new String[]{"--dir", dir.toString(), "--users", "30", "--warmup-days", "1", "--port", "0"}, out);
            } catch (Exception e) {
                out.println("failed " + e);
            }
        });
        t.start();
        long deadline = System.nanoTime() + Duration.ofSeconds(90).toNanos();
        while (!bytes.toString(StandardCharsets.UTF_8).contains("Stop with Ctrl+C") && System.nanoTime() < deadline) {
            Thread.sleep(200);
        }
        t.interrupt();
        t.join(30_000);
        String text = bytes.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains("SOC API (mutual TLS): https://localhost:"), text);
        assertTrue(text.contains("Stopping."), text);
    }
}

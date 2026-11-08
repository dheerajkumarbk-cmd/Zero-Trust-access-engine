package dev.dwarpal.lab;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The simulated sensors send heartbeats, and only a sensor that stops raises the alert. */
class LabHeartbeatTest {

    private static final String RULE = "sensor-heartbeat-missing";

    @TempDir
    Path dir;

    private static List<String> missing(LabWorld w) {
        return w.raised.stream().filter(r -> r.alert().rule().equals(RULE))
                .flatMap(r -> r.alert().entities().stream()).map(Object::toString).toList();
    }

    @Test
    void healthySensorsStayQuietAndAStoppedOneIsNamed() throws Exception {
        try (LabWorld w = LabWorld.create(LabConfig.defaults(dir).withPort(0))) {
            w.warmUp(1);
            w.startHeartbeats();
            w.advanceTo(w.now().plus(Duration.ofHours(3)));
            assertTrue(missing(w).isEmpty(), "no alert while every sensor reports: " + missing(w));

            String laptop = w.org.users.getFirst().laptop();
            Instant now = w.now();
            w.inject(List.of(new LabWorld.SensorStop(laptop, now)));
            w.advanceTo(now.plus(Duration.ofMinutes(160)));

            List<String> named = missing(w);
            assertFalse(named.isEmpty(), "the stopped sensor raises the alert");
            assertTrue(named.stream().allMatch(e -> e.contains(laptop)), named.toString());
            assertEquals(1, w.raised.stream().filter(r -> r.alert().rule().equals(RULE)).count(), "one alert per silence");
            LabWorld.Raised raised = w.raised.stream().filter(r -> r.alert().rule().equals(RULE)).findFirst().orElseThrow();
            assertTrue(w.cases.ranked(raised.alert().id()).isPresent(), "the alert reaches the queue: " + raised.alert());
        }
    }
}

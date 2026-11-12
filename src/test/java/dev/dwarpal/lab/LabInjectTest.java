package dev.dwarpal.lab;

import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.sim.SimTelemetry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The scenario lab starts attacks "now" by adding items to the script; the world must stay sound while it does. */
class LabInjectTest {

    private static LabWorld w;

    @BeforeAll
    static void build() throws Exception {
        w = LabWorld.create(LabConfig.defaults(Files.createTempDirectory("dwarpal-inject")).withPort(0).withUsers(30));
        w.warmUp(1);
    }

    @AfterAll
    static void release() {
        w.close();
    }

    private static SimTelemetry.RawLine line(Instant at, String text) {
        return new SimTelemetry.RawLine(SimTelemetry.Source.FIREWALL, at, text, SimTelemetry.Activity.NOISE, "u1");
    }

    private static String fw(Instant at, int n) {
        return "<134>1 " + at + " fw01 dwfw " + (9_100_000 + n) + " - - action=allow src=10.0.0.9 sport=50000 dst=198.51.100.10"
                + " dport=443 proto=tcp bytes=400 rule=out-any";
    }

    @Test
    void injectedItemsRunInTimeOrderAtTheirOwnTimeAndReachTheChain() {
        Instant now = w.now();
        long before = w.org.sink.lastSequence();
        List<Object> items = new ArrayList<>();
        items.add(line(now.plusSeconds(120), fw(now.plusSeconds(120), 2)));
        items.add(line(now.plusSeconds(60), fw(now.plusSeconds(60), 1)));
        assertEquals(2, w.inject(items));

        w.advanceTo(now.plusSeconds(90));
        assertEquals(before + 1, w.org.sink.lastSequence(), "only the first one is due");
        w.advanceTo(now.plusSeconds(130));
        assertEquals(before + 2, w.org.sink.lastSequence());
    }

    @Test
    void whatCannotBeRunSafelyIsRefusedWhole() {
        Instant now = w.now();
        assertThrows(IllegalArgumentException.class, () -> w.inject(List.of()));
        assertThrows(IllegalArgumentException.class, () -> w.inject(List.of("a string")));
        assertThrows(IllegalArgumentException.class, () -> w.inject(List.of(line(now.minusSeconds(1), "x"))),
                "nothing may be dated before now");
        assertThrows(IllegalArgumentException.class, () -> w.inject(java.util.Collections.nCopies(
                LabWorld.MAX_INJECTED_PER_CALL + 1, line(now.plusSeconds(5), "x"))));
        // a bad item in a batch means none of the batch is added
        long before = w.org.sink.lastSequence();
        assertThrows(IllegalArgumentException.class, () -> w.inject(List.of(line(now.plusSeconds(5), fw(now, 3)), 42)));
        w.advanceTo(now.plusSeconds(10));
        assertEquals(before, w.org.sink.lastSequence());
    }

    @Test
    void theNumberOfWaitingItemsIsBounded() {
        Instant far = w.scriptEnd.plus(Duration.ofDays(30));
        int added = 0;
        boolean refused = false;
        for (int i = 0; i < 4; i++) {
            try {
                added += w.inject(java.util.Collections.nCopies(LabWorld.MAX_INJECTED_PER_CALL, line(far, "x")));
            } catch (IllegalStateException e) {
                refused = true;
            }
        }
        assertTrue(refused, "a runaway scenario button cannot queue without limit: added " + added);
        assertTrue(added <= LabWorld.MAX_INJECTED_PENDING);
    }

    @Test
    void anInjectedEndpointBatchDoesNotMakeTheScriptsLaterBatchesOfThatDeviceRefused() throws Exception {
        try (LabWorld own = LabWorld.create(LabConfig.defaults(Files.createTempDirectory("dwarpal-inject2")).withPort(0)
                .withUsers(30))) {
            own.warmUp(1);
            SimTelemetry.EndpointBatch real = own.telemetry.items().stream()
                    .filter(i -> i instanceof SimTelemetry.EndpointBatch b && b.at().isAfter(own.now()))
                    .map(i -> (SimTelemetry.EndpointBatch) i).findFirst().orElseThrow();
            Instant at = real.at();
            SimTelemetry.EndpointBatch early = new SimTelemetry.EndpointBatch(real.deviceId(), real.keyId(), 1, at,
                    real.body(), real.signature(), real.activities(), real.userId());
            own.inject(List.of(early));
            own.advanceTo(own.scriptEnd);
            assertTrue(own.finished());
            long refused = own.org.sink.snapshot().stream().filter(r -> r.type().equals("SECURITY_EVENT")
                    && r.payloadJson().contains("ingest.refused")).count();
            assertEquals(0, refused, "no batch of the device was refused as replayed");
        }
    }
}

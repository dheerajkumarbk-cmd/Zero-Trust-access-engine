package dev.dwarpal.sim;

import dev.dwarpal.crypto.KeyPurpose;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 5.2 part 0: the multi-source telemetry fixture is deterministic, signed and labelled as documented. */
class SimTelemetryTest {

    private static SimTelemetry telemetry(SimOrganisation org) {
        return SimTelemetry.of(org, org.traffic());
    }

    @Test
    void sameSeedSameTelemetry() {
        List<String> a = telemetry(SimOrganisation.create(7, 30)).items().stream()
                .map(i -> i instanceof SimTelemetry.RawLine r ? r.text() : ((SimTelemetry.EndpointBatch) i).body()).toList();
        List<String> b = telemetry(SimOrganisation.create(7, 30)).items().stream()
                .map(i -> i instanceof SimTelemetry.RawLine r ? r.text() : ((SimTelemetry.EndpointBatch) i).body()).toList();
        assertEquals(a, b);
    }

    @Test
    void everyEndpointBatchIsSignedByItsOwnDeviceAndNumberedInOrder() {
        SimOrganisation org = SimOrganisation.create(7, 60);
        SimTelemetry t = telemetry(org);
        Map<String, Long> last = new HashMap<>();
        int batches = 0;
        for (SimTelemetry.Item i : t.items()) {
            if (i instanceof SimTelemetry.EndpointBatch b) {
                batches++;
                assertTrue(org.keys.verify(KeyPurpose.DEVICE_AGENT, b.deviceId(), b.proof(), b.signedMessage(), b.at(),
                        Duration.ofMinutes(5)).valid(), b.deviceId() + " batch " + b.batch());
                assertTrue(b.batch() > last.getOrDefault(b.deviceId(), 0L), "strictly increasing per device");
                last.put(b.deviceId(), b.batch());
                assertEquals(b.body().split("\n").length, b.activities().size(), "one label per line");
            }
        }
        assertTrue(batches > 100);

        SimTelemetry.EndpointBatch any = t.items().stream().filter(i -> i instanceof SimTelemetry.EndpointBatch)
                .map(i -> (SimTelemetry.EndpointBatch) i).findFirst().orElseThrow();
        SimTelemetry.EndpointBatch edited = new SimTelemetry.EndpointBatch(any.deviceId(), any.keyId(), any.batch(),
                any.at(), any.body().replace("explorer.exe", "services.exe"), any.signature(), any.activities(), any.userId());
        assertFalse(org.keys.verify(KeyPurpose.DEVICE_AGENT, edited.deviceId(), edited.proof(), edited.signedMessage(),
                edited.at(), Duration.ofMinutes(5)).valid(), "one changed line breaks the signature");
        assertFalse(org.keys.verify(KeyPurpose.DEVICE_AGENT, "laptop-u99", any.proof(), any.signedMessage(), any.at(),
                Duration.ofMinutes(5)).valid(), "bound to its own device");
    }

    @Test
    void theLabelledActivitiesAreThereAndInTimeOrder() {
        SimOrganisation org = SimOrganisation.create(7, 60);
        SimTelemetry t = telemetry(org);
        Map<SimTelemetry.Activity, Integer> counts = new EnumMap<>(SimTelemetry.Activity.class);
        Map<SimTelemetry.Source, Integer> sources = new EnumMap<>(SimTelemetry.Source.class);
        SimTelemetry.Item previous = null;
        for (SimTelemetry.Item i : t.items()) {
            if (previous != null) {
                assertFalse(i.at().isBefore(previous.at()), "time order");
            }
            previous = i;
            switch (i) {
                case SimTelemetry.RawLine r -> {
                    counts.merge(r.activity(), 1, Integer::sum);
                    sources.merge(r.source(), 1, Integer::sum);
                }
                case SimTelemetry.EndpointBatch b -> {
                    b.activities().forEach(a -> counts.merge(a, 1, Integer::sum));
                    sources.merge(SimTelemetry.Source.ENDPOINT, 1, Integer::sum);
                }
            }
        }
        assertEquals(60 * 9, counts.get(SimTelemetry.Activity.A6_STOLEN_LAPTOP_AT_HOME), "9 endpoint traces per A6 login");
        assertEquals(2 * (1 + 120 + 120), counts.get(SimTelemetry.Activity.A8_BEACONING), "endpoint and firewall");
        assertEquals(121, counts.get(SimTelemetry.Activity.A9_CLOUD_EXFIL));
        assertEquals(60, counts.get(SimTelemetry.Activity.L5_BIG_LEGIT_DOWNLOAD));
        assertEquals(2 * 8, counts.get(SimTelemetry.Activity.L6_ADMIN_POWERSHELL));
        assertEquals(4, counts.get(SimTelemetry.Activity.NOISE));
        assertTrue(counts.get(SimTelemetry.Activity.NORMAL) > 5_000);
        assertEquals(3, sources.size());

        assertEquals(60, t.departments().size());
        assertEquals("finance", t.departments().get(t.cast().get(SimTelemetry.Activity.L5_BIG_LEGIT_DOWNLOAD)
                .iterator().next()));
        assertTrue(t.admins().stream().allMatch(a -> t.departments().get(a).equals("it")));
        assertEquals("laptop-u4", t.leases().get("10.20.0.5"));
        assertEquals(2, t.cast().get(SimTelemetry.Activity.A8_BEACONING).size());
        assertTrue(t.items().stream().anyMatch(i -> i instanceof SimTelemetry.RawLine r
                && r.text().contains("dst=" + SimTelemetry.C2_ADDRESS)));
        assertTrue(t.items().stream().anyMatch(i -> i instanceof SimTelemetry.RawLine r
                && r.text().contains("\"share\":\"" + SimTelemetry.EXTERNAL_SHARE + "\"")));
        assertTrue(SimTelemetry.Activity.A9_CLOUD_EXFIL.attack());
        assertFalse(SimTelemetry.Activity.L6_ADMIN_POWERSHELL.attack());
    }
}

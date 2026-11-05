package dev.dwarpal.soar;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.Validate;

import java.security.PrivateKey;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A stand-in for the endpoint agents of a demo or a test: it takes isolation commands, keeps which devices are cut
 * off, and answers each with a batch signed by that device's agent key, as a real sensor would. Real kernel-level
 * isolation is out of scope; nothing here touches the network. The device keys are handed in by whoever runs the
 * simulation (made at run time), never stored by this class anywhere but in memory.
 */
public final class SimulatedSensor implements Sensor {

    public static final int MAX_QUEUED = 10_000;

    private record DeviceKey(String keyId, PrivateKey key) {
    }

    private final Map<String, DeviceKey> keys = new HashMap<>();
    private final Map<String, Long> batches = new HashMap<>();
    private final Set<String> isolated = new HashSet<>();
    private final Set<String> offline = new HashSet<>();
    private final ArrayDeque<SensorAck> outbox = new ArrayDeque<>();
    private final Clock clock;

    public SimulatedSensor(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Enrols a device: its agent's key id and private key ({@code DEVICE_AGENT}, bound to the device). */
    public synchronized SimulatedSensor enrol(String deviceId, String keyId, PrivateKey key) {
        keys.put(Validate.id(deviceId, "deviceId"), new DeviceKey(Validate.id(keyId, "keyId"),
                Objects.requireNonNull(key, "key")));
        return this;
    }

    /** Takes a device's sensor off line (commands to it are not delivered) or back on. */
    public synchronized void offline(String deviceId, boolean off) {
        if (off) {
            offline.add(deviceId);
        } else {
            offline.remove(deviceId);
        }
    }

    @Override
    public synchronized boolean deliver(IsolationCommand command) {
        DeviceKey k = keys.get(command.deviceId());
        if (k == null || offline.contains(command.deviceId()) || outbox.size() >= MAX_QUEUED) {
            return false;
        }
        if (command.action() == IsolationCommand.Action.ISOLATE) {
            isolated.add(command.deviceId());
        } else {
            isolated.remove(command.deviceId());
        }
        long batch = batches.merge(command.deviceId(), 1L, Long::sum);
        var at = clock.instant();
        String body = command.ackBody();
        String sig = Ed25519.sign(k.key(), SignedMessages.endpointTelemetry(command.deviceId(), batch, at,
                Digests.sha256Hex(body)));
        outbox.add(new SensorAck(command.deviceId(), k.keyId(), batch, at, body, sig));
        return true;
    }

    /** The acknowledgements sent since the last call, oldest first. */
    public synchronized List<SensorAck> drain() {
        List<SensorAck> out = new ArrayList<>(outbox);
        outbox.clear();
        return out;
    }

    /** Whether the simulated agent has cut this device off. */
    public synchronized boolean isolated(String deviceId) {
        return isolated.contains(deviceId);
    }
}

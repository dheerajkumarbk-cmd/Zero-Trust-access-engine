package dev.dwarpal.soar;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.domain.Validate;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * XDR-lite device isolation. The engine-side half (deny the device in the signal feed, revoke its sessions) is a
 * pair of ordinary steps in part B's play, so its guard rails apply (rate limits, two analysts for protected
 * people). This class does the sensor-side half, and only after that play has run in full:
 *
 * <ol>
 *   <li>{@link #isolate} sends an isolate command with a fresh random id to the device's sensor;</li>
 *   <li>the device counts as isolated only when its sensor answers with a batch signed by that device's own
 *       {@code DEVICE_AGENT} key, whose body quotes the command ({@link #acknowledge}); batch numbers must rise
 *       per device, the signature must be fresh, and nothing else can stand in for it (another device's key, a
 *       replayed batch, an acknowledgement of an older command);</li>
 *   <li>with no acknowledgement in time the isolation is shown as overdue (the engine-side deny stays);</li>
 *   <li>{@link #release} sends the release command, and is called only when a signed verdict lifted the case's
 *       actions (see {@link Soar}); when several cases isolated one device, it is released when the last of them is.</li>
 * </ol>
 * Every change is audited before it happens. At most {@code maxDevices} devices are tracked; beyond that new
 * isolations are refused (and the engine-side deny still holds).
 */
public final class DeviceIsolation {

    public static final String ACTOR = "soc-isolation";
    public static final Duration ACK_MAX_AGE = Duration.ofMinutes(5);

    public enum State {
        /** The isolate command was sent (or is waiting to be sent); no signed acknowledgement yet. */
        PENDING_ACK,
        /** The sensor acknowledged with a valid signed batch. */
        ISOLATED,
        /** The release command was sent; no acknowledgement yet. */
        RELEASE_PENDING,
        /** The sensor acknowledged the release. */
        RELEASED
    }

    /** One device's isolation as shown to analysts. */
    public record Isolation(String deviceId, Set<String> cases, State state, String commandId, Instant since,
                            boolean delivered, boolean overdue) {
        public Isolation {
            cases = Set.copyOf(cases);
        }
    }

    public enum AckResult { ACCEPTED, NO_COMMAND, WRONG_BODY, NOT_VERIFIED, REPLAYED, UNAVAILABLE }

    private static final class Entry {
        final String device;
        final Set<String> cases = new LinkedHashSet<>();
        State state;
        IsolationCommand command;
        Instant since;
        boolean delivered;
        long lastBatch;

        Entry(String device) {
            this.device = device;
        }
    }

    private final KeyRing keys;
    private final Sensor sensor;
    private final AuditLog audit;
    private final Clock clock;
    private final Duration ackWithin;
    private final int maxDevices;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Entry> devices = new LinkedHashMap<>();
    private long refusedAcks;
    private long refusedFull;

    public DeviceIsolation(KeyRing keys, Sensor sensor, AuditLog audit, Clock clock, Duration ackWithin, int maxDevices) {
        this.keys = Objects.requireNonNull(keys, "keys");
        this.sensor = Objects.requireNonNull(sensor, "sensor");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.ackWithin = Objects.requireNonNull(ackWithin, "ackWithin");
        if (ackWithin.compareTo(Duration.ofSeconds(10)) < 0 || ackWithin.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("ackWithin is 10 seconds to 1 hour");
        }
        if (maxDevices < 1 || maxDevices > 100_000) {
            throw new IllegalArgumentException("maxDevices is 1 to 100,000");
        }
        this.maxDevices = maxDevices;
    }

    /**
     * Isolates a device for a case (the play's deny and revoke have already run). Idempotent per case.
     *
     * @return false if refused (full, audit down); the engine-side deny still holds
     */
    synchronized boolean isolate(String caseId, String deviceId, String actor) {
        Validate.id(caseId, "caseId");
        Validate.id(deviceId, "deviceId");
        Instant now = clock.instant();
        Entry e = devices.get(deviceId);
        if (e == null && devices.size() >= maxDevices && !forgetOneReleased()) {
            refusedFull++;
            return false;
        }
        if (e != null && e.cases.contains(caseId) && (e.state == State.PENDING_ACK || e.state == State.ISOLATED)) {
            return true;
        }
        boolean fresh = e == null || e.state == State.RELEASED || e.state == State.RELEASE_PENDING;
        if (!fresh) {
            if (!audited("ISOLATION_JOINED", actor, now, deviceId, e.command.id(), caseId)) {
                return false;
            }
            e.cases.add(caseId);
            return true;
        }
        IsolationCommand cmd = new IsolationCommand(newId(), deviceId, IsolationCommand.Action.ISOLATE, caseId, now);
        if (!audited("ISOLATION_REQUESTED", actor, now, deviceId, cmd.id(), caseId)) {
            return false;
        }
        Entry entry = e == null ? new Entry(deviceId) : e;
        entry.cases.clear();
        entry.cases.add(caseId);
        entry.state = State.PENDING_ACK;
        entry.command = cmd;
        entry.since = now;
        entry.delivered = deliver(cmd);
        devices.put(deviceId, entry);
        return true;
    }

    /**
     * Releases what {@code caseId} isolated. Called only after a signed verdict lifted the case's actions.
     *
     * @return the devices whose release command was issued
     */
    synchronized List<String> release(String caseId, String actor) {
        Instant now = clock.instant();
        List<String> released = new ArrayList<>();
        for (Entry e : devices.values()) {
            if (!e.cases.contains(caseId) || e.state == State.RELEASED || e.state == State.RELEASE_PENDING) {
                continue;
            }
            if (e.cases.size() > 1) {
                if (audited("ISOLATION_LEFT", actor, now, e.device, e.command.id(), caseId)) {
                    e.cases.remove(caseId);
                }
                continue;
            }
            IsolationCommand cmd = new IsolationCommand(newId(), e.device, IsolationCommand.Action.RELEASE, caseId, now);
            if (!audited("ISOLATION_RELEASE_REQUESTED", actor, now, e.device, cmd.id(), caseId)) {
                continue;
            }
            e.state = State.RELEASE_PENDING;
            e.command = cmd;
            e.since = now;
            e.delivered = deliver(cmd);
            released.add(e.device);
        }
        return released;
    }

    /** Checks and applies a sensor's acknowledgement. */
    public synchronized AckResult acknowledge(SensorAck ack) {
        Objects.requireNonNull(ack, "ack");
        Instant now = clock.instant();
        Entry e = devices.get(ack.deviceId());
        if (e == null || e.state == State.ISOLATED || e.state == State.RELEASED) {
            return refused(AckResult.NO_COMMAND);
        }
        if (!e.command.ackBody().equals(ack.body())) {
            return refused(AckResult.WRONG_BODY);
        }
        KeyRing.Result r = keys.verify(KeyPurpose.DEVICE_AGENT, ack.deviceId(), ack.proof(), ack.signedMessage(), now,
                ACK_MAX_AGE);
        if (!r.valid()) {
            return refused(AckResult.NOT_VERIFIED);
        }
        if (ack.batch() <= e.lastBatch) {
            return refused(AckResult.REPLAYED);
        }
        State next = e.state == State.PENDING_ACK ? State.ISOLATED : State.RELEASED;
        if (!audited(next == State.ISOLATED ? "ISOLATION_CONFIRMED" : "ISOLATION_RELEASED", ACTOR, now, e.device,
                e.command.id(), String.join(",", e.cases))) {
            return AckResult.UNAVAILABLE;
        }
        e.lastBatch = ack.batch();
        e.state = next;
        e.since = now;
        return AckResult.ACCEPTED;
    }

    /** Sends again every command not yet handed to its sensor; returns how many were delivered now. */
    public synchronized int redeliver() {
        int n = 0;
        for (Entry e : devices.values()) {
            if (!e.delivered && (e.state == State.PENDING_ACK || e.state == State.RELEASE_PENDING)) {
                e.delivered = deliver(e.command);
                n += e.delivered ? 1 : 0;
            }
        }
        return n;
    }

    public synchronized Optional<Isolation> of(String deviceId) {
        Entry e = devices.get(deviceId);
        return e == null ? Optional.empty() : Optional.of(view(e, clock.instant()));
    }

    public synchronized List<Isolation> all() {
        Instant now = clock.instant();
        return devices.values().stream().map(e -> view(e, now)).toList();
    }

    public synchronized long refusedAcks() {
        return refusedAcks;
    }

    public synchronized long refusedFull() {
        return refusedFull;
    }

    private Isolation view(Entry e, Instant now) {
        boolean waiting = e.state == State.PENDING_ACK || e.state == State.RELEASE_PENDING;
        return new Isolation(e.device, e.cases, e.state, e.command.id(), e.since, e.delivered,
                waiting && now.isAfter(e.since.plus(ackWithin)));
    }

    private boolean deliver(IsolationCommand cmd) {
        try {
            return sensor.deliver(cmd);
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private boolean forgetOneReleased() {
        var it = devices.values().iterator();
        while (it.hasNext()) {
            if (it.next().state == State.RELEASED) {
                it.remove();
                return true;
            }
        }
        return false;
    }

    private AckResult refused(AckResult why) {
        refusedAcks++;
        return why;
    }

    private String newId() {
        byte[] b = new byte[16];
        random.nextBytes(b);
        return "iso-" + HexFormat.of().formatHex(b);
    }

    private boolean audited(String type, String actor, Instant now, String device, String command, String cases) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("device", device);
        f.put("command", command);
        f.put("cases", cases);
        try {
            audit.append(type, Validate.id(actor, "actor"), now, f);
            return true;
        } catch (RuntimeException ex) {
            return false;
        }
    }
}

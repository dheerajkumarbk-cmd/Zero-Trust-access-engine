package dev.dwarpal.soar;

import dev.dwarpal.Fixtures;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.response.Playbooks;
import dev.dwarpal.response.ResponseSettings;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Verdict;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The SOAR end to end: verdicts, guard rails, isolation with signed acknowledgements, connectors. */
class SoarTest {

    private final SoarWorld w = new SoarWorld();

    private String honeytoken(String who, String device) {
        return w.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject(who), Entity.device(device),
                Entity.ip("203.0.113.9"));
    }

    // ---- isolation ------------------------------------------------------------------------------------------

    @Test
    void aConfirmedHoneytokenIsolatesTheDeviceOnlyOnceItsSensorSignsTheAcknowledgement() throws IOException {
        String al = honeytoken("alice", "laptop-alice");
        Soar.Result r = w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(Playbooks.Status.APPLIED, r.status());
        assertEquals(List.of("laptop-alice"), r.isolated());
        assertTrue(w.feed.denied(SignalFeed.Kind.DEVICE, "laptop-alice", w.now()), "engine side: the device is denied");
        assertTrue(w.sensor.isolated("laptop-alice"));
        assertEquals(DeviceIsolation.State.PENDING_ACK, w.isolation.of("laptop-alice").orElseThrow().state());
        assertEquals(List.of(DeviceIsolation.AckResult.ACCEPTED), w.pumpAcks());
        assertEquals(DeviceIsolation.State.ISOLATED, w.isolation.of("laptop-alice").orElseThrow().state());
        assertEquals(1, w.audited("ISOLATION_CONFIRMED"));
        String ticket = Files.readString(w.connectorDir.resolve("ticket.jsonl"));
        String chat = Files.readString(w.connectorDir.resolve("chat.jsonl"));
        assertTrue(ticket.contains("\"template\":\"action-taken\""), ticket);
        assertTrue(chat.contains("\"template\":\"device-isolated\""), chat);
        CaseView v = w.cases.view(w.caseOf(al)).orElseThrow();
        assertTrue(v.timeline().stream().anyMatch(t -> t.kind() == CaseView.TimelineEntry.Kind.ISOLATION));
        assertTrue(v.timeline().stream().anyMatch(t -> t.kind() == CaseView.TimelineEntry.Kind.NOTIFIED));
        assertTrue(v.acknowledgedAt().isPresent());
    }

    @Test
    void onlyASignedFalsePositiveVerdictReleasesTheDevice() {
        String al = honeytoken("alice", "laptop-alice");
        w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE);
        w.pumpAcks();
        // the engine-side deny ends by itself one day; the sensor stays isolated until a verdict
        w.later(Duration.ofDays(8));
        assertFalse(w.feed.denied(SignalFeed.Kind.DEVICE, "laptop-alice", w.now()), "denies always end");
        assertTrue(w.sensor.isolated("laptop-alice"), "the sensor waits for a verdict");
        Soar.Result fp = w.decide("ben", al, Verdict.Outcome.FALSE_POSITIVE);
        assertEquals(Playbooks.Status.UNDONE, fp.status());
        assertEquals(List.of("laptop-alice"), fp.released());
        assertFalse(w.feed.denied(SignalFeed.Kind.DEVICE, "laptop-alice", w.now()));
        assertEquals(DeviceIsolation.State.RELEASE_PENDING, w.isolation.of("laptop-alice").orElseThrow().state());
        assertEquals(List.of(DeviceIsolation.AckResult.ACCEPTED), w.pumpAcks());
        assertEquals(DeviceIsolation.State.RELEASED, w.isolation.of("laptop-alice").orElseThrow().state());
        assertFalse(w.sensor.isolated("laptop-alice"));
    }

    @Test
    void forgedReplayedOrStaleAcknowledgementsAreRefused() {
        String al = honeytoken("alice", "laptop-alice");
        w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE);
        SensorAck real = w.sensor.drain().getFirst();
        // signed by another device's own key
        SensorAck otherKey = new SensorAck("laptop-alice", "agent-laptop-carol", real.batch(), real.sealedAt(), real.body(),
                Ed25519.sign(SoarWorld.CAROL_LAPTOP.getPrivate(), real.signedMessage()));
        assertEquals(DeviceIsolation.AckResult.NOT_VERIFIED, w.isolation.acknowledge(otherKey));
        // a body that does not quote this command
        String wrong = real.body().replace("isolate", "release");
        SensorAck wrongBody = sign(real.batch(), real.sealedAt(), wrong);
        assertEquals(DeviceIsolation.AckResult.WRONG_BODY, w.isolation.acknowledge(wrongBody));
        // a stale signature
        SensorAck stale = sign(real.batch(), w.now().minus(Duration.ofMinutes(10)), real.body());
        assertEquals(DeviceIsolation.AckResult.NOT_VERIFIED, w.isolation.acknowledge(stale));
        // a tampered signature over the right body
        SensorAck tampered = new SensorAck(real.deviceId(), real.keyId(), real.batch() + 1, real.sealedAt(), real.body(),
                real.signature());
        assertEquals(DeviceIsolation.AckResult.NOT_VERIFIED, w.isolation.acknowledge(tampered));
        assertEquals(DeviceIsolation.State.PENDING_ACK, w.isolation.of("laptop-alice").orElseThrow().state());
        assertEquals(DeviceIsolation.AckResult.ACCEPTED, w.isolation.acknowledge(real));
        assertEquals(DeviceIsolation.AckResult.NO_COMMAND, w.isolation.acknowledge(real), "nothing waits any more");
        assertEquals(DeviceIsolation.AckResult.NO_COMMAND, w.isolation.acknowledge(
                new SensorAck("laptop-ceo", "agent-laptop-ceo", 9, w.now(), "{}", "c2lnbmF0dXJl")));
        assertEquals(6, w.isolation.refusedAcks());
    }

    @Test
    void aReleaseCannotBeAcknowledgedWithAnOldBatchNumber() {
        String al = honeytoken("alice", "laptop-alice");
        w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE);
        SensorAck first = w.sensor.drain().getFirst();
        assertEquals(DeviceIsolation.AckResult.ACCEPTED, w.isolation.acknowledge(first));
        w.decide("ben", al, Verdict.Outcome.FALSE_POSITIVE);
        SensorAck release = w.sensor.drain().getFirst();
        SensorAck lowBatch = sign(first.batch(), w.now(), release.body());
        assertEquals(DeviceIsolation.AckResult.REPLAYED, w.isolation.acknowledge(lowBatch));
        assertEquals(DeviceIsolation.AckResult.ACCEPTED, w.isolation.acknowledge(release));
    }

    @Test
    void anUnacknowledgedIsolationIsShownOverdueAndCanBeDeliveredAgain() {
        w.sensor.offline("laptop-alice", true);
        String al = honeytoken("alice", "laptop-alice");
        w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE);
        DeviceIsolation.Isolation i = w.isolation.of("laptop-alice").orElseThrow();
        assertFalse(i.delivered());
        assertFalse(i.overdue());
        assertTrue(w.feed.denied(SignalFeed.Kind.DEVICE, "laptop-alice", w.now()), "the deny holds anyway");
        w.later(Duration.ofMinutes(11));
        assertTrue(w.isolation.of("laptop-alice").orElseThrow().overdue());
        assertEquals(0, w.isolation.redeliver());
        w.sensor.offline("laptop-alice", false);
        assertEquals(1, w.isolation.redeliver());
        assertEquals(List.of(DeviceIsolation.AckResult.ACCEPTED), w.pumpAcks());
    }

    @Test
    void twoCasesIsolatingOneDeviceReleaseItOnlyWhenBothAreLifted() {
        String a1 = honeytoken("alice", "laptop-alice");
        w.decide("ana", a1, Verdict.Outcome.TRUE_POSITIVE);
        w.pumpAcks();
        String a2 = honeytoken("carol", "laptop-alice");
        w.decide("ana", a2, Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(2, w.isolation.of("laptop-alice").orElseThrow().cases().size());
        assertEquals(List.of(), w.decide("ben", a1, Verdict.Outcome.FALSE_POSITIVE).released());
        assertEquals(DeviceIsolation.State.ISOLATED, w.isolation.of("laptop-alice").orElseThrow().state());
        assertEquals(List.of("laptop-alice"), w.decide("ben", a2, Verdict.Outcome.FALSE_POSITIVE).released());
    }

    @Test
    void theProtectedCeosLaptopNeedsTwoAnalystsBeforeAnythingHappens() throws IOException {
        String al = honeytoken("ceo", "laptop-ceo");
        Soar.Result first = w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(Playbooks.Status.AWAITING_SECOND_ANALYST, first.status());
        assertTrue(first.isolated().isEmpty());
        assertFalse(w.sensor.isolated("laptop-ceo"));
        assertTrue(w.cases.view(w.caseOf(al)).orElseThrow().awaitingSecond());
        assertTrue(Files.readString(w.connectorDir.resolve("chat.jsonl")).contains("needs-second-analyst"));
        assertEquals(1, w.soar.pending().size());
        Soar.Result second = w.decide("ben", al, Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(Playbooks.Status.APPLIED, second.status());
        assertEquals(List.of("laptop-ceo"), second.isolated());
        assertEquals(List.of(DeviceIsolation.AckResult.ACCEPTED), w.pumpAcks());
        assertFalse(w.cases.view(w.caseOf(al)).orElseThrow().awaitingSecond());
    }

    @Test
    void isolationIsRefusedWhenFullOrWhenTheAuditTrailIsDown() {
        DeviceIsolation small = new DeviceIsolation(w.keys, w.sensor, w.audit, w.clock, Duration.ofMinutes(1), 1);
        assertTrue(small.isolate("case-1", "laptop-alice", "ana"));
        assertTrue(small.isolate("case-1", "laptop-alice", "ana"), "idempotent");
        assertTrue(small.isolate("case-2", "laptop-alice", "ana"), "joins");
        assertFalse(small.isolate("case-3", "laptop-ceo", "ana"), "full");
        assertEquals(1, small.refusedFull());
        w.auditDown.set(true);
        DeviceIsolation other = new DeviceIsolation(w.keys, w.sensor, w.audit, w.clock, Duration.ofMinutes(1), 10);
        assertFalse(other.isolate("case-1", "laptop-alice", "ana"));
        assertTrue(other.all().isEmpty());
        assertTrue(small.release("case-9", "ana").isEmpty());
    }

    @Test
    void isolationSettingsAreBounded() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> new DeviceIsolation(w.keys, w.sensor, w.audit, w.clock, Duration.ofSeconds(1), 10));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> new DeviceIsolation(w.keys, w.sensor, w.audit, w.clock, Duration.ofMinutes(1), 0));
        DeviceIsolation throwing = new DeviceIsolation(w.keys, c -> {
            throw new IllegalStateException("down");
        }, w.audit, w.clock, Duration.ofMinutes(1), 10);
        assertTrue(throwing.isolate("case-1", "laptop-alice", "ana"));
        assertFalse(throwing.of("laptop-alice").orElseThrow().delivered());
    }

    // ---- provenance and modes -------------------------------------------------------------------------------

    @Test
    void aCollectedOnlyAlertIsDecidedInWatchOnlyMode() {
        dev.dwarpal.soc.Alert a = w.alert(SoarWorld.MIXED_RULE, Severity.HIGH, Entity.subject("carol"),
                Entity.device("laptop-alice"));
        w.ranker.collectedAlerts.add(a.id());
        assertTrue(w.cases.raise(a));
        String forged = a.id();
        Soar.Result r = w.decide("ana", forged, Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(Playbooks.Status.APPLIED, r.status());
        assertEquals(Soar.Mode.WATCH_ONLY, r.mode().orElseThrow());
        assertTrue(r.isolated().isEmpty());
        assertFalse(w.feed.denied(SignalFeed.Kind.DEVICE, "laptop-alice", w.now()));
        assertFalse(w.sensor.isolated("laptop-alice"));
    }

    @Test
    void aCollectedAlertCannotRideOnACaseDecidedInFullMode() {
        SoarWorld tight = new SoarWorld(ResponseSettings.defaults().withProtected(Set.of("ana", "ben", "cleo", "ceo"),
                Set.of()).withLimits(20, 1, 100, 10), CaseSettings.defaults());
        String real = tight.raise("honeytoken-touched", Severity.CRITICAL, Entity.subject("alice"), Entity.ip("203.0.113.9"));
        // one destructive action per analyst per hour: the play runs partly, the case stays open in full mode
        assertEquals(Playbooks.Status.PARTIAL, tight.decide("ana", real, Verdict.Outcome.TRUE_POSITIVE).status());
        dev.dwarpal.soc.Alert forged = tight.alert(SoarWorld.MIXED_RULE, Severity.HIGH, Entity.subject("alice"),
                Entity.device("laptop-alice"));
        tight.ranker.collectedAlerts.add(forged.id());
        assertTrue(tight.cases.raise(forged));
        assertEquals(tight.caseOf(real), tight.caseOf(forged.id()), "the forged alert joined the real case");
        Soar.Result r = tight.decide("ben", forged.id(), Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(Playbooks.Status.REFUSED, r.status());
        assertTrue(r.message().contains("collected evidence"));
        assertFalse(tight.sensor.isolated("laptop-alice"));
        assertEquals(1, tight.audited("SOAR_VERDICT_REFUSED"));
        // a false positive on it is still possible
        assertTrue(tight.soar.metrics().refusedVerdicts() >= 1);
    }

    @Test
    void anAlertTheRankerNeverSawIsTreatedAsCollected() {
        dev.dwarpal.soc.Alert a = w.alert("honeytoken-touched", Severity.CRITICAL, Entity.subject("alice"),
                Entity.device("laptop-alice"));
        assertTrue(w.book.raise(a), "raised past case management");
        Soar.Result r = w.decide("ana", a.id(), Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(Soar.Mode.WATCH_ONLY, r.mode().orElseThrow());
        assertFalse(w.sensor.isolated("laptop-alice"));
    }

    @Test
    void refusedVerdictsChangeNothing() {
        String al = honeytoken("alice", "laptop-alice");
        Verdict good = w.verdict("ana", al, Verdict.Outcome.TRUE_POSITIVE);
        Verdict forged = new Verdict(al, "ana", Verdict.Outcome.TRUE_POSITIVE, new SignatureProof("soc-ana", w.now(),
                Ed25519.sign(SoarWorld.CLEO.getPrivate(), good.signedMessage())));
        assertEquals(Playbooks.Status.REFUSED, w.soar.handle(forged).status());
        assertEquals(Playbooks.Status.REFUSED, w.decide("ana", "al-unknown", Verdict.Outcome.TRUE_POSITIVE).status());
        assertFalse(w.sensor.isolated("laptop-alice"));
    }

    @Test
    void aFalsePositiveOnAnOldPlaybookVersionUndoesWhatThatVersionDid() {
        String al = w.raise("deny-storm-ip", Severity.HIGH, Entity.subject("alice"), Entity.ip("198.51.100.77"));
        assertEquals(Playbooks.Status.APPLIED, w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE).status());
        assertTrue(w.feed.denied(SignalFeed.Kind.IP, "198.51.100.77", w.now()));
        String quiet = SoarWorld.TEST_PLAYBOOKS.replace("version: \"test-1\"", "version: \"test-quiet\"")
                .replace("  - rule: deny-storm-ip\n    steps:\n      - deny: {target: ip, for: PT4H}\n"
                        + "      - watch: {target: subject, ratio: 10, halfLife: P1D}", "  - rule: deny-storm-ip\n"
                        + "    steps: []");
        assertTrue(quiet.contains("deny-storm-ip\n    steps: []"));
        String later = w.raise("deny-storm-ip", Severity.HIGH, Entity.subject("carol"), Entity.ip("198.51.100.78"));
        w.soar.activate(new PlaybookInstaller.Installed(2, w.compile(quiet)));
        assertEquals(2, w.soar.metrics().generationsInUse());
        Soar.Result undo = w.decide("ben", al, Verdict.Outcome.FALSE_POSITIVE);
        assertEquals(Playbooks.Status.UNDONE, undo.status());
        assertFalse(w.feed.denied(SignalFeed.Kind.IP, "198.51.100.77", w.now()));
        // a case first decided after the install uses the new, quiet version
        assertEquals(0, w.decide("ana", later, Verdict.Outcome.TRUE_POSITIVE).actions());
        assertFalse(w.feed.denied(SignalFeed.Kind.IP, "198.51.100.78", w.now()));
    }

    // ---- connectors -----------------------------------------------------------------------------------------

    @Test
    void aFailingConnectorNeverStopsTheResponse() {
        Connector broken = new Connector() {
            @Override
            public String name() {
                return "ticket";
            }

            @Override
            public Kind kind() {
                return Kind.TICKET;
            }

            @Override
            public boolean send(Notification n) {
                throw new IllegalStateException("ticket system down");
            }
        };
        w.soar = w.soar(w.compile(SoarWorld.TEST_PLAYBOOKS), b -> b.connectors(List.of(broken,
                w.connectors.get(1))));
        String al = honeytoken("alice", "laptop-alice");
        assertEquals(Playbooks.Status.APPLIED, w.decide("ana", al, Verdict.Outcome.TRUE_POSITIVE).status());
        assertEquals(1, w.soar.metrics().notifyFailures());
        assertTrue(w.cases.view(w.caseOf(al)).orElseThrow().timeline().stream()
                .anyMatch(t -> t.detail().contains("not sent")));
    }

    @Test
    void connectorsCannotBeConfiguredTwice() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> w.soar(w.compile(SoarWorld.TEST_PLAYBOOKS), b -> b.connectors(List.of(w.connectors.get(0),
                        w.connectors.get(0)))));
        assertEquals(Set.of("ticket", "chat"), w.soar.connectorNames());
    }

    @Test
    void benignAndFalsePositiveVerdictsCloseCasesWithoutAction() {
        String a1 = w.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice"));
        assertEquals(Playbooks.Status.CLOSED, w.decide("ana", a1, Verdict.Outcome.BENIGN).status());
        String a2 = w.raise("pam-refused", Severity.MEDIUM, Entity.subject("carol"));
        assertEquals(Playbooks.Status.CLOSED, w.decide("ana", a2, Verdict.Outcome.FALSE_POSITIVE).status());
        assertEquals(0, w.soar.metrics().pending());
    }

    /** The sensor signs with the agent key of laptop-alice (from the shared fixtures). */
    private SensorAck sign(long batch, Instant at, String body) {
        return new SensorAck("laptop-alice", Fixtures.DEVICE_KEY_ID, batch, at, body, Ed25519.sign(
                Fixtures.DEVICE_AGENT.getPrivate(), SignedMessages.endpointTelemetry("laptop-alice", batch, at,
                        Digests.sha256Hex(body))));
    }
}

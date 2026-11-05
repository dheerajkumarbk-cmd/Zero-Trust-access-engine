package dev.dwarpal.integration;

import dev.dwarpal.analytics.AuditDecisions;
import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.AuditSource;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.response.Case;
import dev.dwarpal.response.CaseBook;
import dev.dwarpal.response.Enforcement;
import dev.dwarpal.response.Playbooks;
import dev.dwarpal.response.ResponseSettings;
import dev.dwarpal.response.SignalLedger;
import dev.dwarpal.response.VerdictGate;
import dev.dwarpal.siem.DetectionEngine;
import dev.dwarpal.siem.EncryptedAuditStore;
import dev.dwarpal.siem.HeadAnchor;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertSink;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Verdict;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Layer 5 integration: the SOC loop across parts A (encrypted store, anchor, detection), B (cases, verdicts,
 * playbooks) and C (analytics) on the shared simulated organisation (seed 7, 60 users). The numbers measure
 * consistency with the threat model, not real-world accuracy.
 */
class Layer5EndToEndTest {

    @TempDir
    Path dir;

    private static SecretKey key(String algorithm, int bits) {
        try {
            KeyGenerator g = KeyGenerator.getInstance(algorithm);
            g.init(bits);
            return g.generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Collects alerts in order, for comparing two detection runs. */
    private static final class Collect implements AlertSink {
        final List<Alert> alerts = new ArrayList<>();

        @Override
        public boolean raise(Alert alert) {
            alerts.add(alert);
            return true;
        }
    }

    private static void detectAll(AuditSource source, SecretKey auditKey, AlertSink sink,
                                  Supplier<Optional<AuditLog.Head>> anchor) {
        DetectionEngine d = new DetectionEngine(source, auditKey, sink, anchor, DetectionEngine.Settings.defaults());
        while (d.poll().events() > 0) {
            // read the whole trail
        }
        d.flush();
        assertEquals(Optional.empty(), d.stopped(), "the trail is intact and agrees with its anchor");
    }

    private static Enforcement noSessions(SimOrganisation org) {
        return new Enforcement() {
            @Override
            public int revokeSession(String s, String a, String r) {
                return 0;
            }

            @Override
            public int revokeSubject(String s, String a, String r) {
                return 0;
            }

            @Override
            public int revokeDevice(String s, String a, String r) {
                return 0;
            }

            @Override
            public Set<String> rolesOf(String s, Instant n) {
                return org.directory.subject(s).map(x -> x.roles()).orElse(Set.of());
            }
        };
    }

    private static Playbooks playbooks(SimOrganisation org, ResponseSettings settings, CaseBook book) {
        return Playbooks.builder(org.audit, new SignalLedger(org.signals, org.clock)).settings(settings).cases(book)
                .verdicts(new VerdictGate(org.keys, org.clock)).clock(org.clock).enforcement(noSessions(org)).build();
    }

    /** The trail written by the simulation, copied into part A's encrypted store and anchored. */
    private EncryptedAuditStore storeOf(SimOrganisation org, Path file) {
        EncryptedAuditStore store = EncryptedAuditStore.open(file, key("AES", 256),
                EncryptedAuditStore.Durability.OS_BUFFERED);
        for (AuditRecord r : org.sink.snapshot()) {
            store.write(r);
        }
        return store;
    }

    @Test
    void theEncryptedStoreFeedsDetectionAndAnalyticsExactlyLikeTheTrailItHolds() throws Exception {
        SimOrganisation org = SimOrganisation.create(7, 60);
        org.run(org.pipeline(org.engine()), org.traffic());
        try (EncryptedAuditStore store = storeOf(org, dir.resolve("audit.dws"))) {
            HeadAnchor anchor = new HeadAnchor(dir.resolve("anchor"), key("HmacSHA256", 256), org.clock);
            anchor.anchor(store.head());

            Collect fromStore = new Collect();
            detectAll(store, org.auditKey, fromStore, anchor::read);
            Collect fromMemory = new Collect();
            detectAll(org.sink, org.auditKey, fromMemory, Optional::empty);
            assertFalse(fromStore.alerts.isEmpty());
            assertEquals(fromMemory.alerts, fromStore.alerts, "same trail, same alerts, wherever it is stored");

            int max = org.sink.snapshot().size();
            AuditDecisions.Result a = AuditDecisions.read(AuditCursor.fromStart(store, org.auditKey), max);
            AuditDecisions.Result b = AuditDecisions.read(AuditCursor.fromStart(org.sink, org.auditKey), max);
            assertEquals(b.entries(), a.entries(), "part C reads part A's store unchanged");
            assertTrue(a.entries().size() > 0);
        }
    }

    @Test
    void afterARestartTheWriterContinuesTheEncryptedTrailAndAStaleHeadIsRefused() throws Exception {
        SimOrganisation org = SimOrganisation.create(7, 20);
        org.run(org.pipeline(org.engine()), org.traffic());
        Path file = dir.resolve("audit.dws");
        SecretKey aes = key("AES", 256);
        AuditLog.Head before;
        try (EncryptedAuditStore store = EncryptedAuditStore.open(file, aes, EncryptedAuditStore.Durability.OS_BUFFERED)) {
            for (AuditRecord r : org.sink.snapshot()) {
                store.write(r);
            }
            before = store.head();
        }
        try (EncryptedAuditStore store = EncryptedAuditStore.open(file, aes, EncryptedAuditStore.Durability.OS_BUFFERED)) {
            assertEquals(before, store.head());
            // Probe (before integration): new AuditLog(key, store) restarted at sequence 1 and was refused.
            assertThrows(IllegalStateException.class, () -> new AuditLog(org.auditKey, store)
                    .append("SERVICE_STARTED", "dwarpal", org.clock.instant(), Map.of()));
            AuditLog resumed = new AuditLog(org.auditKey, store, store.head());
            resumed.append("SERVICE_STARTED", "dwarpal", org.clock.instant(), Map.of("note", "after restart"));
            assertEquals(before.sequence() + 1, store.head().sequence());

            AuditCursor c = AuditCursor.fromStart(store, org.auditKey);
            long read = 0;
            for (AuditCursor.Batch batch = c.next(5_000); !batch.events().isEmpty(); batch = c.next(5_000)) {
                assertEquals(Optional.empty(), batch.problem());
                read += batch.events().size();
            }
            assertEquals(before.sequence() + 1, read, "one unbroken chain across the restart");

            AuditLog stale = new AuditLog(org.auditKey, store, before);
            assertThrows(IllegalStateException.class,
                    () -> stale.append("FORK", "x", org.clock.instant(), Map.of()), "no fork of the chain");
        }
        assertThrows(IllegalArgumentException.class,
                () -> new AuditLog(org.auditKey, new dev.dwarpal.audit.InMemoryAuditSink(), new AuditLog.Head(-1, AuditLog.GENESIS)));
        assertThrows(IllegalArgumentException.class,
                () -> new AuditLog(org.auditKey, new dev.dwarpal.audit.InMemoryAuditSink(), new AuditLog.Head(3, "nothex")));
        assertThrows(IllegalArgumentException.class,
                () -> new AuditLog(org.auditKey, new dev.dwarpal.audit.InMemoryAuditSink(), new AuditLog.Head(0, "a".repeat(64))));
    }

    @Test
    void detectionOpensCasesAndAConfirmedCaseBlocksTheAttackersAddress() {
        SimOrganisation org = SimOrganisation.create(7, 60);
        org.run(org.pipeline(org.engine()), org.traffic());
        ResponseSettings settings = ResponseSettings.defaults();
        CaseBook book = new CaseBook(settings, org.audit, org.clock);
        detectAll(org.sink, org.auditKey, book, Optional::empty);

        Map<String, Integer> byRule = new TreeMap<>();
        for (Case c : book.unresolved()) {
            for (Alert a : c.alerts()) {
                byRule.merge(a.rule(), 1, Integer::sum);
                assertTrue(Playbooks.referencePlays().containsKey(a.rule()), "a play for " + a.rule());
            }
        }
        assertTrue(byRule.containsKey("deny-storm-ip"), "Tor or spray traffic becomes a case: " + byRule);

        Alert storm = book.unresolved().stream().flatMap(c -> c.alerts().stream())
                .filter(a -> a.rule().equals("deny-storm-ip")).findFirst().orElseThrow();
        String ip = storm.entities().stream().filter(e -> e.kind() == Entity.Kind.IP).findFirst().orElseThrow().id();
        Playbooks pb = playbooks(org, settings, book);
        Instant now = org.clock.instant();
        assertFalse(org.signals.denied(SignalFeed.Kind.IP, ip, now));
        assertEquals(Playbooks.Status.APPLIED,
                pb.handle(org.verdict("ana", storm.id(), Verdict.Outcome.TRUE_POSITIVE, now)).status());
        assertTrue(org.signals.denied(SignalFeed.Kind.IP, ip, now), "the address is blocked for the engine");
        assertFalse(org.signals.denied(SignalFeed.Kind.IP, ip, now.plus(Duration.ofHours(5))), "and only for 4 hours");
    }

    /** Request C-4: sensitivity can rebuild an engine with other costs, but not with a second MFA beta. */
    @Test
    void anEngineCanBeCopiedWithOtherCostsButNotWithADisagreeingBeta() {
        SimOrganisation org = SimOrganisation.create(7, 10);
        dev.dwarpal.engine.PolicyEngine engine = org.engine();
        dev.dwarpal.decision.CostModel c = engine.costModel();
        dev.dwarpal.decision.CostModel dearer = new dev.dwarpal.decision.CostModel(c.breachCost() * 2,
                c.frictionCost(), c.wrongDenyCost(), c.stepUpBypassProbability());
        assertEquals(dearer, engine.withCostModel(dearer).costModel());
        double otherBeta = c.stepUpBypassProbability() / 2;
        assertThrows(IllegalArgumentException.class, () -> engine.withCostModel(new dev.dwarpal.decision.CostModel(
                c.breachCost(), c.frictionCost(), c.wrongDenyCost(), otherBeta)));
        assertEquals(engine.checksFreshness(), engine.withCostModel(dearer).checksFreshness());
    }

    /**
     * Cross-part red team (requests A-4 and B-5): anyone can send requests in someone else's name, so an attacker
     * who floods the trail with denied requests "as the CEO" makes part A raise deny-storm alerts naming the CEO.
     * Even when an analyst confirms the alert, part B must block the attacker's address and only watch the CEO.
     */
    @Test
    void junkInTheCeosNameBlocksTheSenderButNeverLocksOutTheCeo() {
        SimOrganisation org = SimOrganisation.create(7, 60);
        org.run(org.pipeline(org.engine()), org.traffic());
        String ceo = org.users.getFirst().id();
        String attacker = "203.0.113.5";
        Instant t = org.clock.instant().plusSeconds(60);
        for (int i = 0; i < 6; i++) {
            Map<String, String> f = new LinkedHashMap<>();
            f.put("requestId", "junk-" + i);
            f.put("outcome", "DENY");
            f.put("subject", ceo);
            f.put("device", "unknown-device");
            f.put("sourceIp", attacker);
            f.put("policy", "default-deny");
            f.put("signals", "");
            org.clock.set(t.plusSeconds(i * 10L));
            org.audit.append("ACCESS_DECISION", "pdp", org.clock.instant(), f);
        }
        ResponseSettings settings = ResponseSettings.defaults().withProtected(Set.of(ceo), Set.of());
        CaseBook book = new CaseBook(settings, org.audit, org.clock);
        detectAll(org.sink, org.auditKey, book, Optional::empty);
        Alert alert = book.unresolved().stream().flatMap(c -> c.alerts().stream())
                .filter(a -> a.rule().equals("deny-storm-subject") && a.entities().contains(Entity.subject(ceo)))
                .findFirst().orElseThrow();
        assertTrue(alert.entities().contains(Entity.ip(attacker)));

        Playbooks pb = playbooks(org, settings, book);
        Instant now = org.clock.instant();
        Playbooks.Status first = pb.handle(org.verdict("ana", alert.id(), Verdict.Outcome.TRUE_POSITIVE, now)).status();
        if (first == Playbooks.Status.AWAITING_SECOND_ANALYST) {
            assertEquals(Playbooks.Status.APPLIED,
                    pb.handle(org.verdict("ben", alert.id(), Verdict.Outcome.TRUE_POSITIVE, now)).status());
        } else {
            assertEquals(Playbooks.Status.APPLIED, first);
        }
        assertTrue(org.signals.denied(SignalFeed.Kind.IP, attacker, now), "the sender is blocked");
        assertFalse(org.signals.denied(SignalFeed.Kind.SUBJECT, ceo, now), "the CEO is never denied");
        double watch = org.signals.watchLogLr(SignalFeed.Kind.SUBJECT, ceo, now);
        assertTrue(watch > 0 && watch <= Math.log(10) + 1e-9, "only a small watch on the CEO: " + watch);
    }
}

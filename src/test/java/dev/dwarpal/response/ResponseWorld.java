package dev.dwarpal.response;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.AuditSink;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.crypto.TrustedKey;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.domain.SubjectType;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.engine.DenyListGate;
import dev.dwarpal.engine.HoneytokenGate;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.engine.PolicyEngineTest;
import dev.dwarpal.pam.PamSettings;
import dev.dwarpal.pam.PrivilegedAccessManager;
import dev.dwarpal.pip.InMemoryDirectory;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.runtime.DecisionPipeline;
import dev.dwarpal.session.PolicyAdministrator;
import dev.dwarpal.session.SessionGrant;
import dev.dwarpal.session.SessionResult;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Verdict;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A small organisation for the response loop: alice and carol (engineers), root (admin), the analysts
 * ana, ben and cleo, a real Policy Administrator, PAM, signal feed and an engine that reads the feed.
 * Analyst keys of ana and ben are the shared {@link SimOrganisation} ones; cleo's and the wrong-purpose
 * key are made at run time (no key material in the source).
 */
final class ResponseWorld {

    static final Instant T = SimOrganisation.DAY_ZERO;
    static final KeyPair CLEO = Ed25519.generateKeyPair();
    /** An identity-provider key bound to "ana": right owner, wrong purpose. */
    static final KeyPair ANA_IDP = Ed25519.generateKeyPair();

    final SimOrganisation.SimClock clock = new SimOrganisation.SimClock();
    final InMemoryAuditSink sink = new InMemoryAuditSink();
    /** Set to make every audit write fail (disk full). */
    final AtomicBoolean auditDown = new AtomicBoolean();
    final SecretKey auditKey = newKey();
    final AuditLog audit = new AuditLog(auditKey, guarded(sink, auditDown));
    final KeyRing keys;
    final InMemoryDirectory directory;
    final SignalFeed feed;
    final SignalLedger ledger;
    final CaseBook book;
    final VerdictGate gate;
    final PrivilegedAccessManager pam;
    final PolicyAdministrator pa;
    final PolicyEngine engine;
    final Counting enforcement;
    final ResponseSettings settings;
    Playbooks playbooks;
    private int alerts;
    private int requests;

    ResponseWorld() {
        this(ResponseSettings.defaults().withProtected(Set.of("ana", "ben", "cleo"), Set.of("198.51.100.1")));
    }

    ResponseWorld(ResponseSettings settings) {
        this.settings = settings;
        clock.set(T);
        Instant from = T.minus(Duration.ofDays(400));
        Instant to = T.plus(Duration.ofDays(400));
        keys = new KeyRing(List.of(
                new TrustedKey("soc-ana", KeyPurpose.SOC_ANALYST, "ana", SimOrganisation.ANALYST_ANA.getPublic(), from, to),
                new TrustedKey("soc-ben", KeyPurpose.SOC_ANALYST, "ben", SimOrganisation.ANALYST_BEN.getPublic(), from, to),
                new TrustedKey("soc-cleo", KeyPurpose.SOC_ANALYST, "cleo", CLEO.getPublic(), from, to),
                new TrustedKey("idp-ana", KeyPurpose.IDENTITY_PROVIDER, "ana", ANA_IDP.getPublic(), from, to),
                new TrustedKey(Fixtures.DEVICE_KEY_ID, KeyPurpose.DEVICE_AGENT, "laptop-alice",
                        Fixtures.DEVICE_AGENT.getPublic(), from, to),
                new TrustedKey(Fixtures.IDP_KEY_ID, KeyPurpose.IDENTITY_PROVIDER, "corp-idp", Fixtures.IDP.getPublic(),
                        from, to)));
        List<Subject> people = new ArrayList<>();
        for (String p : List.of("alice", "carol", "ana", "ben", "cleo", "dave", "erin")) {
            people.add(new Subject(p, SubjectType.HUMAN, Set.of("engineer"), "engineering"));
        }
        people.add(new Subject("root", SubjectType.HUMAN, Set.of("admin", "engineer"), "it"));
        directory = new InMemoryDirectory(people,
                List.of(new Resource("wiki", ResourceKind.PRIVATE_APP, DataClassification.INTERNAL)),
                List.of("laptop-alice", "laptop-carol"));
        feed = new SignalFeed(Set.of(), audit, clock);
        ledger = new SignalLedger(feed, clock);
        book = new CaseBook(settings, audit, clock);
        gate = new VerdictGate(keys, clock);
        pam = new PrivilegedAccessManager(keys, Map.of(), Map.of(), PamSettings.defaults(), audit, clock, s -> { });
        engine = PolicyEngine.builder().policySet(PolicyEngineTest.POLICIES).directory(directory).keyRing(keys)
                .gate(new HoneytokenGate()).gate(new DenyListGate())
                .scorers(List.of(new WatchlistScorer(feed, clock)))
                .aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                .costModel(new CostModel(1000, 1, 20, 0.05)).build();
        DecisionPoint pdp = DecisionPipeline.continuous(engine, audit, clock);
        pa = PolicyAdministrator.builder(audit).opening(pdp).continuous(pdp).directory(directory).keyRing(keys)
                .clock(clock).allowLoginWithoutMfa().build();
        enforcement = new Counting(Enforcement.of(pa, pam, directory));
        playbooks = playbooks(b -> { });
    }

    Playbooks playbooks(java.util.function.Consumer<Playbooks.Builder> tweak) {
        Playbooks.Builder b = Playbooks.builder(audit, ledger).settings(settings).cases(book).verdicts(gate)
                .enforcement(enforcement).clock(clock);
        tweak.accept(b);
        return b.build();
    }

    void later(Duration d) {
        clock.set(clock.instant().plus(d));
    }

    Instant now() {
        return clock.instant();
    }

    /** An alert raised now and put in the case book; returns its id. */
    String raise(String rule, Severity severity, Entity... entities) {
        Alert a = alert(rule, severity, entities);
        if (!book.raise(a)) {
            throw new AssertionError("case book refused " + a.id());
        }
        return a.id();
    }

    Alert alert(String rule, Severity severity, Entity... entities) {
        alerts++;
        return new Alert("al-" + rule + "-" + alerts, rule, severity, now(), Arrays.asList(entities),
                List.of((long) alerts), 1, rule + " on " + entities[0].id());
    }

    Verdict verdict(String analyst, String alertId, Verdict.Outcome outcome) {
        return verdict(analyst, alertId, outcome, now());
    }

    Verdict verdict(String analyst, String alertId, Verdict.Outcome outcome, Instant at) {
        KeyPair k = switch (analyst) {
            case "ana" -> SimOrganisation.ANALYST_ANA;
            case "ben" -> SimOrganisation.ANALYST_BEN;
            case "cleo" -> CLEO;
            default -> throw new IllegalArgumentException("unknown analyst");
        };
        return new Verdict(alertId, analyst, outcome, new SignatureProof("soc-" + analyst, at,
                Ed25519.sign(k.getPrivate(), SignedMessages.socVerdict(alertId, analyst, outcome.name(), at))));
    }

    Playbooks.Result decide(String analyst, String alertId, Verdict.Outcome outcome) {
        return playbooks.handle(verdict(analyst, alertId, outcome));
    }

    long audited(String type) {
        return sink.snapshot().stream().map(AuditRecord::type).filter(type::equals).count();
    }

    List<AuditRecord> records(String type) {
        return sink.snapshot().stream().filter(r -> r.type().equals(type)).toList();
    }

    /** Alice logs in on her laptop now (signed posture, bound to a fresh session key). */
    SessionResult aliceLogsIn() {
        return logIn("alice", "laptop-alice", Ed25519.generateKeyPair());
    }

    SessionResult logIn(String subject, String device, KeyPair sessionKey) {
        requests++;
        AccessRequest r = Fixtures.request().id("rq-" + requests).at(now()).subject(subject).device(device).build();
        SignatureProof bind = new SignatureProof(Fixtures.DEVICE_KEY_ID, now(), Ed25519.sign(
                Fixtures.DEVICE_AGENT.getPrivate(), SignedMessages.sessionBinding(device, r.requestId(),
                        Digests.thumbprint(sessionKey.getPublic()), now())));
        return pa.open(r, feed.snapshot(now()), sessionKey.getPublic(), bind);
    }

    /** One request of alice's straight to the engine, with the feed's current signals. */
    dev.dwarpal.decision.Decision aliceAsks() {
        requests++;
        AccessRequest r = Fixtures.request().id("rq-" + requests).at(now()).build();
        return engine.decide(r, feed.snapshot(now()));
    }

    static SessionGrant grant(SessionResult r) {
        return r.grant().orElseThrow(() -> new AssertionError(r.status() + ": " + r.reason()));
    }

    static SecretKey newKey() {
        try {
            return KeyGenerator.getInstance("HmacSHA256").generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static AuditSink guarded(InMemoryAuditSink sink, AtomicBoolean down) {
        return r -> {
            if (down.get()) {
                throw new IllegalStateException("audit store unavailable");
            }
            sink.write(r);
        };
    }

    /** Real enforcement, counted, and able to fail on demand. */
    static final class Counting implements Enforcement {
        final Enforcement real;
        final AtomicInteger subjects = new AtomicInteger();
        final AtomicInteger devices = new AtomicInteger();
        final AtomicInteger sessions = new AtomicInteger();
        final List<String> revoked = Collections.synchronizedList(new ArrayList<>());
        final AtomicBoolean down = new AtomicBoolean();
        final AtomicBoolean directoryDown = new AtomicBoolean();

        Counting(Enforcement real) {
            this.real = real;
        }

        private void check() {
            if (down.get()) {
                throw new IllegalStateException("policy administrator unreachable");
            }
        }

        @Override
        public int revokeSession(String sessionId, String actor, String reason) {
            check();
            sessions.incrementAndGet();
            revoked.add("session:" + sessionId);
            return real.revokeSession(sessionId, actor, reason);
        }

        @Override
        public int revokeSubject(String subjectId, String actor, String reason) {
            check();
            subjects.incrementAndGet();
            revoked.add("subject:" + subjectId);
            return real.revokeSubject(subjectId, actor, reason);
        }

        @Override
        public int revokeDevice(String deviceId, String actor, String reason) {
            check();
            devices.incrementAndGet();
            revoked.add("device:" + deviceId);
            return real.revokeDevice(deviceId, actor, reason);
        }

        @Override
        public Set<String> rolesOf(String subjectId, Instant now) {
            if (directoryDown.get()) {
                throw new IllegalStateException("directory unreachable");
            }
            return real.rolesOf(subjectId, now);
        }

        int destructive() {
            return subjects.get() + devices.get() + sessions.get();
        }
    }
}

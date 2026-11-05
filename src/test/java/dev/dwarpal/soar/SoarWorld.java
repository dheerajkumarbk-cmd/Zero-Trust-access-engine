package dev.dwarpal.soar;

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
import dev.dwarpal.decision.Decision;
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
import dev.dwarpal.response.CaseBook;
import dev.dwarpal.response.Enforcement;
import dev.dwarpal.response.ResponseSettings;
import dev.dwarpal.response.SignalLedger;
import dev.dwarpal.response.VerdictGate;
import dev.dwarpal.response.WatchlistScorer;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.runtime.DecisionPipeline;
import dev.dwarpal.session.PolicyAdministrator;
import dev.dwarpal.session.SessionResult;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertRanker;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Techniques;
import dev.dwarpal.soc.Verdict;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * A small organisation for part F: people alice, carol, dave and the CEO; root (admin); analysts ana and ben and the
 * lead cleo; administrators adm1 and adm2 who sign playbook bundles; the laptops of alice and the CEO with
 * simulated sensors; a real Policy Administrator, PAM, signal feed and an engine that reads the feed; a fake ranker
 * (part E builds the real one). Keys are made at run time; nothing secret is in the source.
 */
public final class SoarWorld {

    public static final Instant T = SimOrganisation.DAY_ZERO;
    public static final KeyPair CLEO = Ed25519.generateKeyPair();
    public static final KeyPair ADM1 = Ed25519.generateKeyPair();
    public static final KeyPair ADM1_SECOND = Ed25519.generateKeyPair();
    public static final KeyPair ADM2 = Ed25519.generateKeyPair();
    public static final KeyPair CEO_LAPTOP = Ed25519.generateKeyPair();
    /** A device agent key of another device (bound to laptop-carol). */
    public static final KeyPair CAROL_LAPTOP = Ed25519.generateKeyPair();
    public static final Analyst ANA = new Analyst("ana", Analyst.Role.ANALYST);
    public static final Analyst BEN = new Analyst("ben", Analyst.Role.ANALYST);
    public static final Analyst LEAD = new Analyst("cleo", Analyst.Role.LEAD);
    /** A rule of part D's kind whose alerts rest on firewall syslog only. */
    public static final String SYSLOG_RULE = "fw-port-scan";
    /** A part D rule that mixes collected and signed evidence (decided per alert). */
    public static final String MIXED_RULE = "beacon-correlated";

    public final SimOrganisation.SimClock clock = new SimOrganisation.SimClock();
    public final InMemoryAuditSink sink = new InMemoryAuditSink();
    public final AtomicBoolean auditDown = new AtomicBoolean();
    public final AuditLog audit = new AuditLog(newKey(), guarded(sink, auditDown));
    public final KeyRing keys;
    public final InMemoryDirectory directory;
    public final SignalFeed feed;
    public final SignalLedger ledger;
    public final ResponseSettings settings;
    public final CaseBook book;
    public final VerdictGate gate;
    public final PrivilegedAccessManager pam;
    public final PolicyAdministrator pa;
    public final PolicyEngine engine;
    public final Enforcement enforcement;
    public final FakeRanker ranker = new FakeRanker();
    public final CaseManager cases;
    public final SimulatedSensor sensor;
    public final DeviceIsolation isolation;
    public final Path connectorDir;
    public final RuleCatalogue catalogue;
    public final List<Connector> connectors = new ArrayList<>();
    /** The CEO's laptop: owned by a protected person, criticality 5. Alice's: an ordinary laptop. */
    public final dev.dwarpal.soc.InMemoryAssetCatalog assets = new dev.dwarpal.soc.InMemoryAssetCatalog(List.of(
            new dev.dwarpal.soc.Asset(Entity.device("laptop-ceo"), 5, "ceo", Set.of("executive"), true),
            new dev.dwarpal.soc.Asset(Entity.device("laptop-alice"), 2, "alice", Set.of(), true)));
    public Soar soar;
    private int alerts;
    private int requests;

    public SoarWorld() {
        this(ResponseSettings.defaults().withProtected(Set.of("ana", "ben", "cleo", "ceo"), Set.of("198.51.100.1")),
                CaseSettings.defaults());
    }

    public SoarWorld(ResponseSettings settings, CaseSettings caseSettings) {
        this.settings = settings;
        clock.set(T);
        Instant from = T.minus(Duration.ofDays(400));
        Instant to = T.plus(Duration.ofDays(400));
        keys = new KeyRing(List.of(
                new TrustedKey("soc-ana", KeyPurpose.SOC_ANALYST, "ana", SimOrganisation.ANALYST_ANA.getPublic(), from, to),
                new TrustedKey("soc-ben", KeyPurpose.SOC_ANALYST, "ben", SimOrganisation.ANALYST_BEN.getPublic(), from, to),
                new TrustedKey("soc-cleo", KeyPurpose.SOC_ANALYST, "cleo", CLEO.getPublic(), from, to),
                new TrustedKey("adm1", KeyPurpose.POLICY_SIGNER, "adm1", ADM1.getPublic(), from, to),
                new TrustedKey("adm1-b", KeyPurpose.POLICY_SIGNER, "adm1", ADM1_SECOND.getPublic(), from, to),
                new TrustedKey("adm2", KeyPurpose.POLICY_SIGNER, "adm2", ADM2.getPublic(), from, to),
                new TrustedKey(Fixtures.DEVICE_KEY_ID, KeyPurpose.DEVICE_AGENT, "laptop-alice",
                        Fixtures.DEVICE_AGENT.getPublic(), from, to),
                new TrustedKey("agent-laptop-ceo", KeyPurpose.DEVICE_AGENT, "laptop-ceo", CEO_LAPTOP.getPublic(), from, to),
                new TrustedKey("agent-laptop-carol", KeyPurpose.DEVICE_AGENT, "laptop-carol", CAROL_LAPTOP.getPublic(),
                        from, to),
                new TrustedKey(Fixtures.IDP_KEY_ID, KeyPurpose.IDENTITY_PROVIDER, "corp-idp", Fixtures.IDP.getPublic(),
                        from, to)));
        List<Subject> people = new ArrayList<>();
        for (String p : List.of("alice", "carol", "dave", "ceo", "ana", "ben", "cleo")) {
            people.add(new Subject(p, SubjectType.HUMAN, Set.of("engineer"), "engineering"));
        }
        people.add(new Subject("root", SubjectType.HUMAN, Set.of("admin", "engineer"), "it"));
        directory = new InMemoryDirectory(people,
                List.of(new Resource("wiki", ResourceKind.PRIVATE_APP, DataClassification.INTERNAL)),
                List.of("laptop-alice", "laptop-carol", "laptop-ceo"));
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
        enforcement = Enforcement.of(pa, pam, directory);
        cases = new CaseManager(book, ranker, audit, clock, caseSettings, List.of(ANA, BEN, LEAD));
        sensor = new SimulatedSensor(clock).enrol("laptop-alice", Fixtures.DEVICE_KEY_ID, Fixtures.DEVICE_AGENT.getPrivate())
                .enrol("laptop-ceo", "agent-laptop-ceo", CEO_LAPTOP.getPrivate());
        isolation = new DeviceIsolation(keys, sensor, audit, clock, Duration.ofMinutes(10), 1_000);
        try {
            connectorDir = Files.createTempDirectory("dwarpal-connectors");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        connectors.add(new FileConnector("ticket", Connector.Kind.TICKET, connectorDir, 100, clock));
        connectors.add(new FileConnector("chat", Connector.Kind.CHAT, connectorDir, 100, clock));
        catalogue = RuleCatalogue.reference().with(List.of(
                new RuleCatalogue.Rule(SYSLOG_RULE, RuleCatalogue.Evidence.COLLECTED_ONLY, false),
                new RuleCatalogue.Rule(MIXED_RULE, RuleCatalogue.Evidence.MIXED, false)));
        soar = soar(compile(TEST_PLAYBOOKS));
    }

    /** The playbooks the tests run: the reference ones plus part D-style rules and notifications. */
    public static final String TEST_PLAYBOOKS = """
            version: "test-1"
            playbooks:
              - rule: honeytoken-touched
                steps:
                  - revoke: subject
                  - deny: {target: subject, for: P1D}
                  - isolate: device
                  - notify: {connector: ticket, template: action-taken}
                  - notify: {connector: chat, template: device-isolated}
                  - notify: {connector: chat, template: needs-second-analyst}
              - rule: stolen-token-revoked
                steps:
                  - revoke: session
                  - revoke: subject
              - rule: break-glass-used
                steps:
                  - revoke: subject
              - rule: break-glass-refused
                steps: []
              - rule: deny-storm-ip
                steps:
                  - deny: {target: ip, for: PT4H}
                  - watch: {target: subject, ratio: 10, halfLife: P1D}
              - rule: deny-storm-subject
                steps:
                  - deny: {target: ip, for: PT4H}
              - rule: mfa-fatigue
                steps:
                  - revoke: subject
              - rule: impossible-travel-allow
                steps:
                  - revoke: subject
              - rule: dlp-block-spike
                steps:
                  - watch: {target: subject, ratio: 100, halfLife: P7D}
              - rule: pam-refused
                steps: []
              - rule: audit-chain-break
                steps: []
              - rule: audit-anchor-mismatch
                steps: []
              - rule: alert-flood
                steps: []
              - rule: detection-state-full
                steps: []
              - rule: fw-port-scan
                steps:
                  - watch: {target: ip, ratio: 10, halfLife: P1D}
              - rule: beacon-correlated
                steps:
                  - isolate: device
                  - watch: {target: subject, ratio: 1000, halfLife: P7D}
                  - notify: {connector: ticket, template: action-taken}
            default:
              - watch: {target: subject, ratio: 10, halfLife: P1D}
            """;

    public PlaybookCompiler compiler(boolean strict) {
        return new PlaybookCompiler(catalogue, settings, Set.of("ticket", "chat"), strict);
    }

    public PlaybookSet compile(String yaml) {
        PlaybookCompiler.Compilation c = compiler(true).compile(yaml);
        return c.set().orElseThrow(() -> new AssertionError("playbooks refused: " + c.findings()));
    }

    public Soar soar(PlaybookSet set) {
        return soar(set, b -> { });
    }

    public Soar soar(PlaybookSet set, Consumer<Soar.Builder> tweak) {
        Soar.Builder b = Soar.builder(audit, ledger).settings(settings).cases(book, cases).verdicts(gate)
                .enforcement(enforcement).clock(clock).isolation(isolation).connectors(connectors).playbooks(set).assets(assets);
        tweak.accept(b);
        return b.build();
    }

    public void later(Duration d) {
        clock.set(clock.instant().plus(d));
    }

    public Instant now() {
        return clock.instant();
    }

    /** Raises an alert through case management; returns its id. */
    public String raise(String rule, Severity severity, Entity... entities) {
        Alert a = alert(rule, severity, entities);
        if (!cases.raise(a)) {
            throw new AssertionError("refused " + a.id());
        }
        return a.id();
    }

    public Alert alert(String rule, Severity severity, Entity... entities) {
        alerts++;
        return new Alert("al-" + rule + "-" + alerts, rule, severity, now(), Arrays.asList(entities),
                List.of((long) alerts), 1, rule + " on " + entities[0].id());
    }

    public String caseOf(String alertId) {
        return book.caseOf(alertId).orElseThrow().id();
    }

    public Verdict verdict(String analyst, String alertId, Verdict.Outcome outcome) {
        return verdict(analyst, alertId, outcome, now());
    }

    public static Verdict verdict(String analyst, String alertId, Verdict.Outcome outcome, Instant at) {
        KeyPair k = switch (analyst) {
            case "ana" -> SimOrganisation.ANALYST_ANA;
            case "ben" -> SimOrganisation.ANALYST_BEN;
            case "cleo" -> CLEO;
            default -> throw new IllegalArgumentException("unknown analyst");
        };
        return new Verdict(alertId, analyst, outcome, new SignatureProof("soc-" + analyst, at,
                Ed25519.sign(k.getPrivate(), SignedMessages.socVerdict(alertId, analyst, outcome.name(), at))));
    }

    public Soar.Result decide(String analyst, String alertId, Verdict.Outcome outcome) {
        return soar.handle(verdict(analyst, alertId, outcome));
    }

    /** Delivers every acknowledgement the simulated sensors sent. */
    public List<DeviceIsolation.AckResult> pumpAcks() {
        List<DeviceIsolation.AckResult> out = new ArrayList<>();
        for (SensorAck a : sensor.drain()) {
            out.add(isolation.acknowledge(a));
        }
        return out;
    }

    public long audited(String type) {
        return sink.snapshot().stream().map(AuditRecord::type).filter(type::equals).count();
    }

    public List<AuditRecord> records(String type) {
        return sink.snapshot().stream().filter(r -> r.type().equals(type)).toList();
    }

    /** Someone logs in on a laptop now; the device agent key of laptop-alice signs the binding. */
    public SessionResult logIn(String subject, String device) {
        requests++;
        KeyPair sessionKey = Ed25519.generateKeyPair();
        AccessRequest r = Fixtures.request().id("rq-" + requests).at(now()).subject(subject).device(device).build();
        SignatureProof bind = new SignatureProof(Fixtures.DEVICE_KEY_ID, now(), Ed25519.sign(
                Fixtures.DEVICE_AGENT.getPrivate(), SignedMessages.sessionBinding(device, r.requestId(),
                        Digests.thumbprint(sessionKey.getPublic()), now())));
        return pa.open(r, feed.snapshot(now()), sessionKey.getPublic(), bind);
    }

    /** One request of a person on laptop-alice straight to the engine, with the feed's current signals. */
    public Decision asks(String subject) {
        requests++;
        AccessRequest r = Fixtures.request().id("rq-" + requests).at(now()).subject(subject).build();
        return engine.decide(r, feed.snapshot(now()));
    }

    /** A playbook bundle signed by the given administrator keys (key id, key pair). */
    public static PlaybookBundle bundle(long seq, String yaml, Instant at, Object... keyIdAndPair) {
        List<SignatureProof> approvals = new ArrayList<>();
        for (int i = 0; i < keyIdAndPair.length; i += 2) {
            String id = (String) keyIdAndPair[i];
            KeyPair k = (KeyPair) keyIdAndPair[i + 1];
            approvals.add(new SignatureProof(id, at, Ed25519.sign(k.getPrivate(),
                    PlaybookBundle.signedMessage(seq, yaml, at))));
        }
        return new PlaybookBundle(seq, yaml, approvals);
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

    /** Part E's ranker, faked: rules ranked by a table, actionable unless the rule or alert is marked collected. */
    public static final class FakeRanker implements AlertRanker {
        public final Map<String, Priority> priorities = new HashMap<>();
        public final Set<String> collectedRules = new HashSet<>(Set.of(SYSLOG_RULE));
        public final Set<String> collectedAlerts = new HashSet<>();
        public final AtomicBoolean down = new AtomicBoolean();
        public boolean lie;

        @Override
        public RankedAlert rank(Alert alert, Instant now) {
            if (down.get()) {
                throw new IllegalStateException("ranker unavailable");
            }
            Priority p = priorities.getOrDefault(alert.rule(), switch (alert.severity()) {
                case CRITICAL -> Priority.P1;
                case HIGH -> Priority.P2;
                case MEDIUM -> Priority.P3;
                case LOW -> Priority.P4;
            });
            boolean actionable = !collectedRules.contains(alert.rule()) && !collectedAlerts.contains(alert.id());
            Alert about = lie ? new Alert("al-other", alert.rule(), alert.severity(), alert.raisedAt(),
                    alert.entities(), alert.evidence(), 1, "other") : alert;
            return new RankedAlert(about, p, 100 - 20 * p.ordinal(), List.of(Techniques.VALID_ACCOUNTS), actionable,
                    List.of("severity " + alert.severity(), actionable ? "verified evidence" : "collected evidence only"));
        }
    }
}

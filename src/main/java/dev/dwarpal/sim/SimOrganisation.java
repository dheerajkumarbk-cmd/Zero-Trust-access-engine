package dev.dwarpal.sim;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.behavior.FailureLog;
import dev.dwarpal.behavior.InMemoryBehaviorHistory;
import dev.dwarpal.behavior.LoginEvent;
import dev.dwarpal.behavior.TrustLedger;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.crypto.TrustedKey;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.domain.SubjectType;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.engine.DenyListGate;
import dev.dwarpal.engine.HoneytokenGate;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.pip.InMemoryDirectory;
import dev.dwarpal.pip.SignalFeed;
import dev.dwarpal.pip.ThreatIntel;
import dev.dwarpal.policy.PolicySet;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.risk.scorers.StandardScorers;
import dev.dwarpal.runtime.DecisionPipeline;
import dev.dwarpal.soc.Verdict;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Set;

/**
 * A simulated organisation for Layer 5: reproducible (seeded), labelled, and run through the real
 * engine, so every part tests against the same people, attacks and audit trail.
 *
 * <pre>
 * people      N users: 2/3 stay home, 1/6 roam across one ISP, 1/6 travel between seven Indian cities;
 *             each has two daily login habits, a managed laptop and a spare one (agent keys)
 * history     45 days of logins learned before day 0
 * traffic     per user, in time order: legitimate (normal, odd hour, trip, trip with WebAuthn,
 *             new laptop) and attacks with a stolen password (foreign stuffing, impossible travel,
 *             domestic cloud server, same-city residential proxy, Tor, stolen laptop at home,
 *             password-spray address)
 * analysts    "ana" and "ben" with SOC_ANALYST keys, for signed verdicts
 * </pre>
 *
 * The engine and the generator were written by the same team: results measure consistency with the
 * threat model, not real-world accuracy. Say so wherever a number from here is reported.
 */
public final class SimOrganisation {

    public static final Instant DAY_ZERO = Instant.parse("2026-11-02T00:00:00Z");
    public static final String TOR_EXIT = "185.220.101.4";
    public static final String CLOUD_ASN = "AS16509";
    public static final String SPRAY_IP = "198.51.100.66";
    public static final KeyPair ANALYST_ANA = Ed25519.generateKeyPair();
    /** The lab's two administrators: they sign policy and playbook changes and approve privileged access. */
    public static final KeyPair ADMIN_ADA = Ed25519.generateKeyPair();
    public static final KeyPair ADMIN_RAY = Ed25519.generateKeyPair();
    /** The sealed break-glass credential of account {@code bg-root} (in a company it sits in a safe, not in code). */
    public static final KeyPair BREAK_GLASS_ROOT = Ed25519.generateKeyPair();
    public static final KeyPair ANALYST_BEN = Ed25519.generateKeyPair();

    private static final String[][] CITIES = {   // name, lat, lon
            {"mumbai", "19.07", "72.88"}, {"delhi", "28.61", "77.21"}, {"bengaluru", "12.97", "77.59"},
            {"chennai", "13.08", "80.27"}, {"hyderabad", "17.38", "78.48"}, {"pune", "18.52", "73.86"},
            {"kolkata", "22.57", "88.36"}};
    private static final String[] ISPS = {"AS24560", "AS55836", "AS45609", "AS9829", "AS17488"};

    public enum Kind { HOME, ROAMER, TRAVELLER }

    /** What a request really is. Legitimate scenarios start with L, attacks with A. */
    public enum Scenario {
        L1_NORMAL, L2_ODD_HOUR, L3_TRIP, L3_TRIP_WEBAUTHN, L4_NEW_LAPTOP,
        A1_FOREIGN_STUFFING, A2_DOMESTIC_CLOUD, A3_SAME_CITY_PROXY, A4_IMPOSSIBLE_TRAVEL, A5_TOR,
        A6_STOLEN_LAPTOP_AT_HOME, A7_SPRAY_IP;

        public boolean attack() {
            return name().startsWith("A");
        }
    }

    public record User(String id, Kind kind, String laptop, KeyPair laptopKey, String laptop2, KeyPair laptop2Key,
                       int city, String isp, int habit1, int habit2) {
    }

    /** One request and what it really is. */
    public record Labelled(AccessRequest request, Scenario scenario, String userId) {
    }

    /** One step of the traffic: a request, or failed logins recorded before one (password spray). */
    public sealed interface Step permits RequestStep, FailureStep {
        Instant at();
    }

    public record RequestStep(Labelled labelled) implements Step {
        @Override
        public Instant at() {
            return labelled.request().timestamp();
        }
    }

    public record FailureStep(String subject, String ip, Instant at) implements Step {
    }

    /** A request, what it was, and what the engine decided. */
    public record Result(Labelled labelled, Decision decision) {
    }

    /** A clock moved by the simulation: always the time of the step being run. */
    public static final class SimClock extends Clock {
        private volatile Instant now = DAY_ZERO;

        public void set(Instant t) {
            now = t;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /** The console server's delegation key (the key ring trusts it for {@code CONSOLE_DELEGATE} only). */
    public static final String CONSOLE_KEY_ID = "console-delegate";
    public final KeyPair consoleKey = Ed25519.generateKeyPair();
    public final long seed;
    public final List<User> users;
    public final KeyRing keys;
    public final InMemoryDirectory directory;
    public final ThreatIntel threatIntel = new ThreatIntel(Set.of(), Set.of(TOR_EXIT), Set.of(CLOUD_ASN));
    public final InMemoryBehaviorHistory history = new InMemoryBehaviorHistory();
    public final TrustLedger trust = new TrustLedger(Duration.ofDays(30));
    public final FailureLog failures = new FailureLog();
    public final SimClock clock = new SimClock();
    public final SecretKey auditKey;
    public final InMemoryAuditSink sink = new InMemoryAuditSink();
    public final AuditLog audit;
    public final SignalFeed signals;
    private final Random rnd;

    private SimOrganisation(long seed, int size) {
        this.seed = seed;
        this.rnd = new Random(seed);
        List<User> us = new ArrayList<>();
        List<TrustedKey> ks = new ArrayList<>();
        List<Subject> subjects = new ArrayList<>();
        List<String> managed = new ArrayList<>();
        Instant from = DAY_ZERO.minus(Duration.ofDays(400));
        Instant to = DAY_ZERO.plus(Duration.ofDays(400));
        for (int i = 0; i < size; i++) {
            Kind kind = i < size * 2 / 3 ? Kind.HOME : i < size * 5 / 6 ? Kind.ROAMER : Kind.TRAVELLER;
            KeyPair k1 = Ed25519.generateKeyPair();
            KeyPair k2 = Ed25519.generateKeyPair();
            int h1 = 120 + rnd.nextInt(360);                        // 02:00-08:00 UTC
            User u = new User("u" + i, kind, "laptop-u" + i, k1, "laptop2-u" + i, k2, rnd.nextInt(CITIES.length),
                    kind == Kind.ROAMER ? "AS55836" : ISPS[rnd.nextInt(ISPS.length)], h1, h1 + 180 + rnd.nextInt(240));
            us.add(u);
            subjects.add(new Subject(u.id(), SubjectType.HUMAN, Set.of("engineer"), "engineering"));
            ks.add(new TrustedKey("agent-" + u.laptop(), KeyPurpose.DEVICE_AGENT, u.laptop(), k1.getPublic(), from, to));
            ks.add(new TrustedKey("agent-" + u.laptop2(), KeyPurpose.DEVICE_AGENT, u.laptop2(), k2.getPublic(), from, to));
            managed.add(u.laptop());
            managed.add(u.laptop2());
        }
        ks.add(new TrustedKey(SimRequests.IDP_KEY_ID, KeyPurpose.IDENTITY_PROVIDER, "corp-idp", SimRequests.IDP.getPublic(),
                from, to));
        ks.add(new TrustedKey(CONSOLE_KEY_ID, KeyPurpose.CONSOLE_DELEGATE, "console", consoleKey.getPublic(), from, to));
        ks.add(new TrustedKey("pol-ada", KeyPurpose.POLICY_SIGNER, "ada", ADMIN_ADA.getPublic(), from, to));
        ks.add(new TrustedKey("pol-ray", KeyPurpose.POLICY_SIGNER, "ray", ADMIN_RAY.getPublic(), from, to));
        ks.add(new TrustedKey("elev-ada", KeyPurpose.ELEVATION_APPROVER, "ada", ADMIN_ADA.getPublic(), from, to));
        ks.add(new TrustedKey("elev-ray", KeyPurpose.ELEVATION_APPROVER, "ray", ADMIN_RAY.getPublic(), from, to));
        ks.add(new TrustedKey("bg-root", KeyPurpose.BREAK_GLASS, "bg-root", BREAK_GLASS_ROOT.getPublic(), from, to));
        ks.add(new TrustedKey("soc-ana", KeyPurpose.SOC_ANALYST, "ana", ANALYST_ANA.getPublic(), from, to));
        ks.add(new TrustedKey("soc-ben", KeyPurpose.SOC_ANALYST, "ben", ANALYST_BEN.getPublic(), from, to));
        this.users = List.copyOf(us);
        this.keys = new KeyRing(ks);
        this.directory = new InMemoryDirectory(subjects,
                List.of(new Resource("wiki", ResourceKind.PRIVATE_APP, DataClassification.INTERNAL)), managed);
        try {
            this.auditKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        this.audit = new AuditLog(auditKey, sink);
        this.signals = new SignalFeed(Set.of(), audit, clock);
        seedHistory();
    }

    /** An organisation of {@code size} users (at least 6) built from {@code seed}; same seed, same organisation. */
    public static SimOrganisation create(long seed, int size) {
        if (size < 6 || size > 10_000) {
            throw new IllegalArgumentException("between 6 and 10,000 users");
        }
        return new SimOrganisation(seed, size);
    }

    /** The reference engine on this organisation's directory, keys, stores and threat intelligence. */
    public PolicyEngine engine(PolicySet policies) {
        return PolicyEngine.builder().policySet(policies).directory(directory).keyRing(keys)
                .gate(new HoneytokenGate()).gate(new DenyListGate())
                .scorers(StandardScorers.all(history, trust, failures, () -> threatIntel))
                .aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                .costModel(new CostModel(1000, 1, 20, 0.05)).build();
    }

    /** The reference engine with the reference policy. */
    public PolicyEngine engine() {
        return engine(SimRequests.defaultPolicies());
    }

    /** The full live pipeline: learning, audit (into {@link #sink}), engine. */
    public DecisionPoint pipeline(DecisionPoint engine) {
        return DecisionPipeline.standard(engine, audit, history, trust, clock);
    }

    /** The traffic, in time order, drawn from this organisation's random stream (call once per run). */
    public List<Step> traffic() {
        List<Step> steps = new ArrayList<>();
        for (User u : users) {
            steps.addAll(trafficOf(u));
        }
        steps.sort((a, b) -> a.at().compareTo(b.at()));
        return List.copyOf(steps);
    }

    /** Runs {@code steps} through {@code pdp} with the signal feed's deny lists, moving the clock. */
    public List<Result> run(DecisionPoint pdp, List<Step> steps) {
        List<Result> out = new ArrayList<>();
        for (Step s : steps) {
            clock.set(s.at());
            switch (s) {
                case FailureStep f -> failures.recordFailure(f.subject(), f.ip(), f.at());
                case RequestStep r -> out.add(new Result(r.labelled(),
                        pdp.decide(r.labelled().request(), signals.snapshot(s.at()))));
            }
        }
        return List.copyOf(out);
    }

    /** A verdict signed by {@code analyst} ("ana" or "ben") now. */
    public Verdict verdict(String analyst, String alertId, Verdict.Outcome outcome, Instant at) {
        KeyPair k = switch (analyst) {
            case "ana" -> ANALYST_ANA;
            case "ben" -> ANALYST_BEN;
            default -> throw new IllegalArgumentException("unknown analyst");
        };
        return new Verdict(alertId, analyst, outcome, new SignatureProof("soc-" + analyst, at,
                Ed25519.sign(k.getPrivate(), SignedMessages.socVerdict(alertId, analyst, outcome.name(), at))));
    }

    // ---- generation ------------------------------------------------------------------------------------

    private static NetworkContext net(String ip, String asn, String country, int city) {
        return new NetworkContext(ip, asn, country, Double.parseDouble(CITIES[city][1]),
                Double.parseDouble(CITIES[city][2]), 25);
    }

    private static Instant at(int day, int minute) {
        return DAY_ZERO.plus(Duration.ofDays(day)).plus(Duration.ofMinutes(minute));
    }

    private void seedHistory() {
        for (User u : users) {
            for (int day = -45; day < 0; day++) {
                for (int habit : new int[]{u.habit1(), u.habit2()}) {
                    Instant t = at(day, habit + rnd.nextInt(41) - 20);
                    NetworkContext n;
                    if (u.kind() == Kind.ROAMER) {
                        n = net("100.100." + rnd.nextInt(250) + "." + rnd.nextInt(250), u.isp(), "IN", u.city());
                    } else if (u.kind() == Kind.TRAVELLER && Math.floorMod(day, 10) == 0) {
                        int c = (u.city() + 1 + rnd.nextInt(CITIES.length - 1)) % CITIES.length;
                        n = net("100.90." + c + "." + rnd.nextInt(250), ISPS[rnd.nextInt(ISPS.length)], "IN", c);
                    } else {
                        n = net("100.64." + u.id().substring(1) + ".10", u.isp(), "IN", u.city());
                    }
                    history.record(new LoginEvent(u.id(), u.laptop(), n, t));
                    trust.recordGood(TrustLedger.subjectKey(u.id()), t);
                    trust.recordGood(TrustLedger.deviceKey(u.laptop()), t);
                }
            }
        }
    }

    private SimRequests.Builder login(User u, Instant t, String id) {
        return SimRequests.request().id(id).at(t).subject(u.id()).device(u.laptop())
                .postureSignedBy(u.laptopKey(), "agent-" + u.laptop())
                .network(u.kind() == Kind.ROAMER ? "100.100.7." + Math.floorMod(id.hashCode(), 250)
                                : "100.64." + u.id().substring(1) + ".10",
                        u.isp(), "IN", Double.parseDouble(CITIES[u.city()][1]), Double.parseDouble(CITIES[u.city()][2]));
    }

    private List<Step> trafficOf(User u) {
        List<Step> s = new ArrayList<>();
        String p = u.id() + "-";
        int otherCity = (u.city() + 3) % CITIES.length;
        String otherIsp = ISPS[(Arrays.asList(ISPS).indexOf(u.isp()) + 1) % ISPS.length];
        double lat = Double.parseDouble(CITIES[otherCity][1]);
        double lon = Double.parseDouble(CITIES[otherCity][2]);
        add(s, u, Scenario.L1_NORMAL, login(u, at(0, u.habit1()), p + "l1"));
        add(s, u, Scenario.A4_IMPOSSIBLE_TRAVEL, login(u, at(0, u.habit1() + 20), p + "a4").unsignedPosture()
                .network("81.2.69.160", "AS20712", "GB", 51.507, -0.128));
        add(s, u, Scenario.L2_ODD_HOUR, login(u, at(1, u.habit1() + 720), p + "l2"));
        add(s, u, Scenario.L3_TRIP, login(u, at(2, u.habit1()), p + "l3")
                .network("100.80." + otherCity + ".7", otherIsp, "IN", lat, lon));
        add(s, u, Scenario.L3_TRIP_WEBAUTHN, login(u, at(2, u.habit1() + 1), p + "l3w")
                .network("100.80." + otherCity + ".7", otherIsp, "IN", lat, lon)
                .authenticated(AuthMethod.WEBAUTHN, Duration.ofSeconds(30)));
        add(s, u, Scenario.L4_NEW_LAPTOP, login(u, at(4, u.habit1()), p + "l4").device(u.laptop2())
                .postureSignedBy(u.laptop2Key(), "agent-" + u.laptop2()));
        add(s, u, Scenario.A1_FOREIGN_STUFFING, login(u, at(5, rnd.nextInt(1440)), p + "a1")
                .device("pc-" + rnd.nextInt(999)).unsignedPosture()
                .network("45.155.205." + rnd.nextInt(250), "AS49505", "RU", 55.75, 37.62));
        add(s, u, Scenario.A2_DOMESTIC_CLOUD, login(u, at(5, u.habit2()), p + "a2").unsignedPosture()
                .network("3.6.82." + rnd.nextInt(250), CLOUD_ASN, "IN", 19.07, 72.88));
        add(s, u, Scenario.A3_SAME_CITY_PROXY, login(u, at(5, u.habit2() + 30), p + "a3").unsignedPosture()
                .network("100.70.1." + rnd.nextInt(250), otherIsp, "IN",
                        Double.parseDouble(CITIES[u.city()][1]), Double.parseDouble(CITIES[u.city()][2])));
        add(s, u, Scenario.A5_TOR, login(u, at(5, u.habit1()), p + "a5").unsignedPosture()
                .network(TOR_EXIT, "AS9009", "DE", 50.11, 8.68));
        add(s, u, Scenario.A6_STOLEN_LAPTOP_AT_HOME, login(u, at(6, u.habit1()), p + "a6"));
        Instant sprayAt = at(7, u.habit2());
        for (int k = 0; k < 15; k++) {
            s.add(new FailureStep("victim" + k, SPRAY_IP, sprayAt.minus(Duration.ofMinutes(5)).plusSeconds(k)));
        }
        add(s, u, Scenario.A7_SPRAY_IP, login(u, sprayAt, p + "a7").unsignedPosture()
                .network(SPRAY_IP, "AS64511", "IN", 28.61, 77.21));
        return s;
    }

    private static void add(List<Step> s, User u, Scenario c, SimRequests.Builder b) {
        s.add(new RequestStep(new Labelled(b.build(), c, u.id())));
    }
}

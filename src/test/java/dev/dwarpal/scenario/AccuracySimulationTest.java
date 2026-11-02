package dev.dwarpal.scenario;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.behavior.FailureLog;
import dev.dwarpal.behavior.InMemoryBehaviorHistory;
import dev.dwarpal.behavior.LoginEvent;
import dev.dwarpal.behavior.TrustLedger;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.TrustedKey;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
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
import dev.dwarpal.engine.PolicyEngineTest;
import dev.dwarpal.pip.InMemoryDirectory;
import dev.dwarpal.pip.ThreatIntel;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.risk.scorers.StandardScorers;
import dev.dwarpal.runtime.DecisionPipeline;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Accuracy on a synthetic organisation: 60 users with three kinds of habit, 45 days of history,
 * then a mix of legitimate logins and attacks, measured as a confusion table.
 *
 * <p>Expectations, fixed BEFORE the first run (so the test cannot be tuned to pass):
 * <ul>
 *   <li>Legitimate: no normal, odd-hour, travelling or new-laptop login is ever DENIED; normal
 *       logins step up at most 5% of the time; every trip passes once WebAuthn is done.</li>
 *   <li>Attacks with a stolen password only: foreign stuffing, impossible travel, Tor and
 *       password-spray IPs are always DENIED; a domestic cloud server and a same-city residential
 *       proxy (the evasive case) are never ALLOWED.</li>
 *   <li>Blind spot, measured not asserted: a stolen, unlocked laptop used at the victim's home with
 *       the victim's password looks exactly like the victim. Signals alone cannot catch it.</li>
 * </ul>
 * Honest limit: the generator and the engine were written by the same team, so this measures
 * consistency with the threat model, not real-world accuracy. Real or held-out data comes later.
 */
class AccuracySimulationTest {

    private static final Instant S = Instant.parse("2026-11-02T00:00:00Z");
    private static final String[][] CITIES = {   // name, lat, lon
            {"mumbai", "19.07", "72.88"}, {"delhi", "28.61", "77.21"}, {"bengaluru", "12.97", "77.59"},
            {"chennai", "13.08", "80.27"}, {"hyderabad", "17.38", "78.48"}, {"pune", "18.52", "73.86"},
            {"kolkata", "22.57", "88.36"}};
    private static final String[] ISPS = {"AS24560", "AS55836", "AS45609", "AS9829", "AS17488"};

    enum Kind { HOME, ROAMER, TRAVELLER }

    enum Case {
        L1_NORMAL, L2_ODD_HOUR, L3_TRIP, L3_TRIP_WEBAUTHN, L4_NEW_LAPTOP,
        A1_FOREIGN_STUFFING, A2_DOMESTIC_CLOUD, A3_SAME_CITY_PROXY, A4_IMPOSSIBLE_TRAVEL, A5_TOR,
        A6_STOLEN_LAPTOP_AT_HOME, A7_SPRAY_IP;

        boolean legit() {
            return name().startsWith("L");
        }
    }

    private record User(String id, Kind kind, String laptop, KeyPair laptopKey, String laptop2, KeyPair laptop2Key,
                        int city, String isp, int habit1, int habit2) {
    }

    private final Map<Case, EnumMap<Outcome, Integer>> table = new EnumMap<>(Case.class);
    private final InMemoryBehaviorHistory history = new InMemoryBehaviorHistory();
    private final TrustLedger trust = new TrustLedger(Duration.ofDays(30));
    private final FailureLog failures = new FailureLog();
    private final SimClock clock = new SimClock();

    private static final class SimClock extends Clock {
        volatile Instant now = S;

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

    private static NetworkContext net(String ip, String asn, String country, int city) {
        return new NetworkContext(ip, asn, country, Double.parseDouble(CITIES[city][1]), Double.parseDouble(CITIES[city][2]), 25);
    }

    private static Instant at(int day, int minute) {
        return S.plus(Duration.ofDays(day)).plus(Duration.ofMinutes(minute));
    }

    @Test
    void confusionTableOnSixtyUsers() throws Exception {
        Random rnd = new Random(7);
        List<User> users = new ArrayList<>();
        List<TrustedKey> keys = new ArrayList<>();
        List<Subject> subjects = new ArrayList<>();
        List<String> managed = new ArrayList<>();
        for (int i = 0; i < 60; i++) {
            Kind kind = i < 40 ? Kind.HOME : i < 50 ? Kind.ROAMER : Kind.TRAVELLER;
            KeyPair k1 = Ed25519.generateKeyPair();
            KeyPair k2 = Ed25519.generateKeyPair();
            int h1 = 120 + rnd.nextInt(360);                        // 02:00-08:00 UTC
            User u = new User("u" + i, kind, "laptop-u" + i, k1, "laptop2-u" + i, k2, rnd.nextInt(CITIES.length),
                    kind == Kind.ROAMER ? "AS55836" : ISPS[rnd.nextInt(ISPS.length)], h1, h1 + 180 + rnd.nextInt(240));
            users.add(u);
            subjects.add(new Subject(u.id(), SubjectType.HUMAN, Set.of("engineer"), "engineering"));
            for (String[] d : new String[][]{{u.laptop(), "k1"}, {u.laptop2(), "k2"}}) {
                keys.add(new TrustedKey("agent-" + d[0], KeyPurpose.DEVICE_AGENT, d[0],
                        (d[1].equals("k1") ? k1 : k2).getPublic(), S.minus(Duration.ofDays(400)), S.plus(Duration.ofDays(400))));
                managed.add(d[0]);
            }
        }
        keys.add(new TrustedKey(Fixtures.IDP_KEY_ID, KeyPurpose.IDENTITY_PROVIDER, "corp-idp", Fixtures.IDP.getPublic(),
                S.minus(Duration.ofDays(400)), S.plus(Duration.ofDays(400))));

        seedHistory(users, rnd);

        PolicyEngine engine = PolicyEngine.builder().policySet(PolicyEngineTest.POLICIES)
                .directory(new InMemoryDirectory(subjects,
                        List.of(new Resource("wiki", ResourceKind.PRIVATE_APP, DataClassification.INTERNAL)), managed))
                .keyRing(new KeyRing(keys)).gate(new HoneytokenGate()).gate(new DenyListGate())
                .scorers(StandardScorers.all(history, trust, failures,
                        () -> new ThreatIntel(Set.of(), Set.of("185.220.101.4"), Set.of("AS16509"))))
                .aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                .costModel(new CostModel(1000, 1, 20, 0.05)).build();
        DecisionPoint pdp = DecisionPipeline.standard(engine,
                new AuditLog(KeyGenerator.getInstance("HmacSHA256").generateKey(), new InMemoryAuditSink()),
                history, trust, clock);

        for (User u : users) {
            evaluate(pdp, u, rnd);
        }
        printAndCheck();
    }

    private void seedHistory(List<User> users, Random rnd) {
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

    private Fixtures.RequestBuilder login(User u, Instant t, String id) {
        return Fixtures.request().id(id).at(t).subject(u.id()).device(u.laptop()).postureSignedBy(u.laptopKey(), "agent-" + u.laptop())
                .network(u.kind() == Kind.ROAMER ? "100.100.7." + Math.floorMod(id.hashCode(), 250) : "100.64." + u.id().substring(1) + ".10",
                        u.isp(), "IN", Double.parseDouble(CITIES[u.city()][1]), Double.parseDouble(CITIES[u.city()][2]));
    }

    private void evaluate(DecisionPoint pdp, User u, Random rnd) {
        String p = u.id() + "-";
        int otherCity = (u.city() + 3) % CITIES.length;
        String otherIsp = ISPS[(java.util.Arrays.asList(ISPS).indexOf(u.isp()) + 1 + ISPS.length) % ISPS.length];
        if (otherIsp.equals(u.isp())) {
            otherIsp = "AS45609";
        }
        // Legitimate
        record(pdp, Case.L1_NORMAL, login(u, at(0, u.habit1()), p + "l1"));
        record(pdp, Case.A4_IMPOSSIBLE_TRAVEL, login(u, at(0, u.habit1() + 20), p + "a4").unsignedPosture()
                .network("81.2.69.160", "AS20712", "GB", 51.507, -0.128));
        record(pdp, Case.L2_ODD_HOUR, login(u, at(1, u.habit1() + 720), p + "l2"));
        Fixtures.RequestBuilder trip = login(u, at(2, u.habit1()), p + "l3")
                .network("100.80." + otherCity + ".7", otherIsp, "IN",
                        Double.parseDouble(CITIES[otherCity][1]), Double.parseDouble(CITIES[otherCity][2]));
        record(pdp, Case.L3_TRIP, trip);
        record(pdp, Case.L3_TRIP_WEBAUTHN, login(u, at(2, u.habit1() + 1), p + "l3w")
                .network("100.80." + otherCity + ".7", otherIsp, "IN",
                        Double.parseDouble(CITIES[otherCity][1]), Double.parseDouble(CITIES[otherCity][2]))
                .authenticated(AuthMethod.WEBAUTHN, Duration.ofSeconds(30)));
        record(pdp, Case.L4_NEW_LAPTOP, login(u, at(4, u.habit1()), p + "l4").device(u.laptop2())
                .postureSignedBy(u.laptop2Key(), "agent-" + u.laptop2()));
        // Attacks: the attacker has the password, not the laptop, not the MFA device.
        record(pdp, Case.A1_FOREIGN_STUFFING, login(u, at(5, rnd.nextInt(1440)), p + "a1").device("pc-" + rnd.nextInt(999))
                .unsignedPosture().network("45.155.205." + rnd.nextInt(250), "AS49505", "RU", 55.75, 37.62));
        record(pdp, Case.A2_DOMESTIC_CLOUD, login(u, at(5, u.habit2()), p + "a2").unsignedPosture()
                .network("3.6.82." + rnd.nextInt(250), "AS16509", "IN", 19.07, 72.88));
        record(pdp, Case.A3_SAME_CITY_PROXY, login(u, at(5, u.habit2() + 30), p + "a3").unsignedPosture()
                .network("100.70.1." + rnd.nextInt(250), otherIsp, "IN",
                        Double.parseDouble(CITIES[u.city()][1]), Double.parseDouble(CITIES[u.city()][2])));
        record(pdp, Case.A5_TOR, login(u, at(5, u.habit1()), p + "a5").unsignedPosture()
                .network("185.220.101.4", "AS9009", "DE", 50.11, 8.68));
        record(pdp, Case.A6_STOLEN_LAPTOP_AT_HOME, login(u, at(6, u.habit1()), p + "a6"));
        Instant sprayAt = at(7, u.habit2());
        for (int k = 0; k < 15; k++) {
            failures.recordFailure("victim" + k, "198.51.100.66", sprayAt.minus(Duration.ofMinutes(5)).plusSeconds(k));
        }
        record(pdp, Case.A7_SPRAY_IP, login(u, sprayAt, p + "a7").unsignedPosture()
                .network("198.51.100.66", "AS64511", "IN", 28.61, 77.21));
    }

    private void record(DecisionPoint pdp, Case c, Fixtures.RequestBuilder b) {
        var r = b.build();
        clock.now = r.timestamp();
        Decision d = pdp.decide(r, SignalSnapshot.empty());
        table.computeIfAbsent(c, k -> new EnumMap<>(Outcome.class)).merge(d.outcome(), 1, Integer::sum);
    }

    private int count(Case c, Outcome o) {
        return table.getOrDefault(c, new EnumMap<>(Outcome.class)).getOrDefault(o, 0);
    }

    private void printAndCheck() {
        StringBuilder sb = new StringBuilder("\nACCURACY (60 users: 40 home, 10 roamers, 10 travellers)\n");
        sb.append(String.format(Locale.ROOT, "%-26s %6s %8s %8s %6s%n", "case", "ALLOW", "LIMITED", "STEP_UP", "DENY"));
        Map<String, int[]> totals = new LinkedHashMap<>();
        for (Case c : Case.values()) {
            sb.append(String.format(Locale.ROOT, "%-26s %6d %8d %8d %6d%n", c, count(c, Outcome.ALLOW),
                    count(c, Outcome.ALLOW_LIMITED), count(c, Outcome.STEP_UP), count(c, Outcome.DENY)));
            totals.computeIfAbsent(c.legit() ? "legit" : "attack", k -> new int[4]);
        }
        System.out.println(sb);

        int users = 60;
        for (Case c : List.of(Case.L1_NORMAL, Case.L2_ODD_HOUR, Case.L3_TRIP, Case.L3_TRIP_WEBAUTHN, Case.L4_NEW_LAPTOP)) {
            assertEquals(0, count(c, Outcome.DENY), c + ": a legitimate user was denied");
        }
        assertTrue(count(Case.L1_NORMAL, Outcome.STEP_UP) <= users * 0.05, "normal-login friction above 5%");
        assertEquals(users, count(Case.L3_TRIP_WEBAUTHN, Outcome.ALLOW), "every verified traveller gets in");
        for (Case c : List.of(Case.A1_FOREIGN_STUFFING, Case.A4_IMPOSSIBLE_TRAVEL, Case.A5_TOR, Case.A7_SPRAY_IP)) {
            assertEquals(users, count(c, Outcome.DENY), c + ": not always denied");
        }
        for (Case c : List.of(Case.A2_DOMESTIC_CLOUD, Case.A3_SAME_CITY_PROXY)) {
            assertEquals(0, count(c, Outcome.ALLOW), c + ": an attacker got in");
        }
    }
}

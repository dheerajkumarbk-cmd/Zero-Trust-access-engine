package dev.dwarpal.scenario;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.behavior.FailureLog;
import dev.dwarpal.behavior.Feature;
import dev.dwarpal.behavior.InMemoryBehaviorHistory;
import dev.dwarpal.behavior.LoginEvent;
import dev.dwarpal.behavior.TrustLedger;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.domain.SubjectType;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.engine.DenyListGate;
import dev.dwarpal.engine.HoneytokenGate;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.engine.PolicyEngineTest;
import dev.dwarpal.pip.InMemoryDirectory;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.risk.scorers.StandardScorers;
import dev.dwarpal.pip.ThreatIntel;
import dev.dwarpal.runtime.DecisionPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end: the full pipeline (engine + Layer 2 scorers + learning + audit) against real attack
 * patterns, on a user with 40 days of normal history. Each scenario prints the analyst report,
 * so the decisions can be read and defended, not just asserted.
 */
class AttackScenariosTest {

    /** "Now": Monday 04:00 UTC (09:30 in Mumbai). */
    private static final Instant S = Instant.parse("2026-11-02T04:00:00Z");
    /** Threat feed: one Tor exit and Amazon's ASN as a hosting provider. */
    private static final ThreatIntel INTEL = new ThreatIntel(Set.of(), Set.of("185.220.101.4"), Set.of("AS16509"));
    private static final NetworkContext HOME = new NetworkContext("203.0.113.10", "AS64500", "IN", 19.07, 72.88, 25);

    private final InMemoryBehaviorHistory history = new InMemoryBehaviorHistory();
    private final TrustLedger trust = new TrustLedger(Duration.ofDays(30));
    private final FailureLog failures = new FailureLog();
    private final InMemoryAuditSink sink = new InMemoryAuditSink();
    private SecretKey auditKey;
    private AuditLog audit;
    private DecisionPoint pdp;
    /** Simulated wall clock: each scenario request happens "now". */
    private final SimClock clock = new SimClock();

    private static final class SimClock extends Clock {
        private volatile Instant now = S;

        @Override
        public java.time.ZoneId getZone() {
            return java.time.ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private Decision run(dev.dwarpal.domain.AccessRequest r) {
        clock.now = r.timestamp();
        return pdp.decide(r, SignalSnapshot.empty());
    }

    @BeforeEach
    void world() throws Exception {
        List<Subject> people = new ArrayList<>(List.of(
                new Subject("alice", SubjectType.HUMAN, Set.of("engineer"), "engineering"),
                new Subject("carol", SubjectType.HUMAN, Set.of("engineer"), "engineering")));
        for (int i = 0; i < 12; i++) {
            people.add(new Subject("user" + i, SubjectType.HUMAN, Set.of("engineer"), "engineering"));
        }
        InMemoryDirectory directory = new InMemoryDirectory(people,
                List.of(new Resource("wiki", dev.dwarpal.domain.ResourceKind.PRIVATE_APP,
                        dev.dwarpal.domain.DataClassification.INTERNAL)),
                List.of("laptop-alice", "laptop-carol"));

        PolicyEngine engine = PolicyEngine.builder()
                .policySet(PolicyEngineTest.POLICIES).directory(directory).keyRing(Fixtures.KEYRING)
                .gate(new HoneytokenGate()).gate(new DenyListGate())
                .scorers(StandardScorers.all(history, trust, failures, () -> INTEL))
                .aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                .costModel(new CostModel(1000, 1, 20, 0.05))
                .build();
        auditKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
        audit = new AuditLog(auditKey, sink);
        pdp = DecisionPipeline.standard(engine, audit, history, trust, clock);

        // 40 days of Alice: 09:15 and 14:00 IST (03:45 and 08:30 UTC), home broadband, her laptop.
        for (int day = 40; day >= 1; day--) {
            for (Duration t : List.of(Duration.ofMinutes(-15), Duration.ofMinutes(270))) {
                Instant at = S.minus(Duration.ofDays(day)).plus(t);
                history.record(new LoginEvent("alice", "laptop-alice", HOME, at));
                trust.recordGood(TrustLedger.subjectKey("alice"), at);
                trust.recordGood(TrustLedger.deviceKey("laptop-alice"), at);
            }
        }
    }

    private static Fixtures.RequestBuilder alice(Instant at) {
        return Fixtures.request().id("r-" + at.getEpochSecond()).at(at)
                .network(HOME.ip(), HOME.asn(), HOME.country(), HOME.latitude(), HOME.longitude());
    }

    private Decision decide(String title, Fixtures.RequestBuilder r) {
        Decision d = run(r.build());
        System.out.println("\n=== " + title + " ===\n" + d.analystReport());
        return d;
    }

    @Test
    void normalMorningLoginIsAllowedSilently() {
        assertEquals(Outcome.ALLOW, decide("1. Alice, home, laptop, usual time", alice(S)).outcome());
    }

    @Test
    void brandNewUserIsAskedForMfaNotBlocked() {
        Decision d = decide("2. Carol's first ever login (enrolment)",
                Fixtures.request().id("r-carol").subject("carol").device("laptop-carol").at(S).unsignedPosture());
        assertEquals(Outcome.STEP_UP, d.outcome());
    }

    @Test
    void credentialStuffingFromAbroadIsDenied() {
        Decision d = decide("3. Stolen password used from Moscow, unknown PC, 22:00 UTC",
                alice(S.plus(Duration.ofHours(18))).device("unknown-pc")
                        .network("185.220.101.4", "AS9009", "RU", 55.75, 37.62));
        assertEquals(Outcome.DENY, d.outcome());
    }

    @Test
    void impossibleTravelIsDenied() {
        assertEquals(Outcome.ALLOW, run(alice(S).build()).outcome());
        Decision d = decide("4. Same laptop id appears in London 30 minutes after Mumbai",
                alice(S.plus(Duration.ofMinutes(30))).network("81.2.69.160", "AS20712", "GB", 51.507, -0.128));
        assertEquals(Outcome.DENY, d.outcome());
        assertTrue(d.risk().factors().stream().anyMatch(f -> f.name().equals("impossible-travel")));
    }

    @Test
    void passwordSprayIpIsDenied() {
        Instant at = S.plus(Duration.ofHours(2));
        for (int i = 0; i < 12; i++) {
            failures.recordFailure("user" + i, "198.51.100.66", at.minus(Duration.ofMinutes(5)).plusSeconds(i));
        }
        Decision d = decide("5. Login from an IP that just failed against 12 accounts",
                alice(at).network("198.51.100.66", "AS64511", "IN", 28.61, 77.21));
        assertEquals(Outcome.DENY, d.outcome());
    }

    @Test
    void accountUnderBruteForceMakesEvenTheRealUserProveThemselves() {
        Instant at = S.plus(Duration.ofHours(3));
        for (int i = 0; i < 8; i++) {
            failures.recordFailure("alice", "45.33.32." + i, at.minus(Duration.ofMinutes(10)).plusSeconds(i));
        }
        Decision d = decide("6. Real Alice from home, minutes after 8 failed guesses on her account",
                alice(at));
        assertEquals(Outcome.STEP_UP, d.outcome());
    }

    @Test
    void legitimateTripNeedsStrongMfaOnceThenIsLearned() {
        Instant at = S.plus(Duration.ofDays(1));
        Fixtures.RequestBuilder trip = alice(at).network("49.207.47.1", "AS24560", "IN", 12.97, 77.59);
        assertEquals(Outcome.STEP_UP, decide("7a. Alice in Bengaluru, new ISP, no MFA yet", trip).outcome());

        Decision push = decide("7b. ...approved with push (fatigue-prone)",
                alice(at).id("r-push").network("49.207.47.1", "AS24560", "IN", 12.97, 77.59)
                        .authenticated(AuthMethod.PUSH, Duration.ofMinutes(1)));
        assertEquals(Outcome.STEP_UP, push.outcome(), "push is not enough under this much doubt");

        Decision webauthn = decide("7c. ...security key (WebAuthn)",
                alice(at).id("r-webauthn").network("49.207.47.1", "AS24560", "IN", 12.97, 77.59)
                        .authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)));
        assertEquals(Outcome.ALLOW, webauthn.outcome());

        Decision later = decide("7d. Same hotel Wi-Fi an hour later, no MFA",
                alice(at.plus(Duration.ofHours(1))).network("49.207.47.1", "AS24560", "IN", 12.97, 77.59));
        assertEquals(Outcome.ALLOW, later.outcome(), "the verified location was learned");
    }

    @Test
    void cloudServerWithStolenPasswordAndSpoofedLaptopIdIsNotAllowed() {
        // In India, at Alice's usual hour, typing her laptop's id: everything an attacker can fake.
        Decision d = decide("8. Stolen password from an AWS server in Mumbai, laptop id typed in, no agent signature",
                alice(S.plus(Duration.ofDays(3))).unsignedPosture()
                        .network("3.6.82.10", "AS16509", "IN", 19.07, 72.88));
        assertTrue(d.outcome() == Outcome.DENY || d.outcome() == Outcome.STEP_UP, d.outcome().name());
        assertFalse(d.deviceVerified());
        assertTrue(d.risk().factors().stream()
                        .filter(f -> f.name().equals("device-novelty")).allMatch(f -> f.logLikelihoodRatio() >= 0),
                "a typed device id buys no familiarity");
        assertTrue(d.risk().factors().stream().noneMatch(f -> f.name().equals("device-trust")),
                "nor the real laptop's reputation");
        assertTrue(d.risk().factors().stream().anyMatch(f -> f.name().equals("ip-reputation")));
    }

    @Test
    void torExitIsDeniedEvenAtTheUsualHour() {
        Decision d = decide("9. Login through a Tor exit at Alice's usual time",
                alice(S.plus(Duration.ofDays(3)).plus(Duration.ofHours(1)))
                        .network("185.220.101.4", "AS9009", "DE", 50.11, 8.68));
        assertEquals(Outcome.DENY, d.outcome());
    }

    @Test
    void repeatedAttacksCannotPoisonTheBaseline() {
        long before = history.logins("alice");
        for (int i = 0; i < 30; i++) {
            Decision d = run(alice(S.plus(Duration.ofDays(2)).plusSeconds(i * 60L)).device("unknown-pc")
                    .network("185.220.101." + i, "AS9009", "RU", 55.75, 37.62).build());
            assertEquals(Outcome.DENY, d.outcome(), "attempt " + i);
        }
        assertFalse(history.seen("alice", Feature.COUNTRY, "RU"), "denied attempts never become 'familiar'");
        assertEquals(before, history.logins("alice"));
        assertEquals(0, trust.trust(TrustLedger.subjectKey("alice"), S.plus(Duration.ofDays(2))).bad(), 0.0,
                "and never damage Alice's own reputation");
        assertEquals(Outcome.ALLOW, run(alice(S.plus(Duration.ofDays(2)).plus(Duration.ofHours(1))).build()).outcome(),
                "the real Alice is unaffected");
        assertTrue(AuditLog.verify(sink.snapshot(), auditKey, audit.head()).intact(), "all 31 decisions audited");
    }
}

package dev.dwarpal.risk.scorers;

import dev.dwarpal.Fixtures;
import dev.dwarpal.behavior.FailureLog;
import dev.dwarpal.behavior.Feature;
import dev.dwarpal.behavior.InMemoryBehaviorHistory;
import dev.dwarpal.behavior.LoginEvent;
import dev.dwarpal.behavior.TrustLedger;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.NetworkContext;
import dev.dwarpal.pip.ThreatIntel;
import dev.dwarpal.risk.RiskFactor;
import dev.dwarpal.risk.RiskScorer;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScorersTest {

    private static final Instant T = Fixtures.T0;
    private static final NetworkContext MUMBAI = new NetworkContext("203.0.113.10", "AS64500", "IN", 19.07, 72.88, 25);

    private final InMemoryBehaviorHistory history = new InMemoryBehaviorHistory();

    /** Alice: n logins from one IP/ISP/country on one laptop, at 09:00-10:00 UTC. */
    private void seedAlice(int n) {
        for (int i = 0; i < n; i++) {
            history.record(new LoginEvent("alice", "laptop-alice", MUMBAI,
                    T.minus(Duration.ofDays(n - i)).minus(Duration.ofMinutes(30)).plus(Duration.ofMinutes(i % 60))));
        }
    }

    private static double llr(RiskScorer s, AccessRequest r) {
        Optional<RiskFactor> f = s.score(r, SignalSnapshot.empty());
        assertTrue(f.isPresent(), s.name() + " gave no factor");
        return f.get().logLikelihoodRatio();
    }

    private static Fixtures.RequestBuilder alice() {
        return Fixtures.request().network("203.0.113.10", "AS64500", "IN", 19.07, 72.88);
    }

    // ---- novelty (M1) --------------------------------------------------------------------------

    @Test
    void noveltyOrdersEvidenceFromFamiliarToForeign() {
        seedAlice(40);
        NoveltyScorer net = NoveltyScorer.network(history);
        double knownIp = llr(net, alice().build());
        double newIpSameIsp = llr(net, alice().network("203.0.113.99", "AS64500", "IN", 19.07, 72.88).build());
        double newIspSameCountry = llr(net, alice().network("49.207.1.1", "AS24560", "IN", 12.97, 77.59).build());
        double foreign = llr(net, alice().network("185.220.101.4", "AS9009", "RU", 55.75, 37.62).build());
        assertTrue(knownIp < 0, "known IP is reassuring: " + knownIp);
        assertTrue(knownIp < newIpSameIsp && newIpSameIsp < newIspSameCountry && newIspSameCountry < foreign,
                knownIp + " < " + newIpSameIsp + " < " + newIspSameCountry + " < " + foreign);
        double pNew = 2.0 / 42;   // rule of succession: (1 distinct + 1) / (40 logins + 2)
        assertEquals(Math.log(0.99 / pNew) + Math.log(0.90 / pNew) + Math.log(0.60 / pNew), foreign, 1e-9);
    }

    @Test
    void firstEverLoginIsOnlyMildEvidenceSoItStepsUpRatherThanDenies() {
        double cold = llr(NoveltyScorer.network(history), alice().build());
        // ln(.99/.5) + ln(.9/.5) + ln(.6/.5)
        assertEquals(Math.log(0.99 / 0.5) + Math.log(0.9 / 0.5) + Math.log(0.6 / 0.5), cold, 1e-9);
        assertTrue(cold > 1 && cold < 2);
    }

    @Test
    void usersWhoChangeIpOftenAreNotPunishedForANewIp() {
        for (int i = 0; i < 40; i++) {
            history.record(new LoginEvent("roamer", "phone", new NetworkContext("10.0.0." + i, "AS64500", "IN",
                    19.07, 72.88, 25), T.minus(Duration.ofHours(40 - i))));
        }
        AccessRequest r = Fixtures.request().subject("roamer").device("phone")
                .network("10.0.1.200", "AS64500", "IN", 19.07, 72.88).build();
        assertTrue(llr(NoveltyScorer.network(history), r) < 0, "new IP on usual ISP is normal for a roamer");
    }

    @Test
    void deviceNovelty() {
        seedAlice(40);
        NoveltyScorer dev = NoveltyScorer.device(history);
        assertTrue(llr(dev, alice().build()) < 0);
        assertEquals(Math.log(0.95 / (2.0 / 42)), llr(dev, alice().device("unknown-pc").build()), 1e-9);
        assertEquals(Math.log(0.05 / (1 - 2.0 / 42)), llr(dev, alice().build()), 1e-9);
    }

    @Test
    void noveltyParametersAreValidated() {
        assertThrows(IllegalArgumentException.class, () -> new NoveltyScorer("x", history, List.of(), Map.of()));
        assertThrows(IllegalArgumentException.class, () -> new NoveltyScorer("x", history, List.of(Feature.IP), Map.of(Feature.IP, 1.0)));
        assertThrows(IllegalArgumentException.class, () -> new NoveltyScorer("x", history, List.of(Feature.IP), Map.of()));
    }

    // ---- impossible travel (M7) ----------------------------------------------------------------

    @Test
    void haversineMatchesKnownDistance() {
        double km = Geo.haversineKm(19.07, 72.88, 51.507, -0.128);   // Mumbai -> London
        assertTrue(km > 7100 && km < 7300, "km=" + km);
        assertEquals(0, Geo.haversineKm(10, 10, 10, 10), 1e-9);
        assertTrue(Geo.haversineKm(0, 0, 0, 180) > 20000, "antipodal points stay finite");
    }

    @Test
    void impossibleTravelFiresOnlyWhenTrulyImpossible() {
        history.record(new LoginEvent("alice", "laptop-alice", MUMBAI, T));
        ImpossibleTravelScorer s = ImpossibleTravelScorer.withDefaults(history);
        Fixtures.RequestBuilder london = alice().network("81.2.69.160", "AS20712", "GB", 51.507, -0.128);

        assertEquals(Math.log(0.60 / 0.02), llr(s, london.at(T.plus(Duration.ofHours(1))).build()), 1e-9);
        assertTrue(s.score(london.at(T.plus(Duration.ofHours(12))).build(), SignalSnapshot.empty()).isEmpty(),
                "Mumbai to London in 12 h is a flight, not an attack");
        assertTrue(s.score(alice().network("1.1.1.1", "AS13335", "IN", 19.03, 73.03).at(T).build(),
                SignalSnapshot.empty()).isEmpty(), "17 km is inside the GeoIP accuracy radii");
        Optional<RiskFactor> simultaneous = s.score(london.at(T).build(), SignalSnapshot.empty());
        assertTrue(simultaneous.isPresent() && simultaneous.get().evidence().contains("simultaneous"));
        assertTrue(s.score(london.at(T.minus(Duration.ofHours(1))).build(), SignalSnapshot.empty()).isEmpty(),
                "out-of-order timestamps give no speed");
        assertTrue(s.score(Fixtures.request().subject("nobody").build(), SignalSnapshot.empty()).isEmpty());
        assertThrows(IllegalArgumentException.class, () -> new ImpossibleTravelScorer(history, 1000, 0.01, 0.5));
    }

    // ---- login time (M6) -----------------------------------------------------------------------

    @Test
    void circularStatisticsAreCorrect() {
        assertEquals(1.2660658777520082, CircularStats.besselI0(1), 1e-12);
        assertEquals(27.239871823604442, CircularStats.besselI0(5), 1e-9);
        // One login at 23:30 and one at 00:30: midnight is typical, noon is not (the circle wraps).
        List<Integer> aroundMidnight = List.of(23 * 60 + 30, 30);
        assertTrue(CircularStats.logDensityRatio(CircularStats.toAngle(0), aroundMidnight, 8) > 0);
        assertTrue(CircularStats.logDensityRatio(CircularStats.toAngle(12 * 60), aroundMidnight, 8) < -5);
        int busiest = CircularStats.busiestMinute(aroundMidnight, 8);
        assertTrue(busiest == 0 || busiest >= 23 * 60 + 45, "busiest=" + busiest);
        assertThrows(IllegalArgumentException.class, () -> CircularStats.logDensityRatio(0, List.of(), 8));
    }

    @Test
    void usualHourReassuresAndOddHourAlarms() {
        seedAlice(40);
        LoginTimeScorer s = LoginTimeScorer.withDefaults(history);
        assertTrue(llr(s, alice().at(T.plus(Duration.ofDays(1)).minus(Duration.ofMinutes(10))).build()) < 0);
        double night = llr(s, alice().at(T.plus(Duration.ofHours(12))).build());
        assertTrue(night > 2, "21:30 UTC for a 09:00 user: " + night);
    }

    @Test
    void twoDailyHabitsAreBothNormalAndTheGapBetweenIsNot() {
        // Mathematical-fit fix: a single bell curve averaged 03:45 and 08:30 into 06:08 and called
        // the never-used 06:08 the MOST normal time. The kernel density keeps both habits.
        for (int day = 30; day >= 1; day--) {
            history.record(new LoginEvent("alice", "laptop-alice", MUMBAI, T.minus(Duration.ofDays(day)).minus(Duration.ofMinutes(345))));
            history.record(new LoginEvent("alice", "laptop-alice", MUMBAI, T.minus(Duration.ofDays(day)).minus(Duration.ofMinutes(60))));
        }
        // T0 = 09:30 UTC, so habits are at 03:45 and 08:30 UTC.
        LoginTimeScorer s = LoginTimeScorer.withDefaults(history);
        Instant day = T.plus(Duration.ofDays(1));
        double morning = llr(s, alice().at(day.minus(Duration.ofMinutes(345))).build());
        double afternoon = llr(s, alice().at(day.minus(Duration.ofMinutes(60))).build());
        double gap = llr(s, alice().at(day.minus(Duration.ofMinutes(200))).build());   // 06:10, never used
        assertTrue(morning < 0 && afternoon < 0, morning + " " + afternoon);
        assertTrue(gap > morning && gap > afternoon, "the unused gap is less typical than either habit");
    }

    @Test
    void midnightWorkerIsHandledOnTheCircle() {
        List<Instant> times = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            times.add(T.minus(Duration.ofDays(30 - i)).plus(Duration.ofHours(14)).plus(Duration.ofMinutes(i * 2)));
        }
        // T0 is 09:30 UTC, so +14h = 23:30; logins span 23:30 to 00:28.
        times.forEach(t -> history.record(new LoginEvent("owl", "laptop-owl", MUMBAI, t)));
        LoginTimeScorer s = LoginTimeScorer.withDefaults(history);
        RiskFactor f = s.score(Fixtures.request().subject("owl").at(T.plus(Duration.ofHours(14)).plus(Duration.ofMinutes(30))).build(),
                SignalSnapshot.empty()).orElseThrow();
        assertTrue(f.logLikelihoodRatio() < 0, f.evidence());
        assertTrue(f.evidence().contains("busiest 23:") || f.evidence().contains("busiest 00:"), f.evidence());
    }

    @Test
    void perfectlyRegularUserGivesBoundedEvidence() {
        for (int i = 0; i < 20; i++) {
            history.record(new LoginEvent("clock", "pc", MUMBAI, T.minus(Duration.ofDays(20 - i))));
        }
        double odd = llr(LoginTimeScorer.withDefaults(history),
                Fixtures.request().subject("clock").at(T.plus(Duration.ofHours(12))).build());
        // Kernel bound: at most kappa + ln I0(kappa), scaled by confidence 20/30.
        double bound = (8 + Math.log(CircularStats.besselI0(8))) * 20 / 30.0;
        assertTrue(Double.isFinite(odd) && odd > 5 && odd <= bound + 1e-9, "odd=" + odd + " bound=" + bound);
    }

    @Test
    void tooFewSamplesGiveNoTimeEvidence() {
        seedAlice(5);
        assertTrue(LoginTimeScorer.withDefaults(history).score(alice().build(), SignalSnapshot.empty()).isEmpty());
        assertThrows(IllegalArgumentException.class, () -> new LoginTimeScorer(history, 1, 8, 10));
        assertThrows(IllegalArgumentException.class, () -> new LoginTimeScorer(history, 8, 0, 10));
    }

    // ---- trust (M4) ----------------------------------------------------------------------------

    @Test
    void betaReputationWithForgetting() {
        TrustLedger ledger = new TrustLedger(Duration.ofDays(30));
        TrustScorer subject = new TrustScorer(ledger, TrustScorer.Entity.SUBJECT);
        TrustScorer device = new TrustScorer(ledger, TrustScorer.Entity.DEVICE);
        assertTrue(subject.score(alice().build(), SignalSnapshot.empty()).isEmpty(), "unknown is not suspicious");

        for (int i = 0; i < 20; i++) {
            ledger.recordGood(TrustLedger.subjectKey("alice"), T);
        }
        assertEquals(Math.log(1.0 / 21), llr(subject, alice().build()), 1e-9);

        ledger.recordBad(TrustLedger.deviceKey("laptop-alice"), T.minus(Duration.ofDays(60)));
        TrustLedger.Trust t = ledger.trust(TrustLedger.deviceKey("laptop-alice"), T);
        assertEquals(0.25, t.bad(), 1e-6, "two half-lives later the incident weighs a quarter");
        assertTrue(llr(device, alice().build()) > 0);

        ledger.recordGood(TrustLedger.subjectKey("future"), T.plus(Duration.ofDays(1)));
        assertTrue(!ledger.trust(TrustLedger.subjectKey("future"), T).hasEvidence(), "no credit from the future");
        assertThrows(IllegalArgumentException.class, () -> new TrustLedger(Duration.ZERO));
    }

    // ---- failures ------------------------------------------------------------------------------

    @Test
    void bruteForceIsPoissonAndCannotBeGamedWithOneFailure() {
        FailureLog log = new FailureLog();
        FailureRateScorer brute = FailureRateScorer.bruteForce(log);
        assertTrue(brute.score(alice().build(), SignalSnapshot.empty()).isEmpty());

        log.recordFailure("alice", "198.51.100.7", T.minusSeconds(60));
        assertEquals(0.0, llr(brute, alice().build()), 0.0, "one failure must not LOWER risk");

        for (int i = 0; i < 7; i++) {
            log.recordFailure("alice", "198.51.100.7", T.minusSeconds(30 + i));
        }
        assertEquals(8 * Math.log(5 / 0.2) - (5 - 0.2), llr(brute, alice().build()), 1e-9);

        log.recordFailure("bob", "198.51.100.7", T.minus(Duration.ofHours(1)));
        assertTrue(brute.score(Fixtures.request().subject("bob").build(), SignalSnapshot.empty()).isEmpty(),
                "failures outside the window are forgotten");
    }

    @Test
    void passwordSprayCountsDistinctAccountsPerIp() {
        FailureLog log = new FailureLog();
        for (int i = 0; i < 12; i++) {
            log.recordFailure("user" + i, "198.51.100.66", T.minusSeconds(100 + i));
            log.recordFailure("user0", "203.0.113.200", T.minusSeconds(50 + i));   // one account, many tries
        }
        FailureRateScorer spray = FailureRateScorer.passwordSpray(log);
        assertTrue(llr(spray, alice().network("198.51.100.66", "AS64511", "IN", 28.6, 77.2).build()) > 20);
        assertEquals(0.0, llr(spray, alice().network("203.0.113.200", "AS64500", "IN", 19.07, 72.88).build()), 0.0,
                "12 failures on ONE account is brute force, not spray");
        assertThrows(IllegalArgumentException.class, () -> new FailureRateScorer(log,
                FailureRateScorer.Mode.BRUTE_FORCE, Duration.ofMinutes(5), 5, 1));
        assertThrows(IllegalArgumentException.class, () -> new FailureRateScorer(log,
                FailureRateScorer.Mode.BRUTE_FORCE, Duration.ZERO, 1, 5));
    }

    @Test
    void standardSuiteHasEveryScorer() {
        assertEquals(List.of("network-novelty", "device-novelty", "impossible-travel", "login-time",
                        "subject-trust", "device-trust", "brute-force", "password-spray", "attack-surge", "ip-reputation"),
                StandardScorers.all(history, new TrustLedger(Duration.ofDays(30)), new FailureLog(), ThreatIntel::empty)
                        .stream().map(RiskScorer::name).toList());
    }

    // ---- recent-novelty window (C3 regression) -------------------------------------------------

    @Test
    void roamerWhoseEveryLoginIsANewIpIsNotPunishedEvenAfterThousandsOfLogins() {
        // Was: distinct values capped at 256 while logins kept counting, so after 1000 logins the
        // model believed this user changes IP only 26% of the time.
        for (int i = 0; i < 1000; i++) {
            history.record(new LoginEvent("roamer", "phone", new NetworkContext("10.1." + (i / 250) + "." + (i % 250),
                    "AS64500", "IN", 19.07, 72.88, 25), T.minus(Duration.ofMinutes(1000 - i))));
        }
        var r = Fixtures.request().subject("roamer").device("phone").network("10.9.9.9", "AS64500", "IN", 19.07, 72.88).build();
        RiskFactor f = NoveltyScorer.network(history).score(r, SignalSnapshot.empty()).orElseThrow();
        assertTrue(f.evidence().contains("changes IP 100%"), f.evidence());
        assertTrue(f.logLikelihoodRatio() < 0, "new IP on the usual ISP is normal for a roamer: " + f.logLikelihoodRatio());
    }

    @Test
    void novelUserWhoSettlesDownIsJudgedOnRecentBehaviour() {
        for (int i = 0; i < 100; i++) {          // a year of hopping around...
            history.record(new LoginEvent("mover", "pc", new NetworkContext("10.2.0." + i, "AS" + (65000 + i), "IN",
                    19.07, 72.88, 25), T.minus(Duration.ofDays(400 - i))));
        }
        for (int i = 0; i < 200; i++) {          // ...then 200 logins from one home connection
            history.record(new LoginEvent("mover", "pc", MUMBAI, T.minus(Duration.ofHours(200 - i))));
        }
        assertEquals(2.0 / 202, history.novelty("mover", Feature.ASN).pNew(), 1e-12,
                "only the last 200 logins count, and only the first home login was new");
    }

    // ---- attack surge --------------------------------------------------------------------------

    @Test
    void orgWideSurgeRaisesRiskButIsCappedSoAFloodCannotLockEveryoneOut() {
        FailureLog log = new FailureLog();
        AttackSurgeScorer surge = AttackSurgeScorer.withDefaults(log);
        for (int i = 0; i < 15; i++) {
            log.recordFailure("u" + i, "198.51.100." + i, T.minusSeconds(30));
        }
        assertTrue(surge.score(alice().build(), SignalSnapshot.empty()).isEmpty(), "15 failures is a normal day");
        for (int i = 0; i < 5000; i++) {
            log.recordFailure("bot" + i, "10.0." + (i / 250) + "." + (i % 250), T.minusSeconds(60));
        }
        RiskFactor f = surge.score(alice().build(), SignalSnapshot.empty()).orElseThrow();
        assertEquals(Math.log(10), f.logLikelihoodRatio(), 1e-12, "capped at x10");
        assertTrue(f.evidence().contains("heightened alert"));
        assertTrue(surge.score(alice().at(T.plus(Duration.ofHours(1))).build(), SignalSnapshot.empty()).isEmpty(),
                "the alert ends when the window passes");
        assertThrows(IllegalArgumentException.class, () -> new AttackSurgeScorer(log, Duration.ofHours(2), 1, 10, 1));
        assertThrows(IllegalArgumentException.class, () -> new AttackSurgeScorer(log, Duration.ofMinutes(15), 10, 1, 1));
    }

    // ---- IP reputation -------------------------------------------------------------------------

    @Test
    void ipReputationUsesTheStrongestCategoryOnly() {
        ThreatIntel intel = new ThreatIntel(Set.of("192.0.2.66"), Set.of("192.0.2.66", "192.0.2.77"), Set.of("AS16509"));
        IpReputationScorer s = IpReputationScorer.withDefaults(() -> intel);
        assertEquals(Math.log(50), llr(s, alice().network("192.0.2.66", "AS1", "NL", 52, 4).build()), 1e-12,
                "listed as abuse AND Tor: counted once, as abuse");
        assertEquals(Math.log(20), llr(s, alice().network("192.0.2.77", "AS1", "DE", 52, 13).build()), 1e-12);
        assertEquals(Math.log(10), llr(s, alice().network("3.5.140.2", "AS16509", "IN", 19, 72).build()), 1e-12);
        assertTrue(s.score(Fixtures.request().workload().network("3.5.140.2", "AS16509", "IN", 19, 72).build(),
                SignalSnapshot.empty()).isEmpty(), "workloads may run in the cloud");
        assertTrue(s.score(alice().build(), SignalSnapshot.empty()).isEmpty(), "unlisted proves nothing");
        assertThrows(IllegalArgumentException.class, () -> new IpReputationScorer(() -> intel, 0.5, 20, 10));
        assertThrows(IllegalArgumentException.class, () -> new ThreatIntel(Set.of("bad\nentry"), Set.of(), Set.of()));
    }
}

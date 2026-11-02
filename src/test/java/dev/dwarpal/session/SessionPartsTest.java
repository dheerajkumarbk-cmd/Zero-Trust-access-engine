package dev.dwarpal.session;

import dev.dwarpal.Fixtures;
import dev.dwarpal.behavior.FailureLog;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.guard.NonceCache;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.risk.scorers.FailureRateScorer;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The building blocks of Layer 3: replay cache, limits, grant secrecy, signed failure reports. */
class SessionPartsTest {

    private static final Instant T = SessionFixtures.T;

    @Test
    void theNonceCacheAcceptsEachValueOnceWithinItsWindow() {
        NonceCache c = new NonceCache(Duration.ofMinutes(4), 10);
        assertTrue(c.firstUse("a", T));
        assertFalse(c.firstUse("a", T.plus(Duration.ofMinutes(3))), "replay inside the window");
        assertTrue(c.firstUse("b", T.plus(Duration.ofMinutes(3))));
        assertTrue(c.firstUse("a", T.plus(Duration.ofMinutes(4))), "forgotten once its window is over");
        assertEquals(2, c.size(), "expired entries are cleaned up as time moves on");
    }

    @Test
    void aFullNonceCacheRefusesRatherThanForgetsLiveEntries() {
        NonceCache c = new NonceCache(Duration.ofMinutes(4), 3);
        assertTrue(c.firstUse("1", T));
        assertTrue(c.firstUse("2", T));
        assertTrue(c.firstUse("3", T));
        assertFalse(c.firstUse("4", T), "evicting '1' would let it be replayed");
        assertFalse(c.firstUse("1", T), "and '1' is still remembered");
        assertEquals(1, c.refusedWhenFull());
        assertTrue(c.firstUse("4", T.plus(Duration.ofMinutes(5))), "space returns as entries expire");
    }

    @Test
    void nonceRetentionCoversEverySignatureThatCouldStillVerify() {
        // Proof accepted if signedAt is at most 2 min old and at most 2 min in the future:
        // the latest acceptance of a proof first seen at t is t + 4 min.
        SessionLimits l = SessionLimits.defaults();
        assertEquals(Duration.ofMinutes(4), l.maxProofAge().plus(dev.dwarpal.crypto.KeyRing.MAX_CLOCK_SKEW));
    }

    @Test
    void sessionLimitsAreValidated() {
        SessionLimits d = SessionLimits.defaults();
        assertEquals(Duration.ofMinutes(15), d.reauthFor(DataClassification.RESTRICTED));
        assertEquals(Duration.ofHours(1), d.reauthFor(DataClassification.CONFIDENTIAL));
        Map<DataClassification, Duration> partial = new EnumMap<>(DataClassification.class);
        partial.put(DataClassification.PUBLIC, Duration.ofHours(1));
        assertThrows(NullPointerException.class, () -> new SessionLimits(Duration.ofMinutes(30), Duration.ofHours(10),
                partial, 5, 10, Duration.ofMinutes(2), 0.05));
        Map<DataClassification, Duration> full = new EnumMap<>(DataClassification.class);
        for (DataClassification c : DataClassification.values()) {
            full.put(c, Duration.ofHours(1));
        }
        assertThrows(IllegalArgumentException.class, () -> new SessionLimits(Duration.ZERO, Duration.ofHours(10),
                full, 5, 10, Duration.ofMinutes(2), 0.05));
        assertThrows(IllegalArgumentException.class, () -> new SessionLimits(Duration.ofMinutes(30), Duration.ofHours(10),
                full, 0, 10, Duration.ofMinutes(2), 0.05));
        assertThrows(IllegalArgumentException.class, () -> new SessionLimits(Duration.ofMinutes(30), Duration.ofHours(10),
                full, 5, 10, Duration.ofMinutes(2), 1.5));
    }

    @Test
    void aGrantNeverPrintsItsTokenAndResultsKeepTheirShape() {
        SessionGrant g = new SessionGrant("s-1", "secret-token-value", T, T, false);
        assertFalse(g.toString().contains("secret-token-value"));
        SessionResult opened = SessionResult.opened(g, fakeDecision(), "ok");
        assertFalse(opened.toString().contains("secret-token-value"), "a result printed in a log stays safe");
        assertThrows(IllegalArgumentException.class, () -> new SessionResult(SessionResult.Status.GRANTED,
                Optional.of(g), Optional.empty(), "x", false));
    }

    @Test
    void onlyWellFormedTokensReachTheStore() {
        assertTrue(PolicyAdministrator.wellFormed("A".repeat(43)));
        assertTrue(PolicyAdministrator.wellFormed("abc-_09XYZ".repeat(4) + "abc"));
        assertFalse(PolicyAdministrator.wellFormed("A".repeat(42)));
        assertFalse(PolicyAdministrator.wellFormed("A".repeat(42) + "="));
        assertFalse(PolicyAdministrator.wellFormed("A".repeat(42) + "+"));
        assertFalse(PolicyAdministrator.wellFormed(null));
    }

    // ---- Signed failure reports ---------------------------------------------------------------------

    private final SessionFixtures.MutableClock clock = new SessionFixtures.MutableClock();
    private final FailureLog log = new FailureLog();
    private final FailureReportReceiver receiver = new FailureReportReceiver(Fixtures.KEYRING, log, clock, 1000);

    private static SignatureProof sign(KeyPair k, String keyId, FailureReportReceiver.FailureReport r, Instant at) {
        return new SignatureProof(keyId, at, Ed25519.sign(k.getPrivate(),
                SignedMessages.authenticationFailure(r.reportId(), r.subjectId(), r.ip(), r.failedAt(), at)));
    }

    private FailureReportReceiver.FailureReport report(String id) {
        return new FailureReportReceiver.FailureReport(id, "alice", "198.51.100.7", clock.now());
    }

    @Test
    void signedFailureReportsFeedTheBruteForceDetector() {
        for (int i = 0; i < 3; i++) {
            FailureReportReceiver.FailureReport r = report("f-" + i);
            assertTrue(receiver.accept(r, sign(Fixtures.IDP, Fixtures.IDP_KEY_ID, r, clock.now())).accepted());
        }
        assertEquals(3, log.subjectFailures("alice", T.minus(Duration.ofMinutes(15)), T.plus(Duration.ofSeconds(1))));
        double llr = FailureRateScorer.bruteForce(log)
                .score(Fixtures.request().at(T.plus(Duration.ofSeconds(1))).build(), SignalSnapshot.empty())
                .orElseThrow().logLikelihoodRatio();
        assertEquals(3 * Math.log(25) - 4.8, llr, 1e-9);
    }

    @Test
    void forgedReplayedAndStaleFailureReportsAreRefused() {
        FailureReportReceiver.FailureReport r = report("f-1");
        SignatureProof good = sign(Fixtures.IDP, Fixtures.IDP_KEY_ID, r, clock.now());
        assertTrue(receiver.accept(r, good).accepted());
        assertFalse(receiver.accept(r, good).accepted(), "replay would count one failure many times");

        FailureReportReceiver.FailureReport other = report("f-2");
        assertFalse(receiver.accept(other, sign(Fixtures.DEVICE_AGENT, Fixtures.DEVICE_KEY_ID, other, clock.now()))
                .accepted(), "a device key cannot report login failures");
        KeyPair attacker = Ed25519.generateKeyPair();
        assertFalse(receiver.accept(other, sign(attacker, Fixtures.IDP_KEY_ID, other, clock.now())).accepted(),
                "a forged signature under the IdP's key id");
        FailureReportReceiver.FailureReport retargeted = new FailureReportReceiver.FailureReport("f-1x", "carol",
                r.ip(), r.failedAt());
        assertFalse(receiver.accept(retargeted, new SignatureProof(Fixtures.IDP_KEY_ID, good.signedAt(),
                good.signature())).accepted(), "the subject is signed: it cannot be switched to lock out someone else");

        FailureReportReceiver.FailureReport old = report("f-3");
        SignatureProof oldProof = sign(Fixtures.IDP, Fixtures.IDP_KEY_ID, old, clock.now());
        clock.advance(Duration.ofMinutes(6));
        assertFalse(receiver.accept(old, oldProof).accepted(), "signed more than 5 minutes ago");

        FailureReportReceiver.FailureReport ancient = new FailureReportReceiver.FailureReport("f-4", "alice",
                r.ip(), clock.now().minus(Duration.ofHours(2)));
        assertFalse(receiver.accept(ancient, sign(Fixtures.IDP, Fixtures.IDP_KEY_ID, ancient, clock.now())).accepted(),
                "older than the failure log keeps");
        FailureReportReceiver.FailureReport future = new FailureReportReceiver.FailureReport("f-5", "alice",
                r.ip(), clock.now().plus(Duration.ofMinutes(10)));
        assertFalse(receiver.accept(future, sign(Fixtures.IDP, Fixtures.IDP_KEY_ID, future, clock.now())).accepted(),
                "a failure dated after its own report");

        assertEquals(1, log.subjectFailures("alice", T.minus(Duration.ofHours(3)), clock.now().plus(Duration.ofHours(1))));
        assertEquals(7, receiver.rejected(), "replay, device key, forgery, re-target, stale, ancient, future");
    }

    private static dev.dwarpal.decision.Decision fakeDecision() {
        return SessionFixtures.engine().decide(Fixtures.request().build(), SignalSnapshot.empty());
    }
}

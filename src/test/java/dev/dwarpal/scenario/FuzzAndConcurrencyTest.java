package dev.dwarpal.scenario;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.behavior.FailureLog;
import dev.dwarpal.behavior.InMemoryBehaviorHistory;
import dev.dwarpal.behavior.LearningDecisionPoint;
import dev.dwarpal.behavior.TrustLedger;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AuthMethod;
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
import dev.dwarpal.pip.InMemoryDirectory;
import dev.dwarpal.pip.ThreatIntel;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.risk.scorers.StandardScorers;
import dev.dwarpal.runtime.DecisionPipeline;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Robustness: random inputs and parallel load must never crash, corrupt numbers or break the audit chain. */
class FuzzAndConcurrencyTest {

    private static final Instant S = Instant.parse("2026-11-02T04:00:00Z");
    private static final String[] COUNTRIES = {"IN", "US", "GB", "RU", "CN", "BR", "DE", "NG", "JP", "AU"};

    private final InMemoryBehaviorHistory history = new InMemoryBehaviorHistory();
    private final TrustLedger trust = new TrustLedger(Duration.ofDays(30));
    private final FailureLog failures = new FailureLog();
    private final InMemoryAuditSink sink = new InMemoryAuditSink();
    private final SecretKey key;
    private final AuditLog audit;
    private final DecisionPoint pdp;

    FuzzAndConcurrencyTest() throws Exception {
        key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        audit = new AuditLog(key, sink);
        InMemoryDirectory directory = new InMemoryDirectory(
                List.of(new Subject("alice", SubjectType.HUMAN, Set.of("engineer"), "engineering"),
                        new Subject("svc-batch", SubjectType.WORKLOAD, Set.of("batch"), "ops")),
                List.of(new Resource("wiki", ResourceKind.PRIVATE_APP, DataClassification.INTERNAL),
                        new Resource("payroll", ResourceKind.PRIVATE_APP, DataClassification.RESTRICTED),
                        new Resource("crm", ResourceKind.SAAS_DATA, DataClassification.CONFIDENTIAL)),
                List.of("laptop-alice"));
        PolicyEngine engine = PolicyEngine.builder().policySet(PolicyEngineTest.POLICIES).directory(directory)
                .keyRing(Fixtures.KEYRING).gate(new HoneytokenGate()).gate(new DenyListGate())
                .scorers(StandardScorers.all(history, trust, failures,
                        () -> new ThreatIntel(Set.of(), Set.of("185.220.101.4"), Set.of("AS16509"))))
                .aggregator(new BayesianRiskAggregator(0.001, Math.log(1000)))
                .costModel(new CostModel(1000, 1, 20, 0.05)).build();
        pdp = DecisionPipeline.standard(engine, audit, history, trust, Clock.fixed(S, ZoneOffset.UTC));
    }

    private static String id(Random r, String prefix) {
        return prefix + Integer.toHexString(r.nextInt(64));
    }

    private Fixtures.RequestBuilder randomRequest(Random r, int i) {
        Fixtures.RequestBuilder b = Fixtures.request().id("fz-" + i)
                .at(S.plusSeconds(r.nextInt(20 * 86_400) - 10L * 86_400))
                .subject(r.nextInt(3) == 0 ? id(r, "user") : (r.nextBoolean() ? "alice" : "svc-batch"))
                .device(r.nextInt(3) == 0 ? "laptop-alice" : id(r, "dev"))
                .network(r.nextInt(256) + "." + r.nextInt(256) + ".0." + r.nextInt(256),
                        r.nextInt(4) == 0 ? "AS16509" : "AS" + (64500 + r.nextInt(20)),
                        COUNTRIES[r.nextInt(COUNTRIES.length)],
                        r.nextDouble() * 180 - 90, r.nextDouble() * 360 - 180)
                .action(Action.values()[r.nextInt(Action.values().length)]);
        switch (r.nextInt(3)) {
            case 0 -> b.resource("wiki", ResourceKind.PRIVATE_APP, DataClassification.INTERNAL);
            case 1 -> b.resource("payroll", ResourceKind.WEB, DataClassification.PUBLIC);   // lies about the resource
            default -> b.resource(id(r, "res"), ResourceKind.SAAS_DATA, DataClassification.PUBLIC);
        }
        if (r.nextBoolean()) {
            b.unsignedPosture();
        }
        if (r.nextBoolean()) {
            b.authenticated(AuthMethod.values()[r.nextInt(AuthMethod.values().length)],
                    Duration.ofMinutes(r.nextInt(90) - 30));
            if (r.nextInt(4) == 0) {
                b.unsignedAuthentication();
            }
        }
        if (r.nextBoolean()) {
            b.unmanaged();
        }
        return b;
    }

    @Test
    void randomRequestsNeverCrashOrCorruptTheTrail() {
        Random r = new Random(20261101);
        int n = 3000;
        for (int i = 0; i < n; i++) {
            if (r.nextInt(5) == 0) {
                failures.recordFailure(r.nextBoolean() ? "alice" : id(r, "user"), "198.51.100." + r.nextInt(8),
                        S.plusSeconds(r.nextInt(3600) - 1800L));
            }
            Decision d = pdp.decide(randomRequest(r, i).build(), SignalSnapshot.empty());
            assertNotNull(d.outcome());
            double p = d.risk().posteriorAttack();
            assertTrue(p >= 0 && p <= 1 && Double.isFinite(p), "P(attack)=" + p + " for request " + i);
            assertTrue(d.risk().factors().stream().allMatch(f -> Double.isFinite(f.logLikelihoodRatio())));
            assertFalse(d.matchedPolicyId().equals("engine-error"), "engine error on request " + i + ":\n" + d.analystReport());
            assertTrue(d.reasons().stream().noneMatch(s -> s.contains("\n")), "raw newline in a reason");
        }
        assertEquals(n, sink.snapshot().size(), "every decision audited");
        assertTrue(AuditLog.verify(sink.snapshot(), key, audit.head()).intact());
        assertEquals(0, ((LearningDecisionPoint) pdp).learningFailures());
    }

    @Test
    void decisionLatencyMeetsTheTwentyMillisecondTarget() {
        // NFR-01: p99 under 20 ms. Requests are built (and signed) before timing: we measure the PDP only.
        // 80 learned logins first, so every scorer has real history to work on.
        for (int i = 0; i < 80; i++) {
            pdp.decide(Fixtures.request().id("seed-" + i).at(S).network("203.0.113.10", "AS64500", "IN", 19.07, 72.88)
                    .authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1)).build(), SignalSnapshot.empty());
        }
        int n = 2000;
        var requests = new java.util.ArrayList<dev.dwarpal.domain.AccessRequest>();
        for (int i = 0; i < n + 500; i++) {
            requests.add(Fixtures.request().id("lat-" + i).at(S).network("203.0.113.10", "AS64500", "IN", 19.07, 72.88).build());
        }
        long[] nanos = new long[n];
        for (int i = 0; i < requests.size(); i++) {
            long t0 = System.nanoTime();
            pdp.decide(requests.get(i), SignalSnapshot.empty());
            if (i >= 500) {                       // first 500 are JIT warm-up
                nanos[i - 500] = System.nanoTime() - t0;
            }
        }
        java.util.Arrays.sort(nanos);
        double p50 = nanos[n / 2] / 1e6;
        double p99 = nanos[(int) (n * 0.99)] / 1e6;
        // Coverage instrumentation (JaCoCo) slows every line; asserting 20 ms there would make the build
        // flaky, and flaky tests teach people to ignore red builds. Strict target uninstrumented,
        // generous ceiling (still catches pathological regressions) when instrumented.
        boolean instrumented = java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments()
                .stream().anyMatch(arg -> arg.contains("jacoco"));
        double limit = instrumented ? 100 : 20;
        System.out.printf(java.util.Locale.ROOT, "LATENCY full pipeline (10 scorers, signatures, audit, learning)%s: p50=%.3f ms p99=%.3f ms (limit %.0f)%n",
                instrumented ? " [coverage-instrumented]" : "", p50, p99, limit);
        assertTrue(p99 < limit, "p99=" + p99 + " ms");
    }

    @Test
    void parallelLoadKeepsTheAuditChainIntact() throws Exception {
        int threads = 8;
        int perThread = 250;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();
        CountDownLatch start = new CountDownLatch(1);
        for (int t = 0; t < threads; t++) {
            int thread = t;
            pool.submit(() -> {
                Random r = new Random(thread);
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        Fixtures.RequestBuilder b = (i % 2 == 0)
                                // A brand-new user must pass MFA before anything is learned, so Alice uses WebAuthn.
                                ? Fixtures.request().id("t" + thread + "-" + i).at(S)
                                .network("203.0.113.10", "AS64500", "IN", 19.07, 72.88)
                                .resource("wiki", ResourceKind.PRIVATE_APP, DataClassification.INTERNAL)
                                .authenticated(AuthMethod.WEBAUTHN, Duration.ofMinutes(1))
                                : randomRequest(r, thread * 10_000 + i).id("t" + thread + "-" + i).subject(id(r, "user"));
                        pdp.decide(b.build(), SignalSnapshot.empty());
                        failures.recordFailure("user" + i, "198.51.100." + thread, S);
                    }
                } catch (Throwable e) {
                    errors.add(e);
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(2, TimeUnit.MINUTES));
        assertTrue(errors.isEmpty(), "errors under load: " + errors);
        assertEquals(threads * perThread, sink.snapshot().size());
        assertTrue(AuditLog.verify(sink.snapshot(), key, audit.head()).intact(), "chain intact under concurrency");
        assertEquals(threads * perThread / 2, history.logins("alice"), "every normal login learned exactly once");
        assertEquals(0, ((LearningDecisionPoint) pdp).learningFailures());
    }
}

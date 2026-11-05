package dev.dwarpal.api;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.edge.EdgeGrant;
import dev.dwarpal.edge.EdgeResult;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** What a session use costs over the network: mutual TLS, JSON both ways, the PA, the engine and two audit records. */
class ApiLatencyTest {

    private static final int WARM_UP = 200;
    private static final int MEASURED = 1000;
    /**
     * The plan's target is 20 ms at the median. The gate catches a regression of the median at 50 ms and of the tail at
     * 250 ms: the tail of 1,000 calls on a laptop that is also running a build or a garbage collection reaches 130 ms
     * without anything being wrong (seen on 2026-11-05 with the full suite running), so a tighter tail limit made the
     * gate fail on load, not on code.
     */
    private static final double P50_LIMIT_MS = 50;
    private static final double P99_LIMIT_MS = 250;

    @Test
    void aSessionUseOverTheApiIsFast() {
        try (ApiKit.Harness h = new ApiKit.Harness(ApiSettings.defaults()); RemoteSessionAuthority c = h.client("gateway")) {
            KeyPair key = Ed25519.generateKeyPair();
            EdgeGrant grant = h.open(c, key, h.world.request().build()).grant().orElseThrow();
            double[] ms = new double[MEASURED];
            for (int i = 0; i < WARM_UP + MEASURED; i++) {
                long start = System.nanoTime();
                EdgeResult r = h.use(c, key, grant, h.world.request().build());
                long took = System.nanoTime() - start;
                assertEquals(EdgeResult.Status.GRANTED, r.status());
                if (i >= WARM_UP) {
                    ms[i - WARM_UP] = took / 1e6;
                }
            }
            Arrays.sort(ms);
            double p50 = ms[MEASURED / 2];
            double p99 = ms[(int) (MEASURED * 0.99)];
            System.out.printf("LATENCY session use over the API (mTLS 1.3, JSON, PA, engine, audit): p50=%.3f ms p99=%.3f ms%n",
                    p50, p99);
            assertTrue(p50 < P50_LIMIT_MS, "p50 " + p50 + " ms");
            assertTrue(p99 < P99_LIMIT_MS, "p99 " + p99 + " ms");
        }
    }
}

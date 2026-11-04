package dev.dwarpal.swg;

import dev.dwarpal.domain.Action;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** What the web decision adds to a request: filter, engine decision and audit record, in process. */
class WebLatencyTest {

    private final SwgWorld s = new SwgWorld();

    @Test
    void aDecisionIsFastAndSafeUnderParallelLoad() throws Exception {
        WebAccess access = s.access(SwgWorld.policy().build());
        WebIdentity alice = s.alice();
        for (int i = 0; i < 300; i++) {
            access.check(alice, "news.example", true, Action.READ); // warm-up
        }
        int n = 2000;
        long[] nanos = new long[n];
        for (int i = 0; i < n; i++) {
            long t = System.nanoTime();
            WebVerdict v = access.check(alice, i % 2 == 0 ? "news.example" : "evil.example", true, Action.READ);
            nanos[i] = System.nanoTime() - t;
            assertEquals(i % 2 == 0, v.allowed());
        }
        Arrays.sort(nanos);
        double p50 = nanos[n / 2] / 1e6;
        double p99 = nanos[(int) (n * 0.99)] / 1e6;
        System.out.printf("LATENCY web decision (filter + engine + audit): p50=%.3f ms p99=%.3f ms%n", p50, p99);
        assertTrue(p99 < 20, "p99 " + p99 + " ms (limit 20)");

        ExecutorService pool = Executors.newFixedThreadPool(16);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < 400; i++) {
                int k = i;
                results.add(pool.submit(() -> access.check(alice, k % 2 == 0 ? "news.example" : "x.malware.example", true,
                        Action.READ).allowed() == (k % 2 == 0)));
            }
            for (Future<Boolean> f : results) {
                assertTrue(f.get());
            }
        } finally {
            pool.shutdownNow();
        }
    }
}

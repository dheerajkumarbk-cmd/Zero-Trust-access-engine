package dev.dwarpal.casb;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Detectors on the largest content the CASB inspects (8 MiB) with inputs chosen to hurt: the worst case
 * of each detector. There are no regular expressions to backtrack; this proves the work really is
 * linear, with a generous limit so a slow build machine does not make it flaky.
 */
class DetectorPerformanceTest {

    private static final int SIZE = Inspection.MAX_BYTES;
    private static final long LIMIT_MS = 5000;

    private static String fill(String unit) {
        return unit.repeat(SIZE / unit.length() + 1).substring(0, SIZE);
    }

    private static Map<String, String> adversarial() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("digits only", "1".repeat(SIZE));
        m.put("digit groups with spaces", fill("1 "));
        m.put("digit groups with invisible separators", fill("1\u200b \u200b"));
        m.put("many near-cards", fill("4111 1111 1111 111 "));
        m.put("at signs", "@".repeat(SIZE));
        m.put("long local parts", fill("a".repeat(70) + "@"));
        m.put("dots and at signs", fill("a.@.b@"));
        m.put("BEGIN markers on lines", fill("-----BEGIN " + "PRIVATE KEY-----\n"));
        m.put("BEGIN markers with END", fill("-----BEGIN " + "PRIVATE KEY-----\n-----END " + "PRIVATE KEY-----\n"));
        m.put("BEGIN without kind", fill("BEGIN BEGIN BEGIN "));
        m.put("token prefixes", fill("gh" + "p_ghp_ghs_gho_" + "xo" + "xb-xo" + "xb-" + "AK" + "IAAKIAASIA"));
        m.put("github_pat prefixes", fill("github_pat_"));
        m.put("one long word", "A".repeat(SIZE));
        m.put("PAN-like words", fill("ABCPD1234E "));
        m.put("alphanumeric soup", fill("a1B2c3D4e5 "));
        m.put("only invisible characters", "\u200b".repeat(SIZE));
        Random rnd = new Random(7);
        StringBuilder sb = new StringBuilder(SIZE);
        String alphabet = "0123456789 -@.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_\n\u200b";
        while (sb.length() < SIZE) {
            sb.append(alphabet.charAt(rnd.nextInt(alphabet.length())));
        }
        m.put("random mixture", sb.toString());
        return m;
    }

    @Test
    @Timeout(180)
    void everyWorstCaseIsScannedInLinearTime() {
        for (Map.Entry<String, String> e : adversarial().entrySet()) {
            long start = System.nanoTime();
            Detectors.Scan scan = Detectors.scanAll(e.getValue());
            long ms = (System.nanoTime() - start) / 1_000_000;
            System.out.printf("DETECTORS %-40s %5d ms, %d findings%n", e.getKey(), ms, scan.findings().size());
            assertTrue(ms < LIMIT_MS, e.getKey() + " took " + ms + " ms");
        }
    }

    @Test
    @Timeout(120)
    void aFullSizeUploadIsInspectedAndRedactedWithinTheLimit() {
        String chunk = "order 4111111111111112 ref ABCPD1234E mail a@b.example uid 5555555555554444 end\n";
        byte[] content = fill(chunk).getBytes(StandardCharsets.UTF_8);
        long start = System.nanoTime();
        Inspection i = Inspection.of(content);
        String redacted = i.redacted().orElseThrow();
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.printf("DETECTORS full-size inspection and redaction (%d findings kept, truncated=%b): %d ms%n",
                i.findings().size(), i.truncated(), ms);
        assertTrue(i.truncated(), "more than the per-type cap of each kind in 8 MiB");
        assertEquals(3 * Detectors.MAX_PER_TYPE, i.findings().size(), "PAN, e-mail and card: each kept up to the cap");
        assertTrue(redacted.contains("[REDACTED:"));
        assertTrue(ms < LIMIT_MS * 2, "took " + ms + " ms");
    }
}

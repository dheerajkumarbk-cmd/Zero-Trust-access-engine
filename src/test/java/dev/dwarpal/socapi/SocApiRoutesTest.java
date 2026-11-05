package dev.dwarpal.socapi;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Routing and settings without a server: every path has exactly one reading or none. */
class SocApiRoutesTest {

    @Test
    void pathsResolveToOneEndpointWithPlainParameters() {
        assertEquals(SocApiServer.Endpoint.CASE, SocApiServer.route("/v1/cases/case-1", null).orElseThrow().endpoint());
        assertEquals(List.of("subject", "a.b_c:d@e"),
                SocApiServer.route("/v1/risk/subject/a.b_c:d@e", null).orElseThrow().params());
        assertEquals(SocApiServer.Endpoint.RISK_TOP, SocApiServer.route("/v1/risk/top", null).orElseThrow().endpoint());
        for (String bad : List.of("/v1/cases/a%20b", "/v1/cases/a\\b", "/v1/cases/a;b", "/v1/cases/a b", "/v1/cases/a/b/c",
                "/v1/cases/" + "x".repeat(129), "/" + "v".repeat(301), "/v1/cases/é", "/v1/cases/a+b",
                "/v1/cases/a..b", "/v1/cases/", "")) {
            assertTrue(SocApiServer.route(bad, null).isEmpty(), bad);
        }
        assertTrue(SocApiServer.route(null, null).isEmpty());
        assertTrue(SocApiServer.route("/v1/health", "a=1").isEmpty());
    }

    @Test
    void settingsRefuseEveryOutOfRangeValue() {
        Duration s5 = Duration.ofSeconds(5);
        Duration d1 = Duration.ofDays(1);
        int[][] bad = {{0, 32, 16, 1024, 1, 1, 1, 1}, {65, 32, 16, 1024, 1, 1, 1, 1}, {8, 0, 16, 1024, 1, 1, 1, 1},
                {8, 1001, 16, 1024, 1, 1, 1, 1}, {8, 32, 0, 1024, 1, 1, 1, 1}, {8, 32, 257, 1024, 1, 1, 1, 1},
                {8, 32, 16, 10, 1, 1, 1, 1}, {8, 32, 16, 1024, 1, 0, 1, 1}, {8, 32, 16, 1024, 1, 1, 0, 1},
                {8, 32, 16, 1024, 1, 1, 1, 0}};
        for (int[] b : bad) {
            assertThrows(IllegalArgumentException.class, () -> new SocApiSettings(b[0], b[1], b[2], b[3], s5, b[4], b[5],
                    b[6], b[7], d1));
        }
        assertThrows(IllegalArgumentException.class, () -> new SocApiSettings(8, 32, 16, 1024, Duration.ofSeconds(-1),
                1, 1, 1, 1, d1));
        assertThrows(IllegalArgumentException.class, () -> new SocApiSettings(8, 32, 16, 1024, s5, 1, 1, 1, 1,
                Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new SocApiSettings(8, 32, 16, 1024, s5, 1, 1, 1, 1,
                Duration.ofDays(-1)));
        assertEquals(1024, new SocApiSettings(8, 32, 16, 1024, s5, 1, 1, 1, 1, d1).maxBodyBytes());
    }
}

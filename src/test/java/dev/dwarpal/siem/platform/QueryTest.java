package dev.dwarpal.siem.platform;

import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Part D: the search language is strict, bounded and means what it says. */
class QueryTest {

    private static final SecurityEvent FLOW = new SecurityEvent("fw-1", Fx.T0, "firewall",
            SecurityEvent.Category.NETWORK, "network.flow", SecurityEvent.EventOutcome.SUCCESS,
            SecurityEvent.Provenance.COLLECTED, List.of(Entity.ip("10.20.0.5"), Entity.ip("203.0.113.66"),
            Entity.device("laptop-u4")), Map.of("dport", "4444", "bytes", "320", "cmd", "PowerShell -ENC x",
            "action", "READ"));

    private static boolean m(String q) {
        return Query.parse(q).matches(FLOW);
    }

    // ---- abuse first ----------------------------------------------------------------------------------------

    @Test
    void malformedAndOversizedQueriesAreErrorsNeverEmptyResults() {
        List<String> bad = List.of("dataset =", "= firewall", "dataset firewall", "(dataset = firewall",
                "dataset = firewall)", "dataset ! firewall", "dataset = \"open", "category = netwrk",
                "outcome = maybe", "provenance = trusted", "at > yesterday", "at ~ 2026", "bytes > lots",
                "dport in 4444", "dport in (4444", "x = 1 | count", "x = 1 | count by", "x = 1 | count by a, a",
                "x = 1 | count by a, b, c, d, e", "1bad = x", "a = b c = d", "cmd ~ \"\"", "a = $",
                "dport in (" + "1,".repeat(Query.MAX_IN) + "1)", "a = \"" + "v".repeat(Query.MAX_VALUE + 1) + "\"",
                "a = " + "v".repeat(Query.MAX_VALUE + 1), "a = 1 and", "not", "x = 1 | count by 9");
        for (String q : bad) {
            assertThrows(QueryException.class, () -> Query.parse(q), q.length() > 50 ? q.substring(0, 50) : q);
        }
        assertThrows(IllegalArgumentException.class, () -> Query.parse("a = 1 or ".repeat(400) + "a = 1"));
        assertThrows(QueryException.class, () -> Query.parse("(".repeat(40) + "a = 1" + ")".repeat(40)), "depth");
        assertThrows(QueryException.class, () -> Query.parse("not ".repeat(40) + "a = 1"), "depth");
        assertThrows(QueryException.class, () -> Query.parse("a = 1 and ".repeat(150) + "a = 1"), "nodes or tokens");
        String error = assertThrows(QueryException.class, () -> Query.parse("category = s3cr3t-value")).getMessage();
        assertTrue(error.length() < 120, "errors quote little");
    }

    @Test
    void parsingIsLinearEvenOnHostileInput() {
        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
            for (int i = 0; i < 2_000; i++) {
                assertThrows(QueryException.class, () -> Query.parse("a = \"" + "\\\\".repeat(500)));
                Query.parse("a ~ \"" + "x".repeat(200) + "\"").matches(FLOW);
            }
        });
    }

    // ---- meaning --------------------------------------------------------------------------------------------

    @Test
    void comparisonsBooleansAndFields() {
        assertTrue(m(""));
        assertTrue(m("*"));
        assertTrue(m("dataset = firewall and action = network.flow"));
        assertTrue(m("category = network and outcome = success and provenance = collected"), "enums ignore case");
        assertTrue(m("device = laptop-u4 and ip = 203.0.113.66"), "any entity of the kind");
        assertFalse(m("subject = u4"));
        assertTrue(m("dport = 4444 and bytes > 300 and bytes >= 320 and bytes < 321 and bytes <= 320"));
        assertFalse(m("bytes > 320"));
        assertFalse(m("cmd > 3"), "not a number: false");
        assertTrue(m("cmd ~ \" -enc\""), "contains, ignoring case");
        assertTrue(m("dport in (80, 443, 4444)"));
        assertTrue(m("f.action = READ and action = network.flow"), "f. reaches a field named like a built-in");
        assertFalse(m("missing = x"));
        assertFalse(m("missing != x"), "a missing field never compares");
        assertTrue(m("not missing = x"));
        assertTrue(m("(dataset = cloud or dataset = firewall) and not outcome = failure"));
        assertFalse(m("dataset != firewall"));
        assertTrue(m("id = fw-1"));
        assertTrue(m("at = 2026-11-04T10:00:00Z and at >= 2026-11-04T10:00:00Z and at <= 2026-11-04T10:00:00Z"));
        assertTrue(m("at > 2026-11-04T09:00:00Z and at < 2026-11-04T11:00:00Z and at != 2026-11-04T09:00:00Z"));
        assertTrue(m("at in (2026-11-04T09:00:00Z, 2026-11-04T10:00:00Z)"));
        assertFalse(m("at < 2026-11-04T10:00:00Z or at > 2026-11-04T10:00:00Z"));
        assertTrue(m("dataset = \"fire\\\"wall\" or dataset = \"firewall\""));
        assertTrue(m("session != x or resource != y or true = 1 or dataset = firewall"));

        Query q = Query.parse("dataset = firewall and device = laptop-u4 and (a = 1 or b = 2) | count by dst, device");
        assertEquals(List.of("dst", "device"), q.countBy());
        assertEquals(2, q.required().size());
        assertEquals(4, q.comparisons().size());
        assertTrue(q.toString().contains("count by"));
        assertEquals(1, Query.parse("a = 1").required().size());
        assertTrue(Query.parse("a = 1 or b = 2").required().isEmpty());
        assertTrue(Query.all().matches(FLOW));
        assertEquals(List.of("10.20.0.5", "203.0.113.66"), Query.values(FLOW, "ip"));
        assertEquals(List.of("SUCCESS"), Query.values(FLOW, "outcome"));
        assertEquals(List.of(Fx.T0.toString()), Query.values(FLOW, "at"));
        assertTrue(Query.entityKind("session").isPresent());
        assertTrue(Query.entityKind("resource").isPresent());
        assertFalse(Query.entityKind("host").isPresent());
        assertTrue(Query.number("-1.5").isPresent());
        assertFalse(Query.number("1.2.3").isPresent());
        assertFalse(Query.number("-").isPresent());
    }
}

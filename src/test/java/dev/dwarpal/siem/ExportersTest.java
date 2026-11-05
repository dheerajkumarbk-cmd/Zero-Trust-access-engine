package dev.dwarpal.siem;

import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Layer 5 part A: SIEM export. Hostile names and values first: nothing may forge a field or an event. */
class ExportersTest {

    private static final Instant AT = Instant.parse("2026-11-05T09:00:00.123456789Z");
    private static final String NL = String.valueOf((char) 10);
    private static final String CR = String.valueOf((char) 13);
    private static final String LS = String.valueOf((char) 0x2028);
    private static final String RLO = String.valueOf((char) 0x202E);

    /** Values and names an attacker would try in every format. */
    private static AuditEvent hostile() {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("subject", "u1");
        f.put("reason", "x" + NL + "CEF:0|Evil|Evil|1|forged|forged|10|suser=root");
        f.put("pipe", "a|b\\|c");
        f.put("eq", "a=b suser=root act=allow");
        f.put("sd", "\"] [evil@1 admin=\"yes\"]");
        f.put("crlf", "line" + CR + NL + "<13>1 2026-11-05T00:00:00Z host app - FORGED -");
        f.put("bidi", "ok" + RLO + "evil" + LS + "next");
        f.put("we ird=name]\"", "v");
        f.put("suser", "not-the-real-actor");
        return new AuditEvent(17, AT, "ACCESS_DECISION", "pdp", f);
    }

    private static boolean oneLine(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isISOControl(c) || c == 0x2028 || c == 0x2029 || (c >= 0x202A && c <= 0x202E)
                    || (c >= 0x2066 && c <= 0x2069)) {
                return false;
            }
        }
        return true;
    }

    // ---- CEF -----------------------------------------------------------------------------------------

    /** Parses a CEF extension the way a SIEM does: unescaped {@code key=} starts a field. */
    private static Map<String, String> cefExtension(String line) {
        int pipes = 0;
        int i = 0;
        for (; i < line.length() && pipes < 7; i++) {
            if (line.charAt(i) == '\\') {
                i++;
            } else if (line.charAt(i) == '|') {
                pipes++;
            }
        }
        String ext = line.substring(i);
        Map<String, String> out = new LinkedHashMap<>();
        Matcher m = Pattern.compile("(?:^| )([A-Za-z0-9_]+)=").matcher(ext);
        List<int[]> starts = new java.util.ArrayList<>();
        while (m.find()) {
            if (m.start(1) > 0 && ext.charAt(m.start(1) - 1) != ' ') {
                continue;
            }
            int bs = 0;
            for (int k = m.start() - 1; k >= 0 && ext.charAt(k) == '\\'; k--) {
                bs++;
            }
            if (bs % 2 == 0) {
                starts.add(new int[]{m.start(1), m.end()});
            }
        }
        for (int k = 0; k < starts.size(); k++) {
            int end = k + 1 < starts.size() ? starts.get(k + 1)[0] - 1 : ext.length();
            out.put(ext.substring(starts.get(k)[0], starts.get(k)[1] - 1), ext.substring(starts.get(k)[1], end));
        }
        return out;
    }

    @Test
    void cefCannotBeForged() {
        String line = Exporters.cef(hostile());
        assertTrue(oneLine(line), line);
        assertTrue(line.startsWith("CEF:0|Dwarpal|Dwarpal|0.1|ACCESS_DECISION|ACCESS_DECISION|3|rt="));
        Map<String, String> ext = cefExtension(line);
        assertEquals("pdp", ext.get("suser"), "the real actor; the payload field went to its own key");
        assertEquals("not-the-real-actor", ext.get("dwfsuser"));
        assertFalse(ext.containsKey("act"));
        assertEquals("a\\=b suser\\=root act\\=allow", ext.get("dwfeq"));
        assertEquals("17", ext.get("externalId"));
        assertTrue(ext.keySet().stream().anyMatch(k -> k.startsWith("dwh")), "odd names hashed");
        assertTrue(ext.get("dwfreason").startsWith("x\\n"));
        assertTrue(ext.get("dwfbidi").contains("\\\\u202e"));
        assertEquals(13, ext.size(), ext.toString());
    }

    @Test
    void cefHeaderFieldsEscapePipesAndBackslashes() {
        assertEquals("a\\|b\\\\c", Exporters.cefHeaderValue("a|b\\c"));
        assertEquals("a\\\\u000ab", Exporters.cefHeaderValue("a" + NL + "b"));
        Alert a = new Alert("al-x-1", "x", Severity.HIGH, AT, List.of(Entity.subject("u1")), List.of(1L), 3,
                "x|y=z");
        String line = Exporters.cef(a);
        assertTrue(line.startsWith("CEF:0|Dwarpal|Dwarpal|0.1|x|x\\|y=z|8|"), line);
        Map<String, String> ext = cefExtension(line);
        assertEquals("x|y\\=z", ext.get("msg"));
        assertEquals("3", ext.get("cnt"));
        assertEquals("SUBJECT:u1", ext.get("dwfentities"));
    }

    @Test
    void namesMapToDistinctSafeKeys() {
        assertEquals("dwfsubject", Exporters.cefKey("subject"));
        assertTrue(Exporters.cefKey("a b").matches("dwh[0-9a-f]{24}"));
        assertFalse(Exporters.cefKey("a b").equals(Exporters.cefKey("a_b")));
        assertTrue(Exporters.cefKey("x".repeat(29)).startsWith("dwh"));
        assertEquals("fsubject", Exporters.sdName("subject"));
        assertTrue(Exporters.sdName("we ird=name]\"").matches("h[0-9a-f]{24}"));
        assertTrue(Exporters.sdName("x".repeat(40)).length() <= 32);
    }

    // ---- syslog --------------------------------------------------------------------------------------

    /** Splits RFC 5424 structured data into elements and params as a receiver does. */
    private static Map<String, String> sdParams(String line) {
        Map<String, String> out = new LinkedHashMap<>();
        int i = line.indexOf('[');
        String element = null;
        while (i >= 0 && i < line.length()) {
            char c = line.charAt(i);
            if (c == '[') {
                int sp = line.indexOf(' ', i);
                int close = line.indexOf(']', i);
                element = line.substring(i + 1, sp > 0 && sp < close ? sp : close);
                i = sp > 0 && sp < close ? sp + 1 : close;
            } else if (c == ']') {
                i++;
                if (i >= line.length() || line.charAt(i) != '[') {
                    break;
                }
            } else if (c == ' ') {
                i++;
            } else {
                int eq = line.indexOf('=', i);
                String name = line.substring(i, eq);
                StringBuilder v = new StringBuilder();
                int k = eq + 2;
                for (; line.charAt(k) != '"'; k++) {
                    if (line.charAt(k) == '\\' && "\"\\]".indexOf(line.charAt(k + 1)) >= 0) {
                        k++;
                    }
                    v.append(line.charAt(k));
                }
                out.put(element + "/" + name, v.toString());
                i = k + 1;
            }
        }
        return out;
    }

    @Test
    void syslogCannotBeForged() {
        String line = Exporters.syslog(hostile(), "dwarpal-01", "dwarpal");
        assertTrue(oneLine(line), line);
        assertTrue(line.startsWith("<110>1 2026-11-05T09:00:00.123456Z dwarpal-01 dwarpal - ACCESS_DECISION [audit@32473 "),
                line);
        Map<String, String> p = sdParams(line);
        assertEquals("pdp", p.get("audit@32473/actor"));
        assertEquals("17", p.get("audit@32473/seq"));
        assertEquals("ACCESS_DECISION", p.get("audit@32473/type"));
        assertEquals("\"] [evil@1 admin=\"yes\"]", p.get("fields@32473/fsd"));
        assertFalse(p.keySet().stream().anyMatch(k -> k.startsWith("evil")));
        assertTrue(p.keySet().stream().anyMatch(k -> k.matches("fields@32473/h[0-9a-f]{24}")));
        assertEquals(12, p.size(), p.toString());
    }

    @Test
    void syslogHeaderFieldsAreChecked() {
        assertThrows(IllegalArgumentException.class, () -> Exporters.syslog(hostile(), "two words", "app"));
        assertThrows(IllegalArgumentException.class, () -> Exporters.syslog(hostile(), "host", "a".repeat(49)));
        assertThrows(IllegalArgumentException.class, () -> Exporters.syslog(hostile(), null, "app"));
        assertThrows(IllegalArgumentException.class, () -> Exporters.syslog(hostile(), "host", null));
        AuditEvent longType = new AuditEvent(1, AT, "T".repeat(40), "pdp", Map.of());
        String line = Exporters.syslog(longType, "h", "a");
        assertTrue(line.contains(" - " + "T".repeat(32) + " [audit@"), line);
        assertFalse(line.contains("[fields@"), "no empty element");
    }

    @Test
    void alertsGoToSyslogWithTheirSummaryAsMessage() {
        Alert a = new Alert("al-honeytoken-touched-9", "honeytoken-touched", Severity.CRITICAL, AT,
                List.of(Entity.subject("u1"), Entity.ip("203.0.113.7")), List.of(9L), 1, "honeytoken ] used");
        String line = Exporters.syslog(a, "h", "dwarpal");
        assertTrue(line.startsWith("<106>1 "), line);
        assertTrue(line.endsWith("] honeytoken ] used"), line);
        Map<String, String> p = sdParams(line);
        assertEquals("CRITICAL", p.get("alert@32473/severity"));
        assertEquals("SUBJECT:u1,IP:203.0.113.7", p.get("fields@32473/fentities"));
        assertEquals("9", p.get("fields@32473/fevidence"));
        for (Severity s : Severity.values()) {
            assertTrue(Exporters.syslogSeverity(s) >= 2 && Exporters.syslogSeverity(s) <= 6);
            assertTrue(Exporters.cefSeverity(s) >= 3);
        }
    }

    // ---- JSON lines ----------------------------------------------------------------------------------

    @Test
    void jsonLinesAreLosslessAndOneLine() {
        AuditEvent e = hostile();
        String line = Exporters.jsonLine(e);
        assertTrue(oneLine(line), line);
        JsonValue.JObject o = (JsonValue.JObject) new JsonReader(JsonLimits.defaults()).read(line);
        JsonValue.JObject fields = (JsonValue.JObject) o.get("fields").orElseThrow();
        for (Map.Entry<String, String> f : e.fields().entrySet()) {
            assertEquals(new JsonValue.JString(f.getValue()), fields.get(f.getKey()).orElseThrow(), f.getKey());
        }
        assertEquals(new JsonValue.JString("pdp"), o.get("actor").orElseThrow());
        Alert a = new Alert("al-x-1", "x", Severity.LOW, AT, List.of(Entity.subject("u1")), List.of(1L, 2L), 2,
                "two" + NL + "lines");
        String al = Exporters.jsonLine(a);
        assertTrue(oneLine(al));
        assertTrue(al.contains("\"evidence\":[1,2]"), al);
    }

    // ---- bounds and order ------------------------------------------------------------------------------

    @Test
    void aHugeValueCannotPushOutTheSubject() {
        Map<String, String> f = new LinkedHashMap<>();
        for (int i = 0; i < 40; i++) {
            f.put("aaa" + i, "z".repeat(5000));
        }
        f.put("subject", "u9");
        f.put("sourceIp", "203.0.113.4");
        AuditEvent e = new AuditEvent(3, AT, "ACCESS_DECISION", "pdp", f);
        for (String line : List.of(Exporters.cef(e), Exporters.syslog(e, "h", "a"))) {
            assertTrue(line.length() <= Exporters.MAX_LINE_CHARS + 200, "bounded: " + line.length());
            assertTrue(line.contains("u9") && line.contains("203.0.113.4"));
            assertTrue(line.contains("truncated"));
        }
        assertEquals(Exporters.cef(e), Exporters.cef(e), "deterministic");
    }

    @Test
    void cuttingNeverSplitsASurrogatePair() {
        String emoji = new String(Character.toChars(0x1F600));
        String v = "a".repeat(Exporters.MAX_VALUE_CHARS - 1) + emoji + "tail";
        AuditEvent e = new AuditEvent(1, AT, "T", "pdp", Map.of("v", v));
        String line = Exporters.cef(e);
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (Character.isHighSurrogate(c)) {
                assertTrue(i + 1 < line.length() && Character.isLowSurrogate(line.charAt(i + 1)));
            }
        }
    }

    @Test
    void eventSeverityComesFromTheTypeOnly() {
        assertEquals(Severity.CRITICAL, Exporters.eventSeverity(new AuditEvent(1, AT, "BREAK_GLASS_USED", "a", Map.of())));
        assertEquals(Severity.MEDIUM, Exporters.eventSeverity(new AuditEvent(1, AT, "SESSION_REVOKED", "a", Map.of())));
        assertEquals(Severity.MEDIUM, Exporters.eventSeverity(new AuditEvent(1, AT, "SIGNAL_DENY", "a", Map.of())));
        assertEquals(Severity.LOW, Exporters.eventSeverity(
                new AuditEvent(1, AT, "ACCESS_DECISION", "a", Map.of("severity", "CRITICAL"))));
    }
}

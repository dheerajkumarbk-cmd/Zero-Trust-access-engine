package dev.dwarpal.casb;

import dev.dwarpal.edge.EdgeResult;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Text encodings, redaction details, the shape of results, and the remaining detector branches. */
class InspectionAndResultsTest {

    private static EdgeResult granted() {
        return new EdgeResult(EdgeResult.Status.GRANTED, "r-1", EdgeResult.genericMessage(EdgeResult.Status.GRANTED, "r-1"),
                false, Optional.empty(), Optional.empty(), false);
    }

    @Test
    void encodingsAreRecognisedOrRefused() {
        assertEquals(StandardCharsets.UTF_8, Inspection.detect("plain".getBytes(StandardCharsets.UTF_8)));
        assertEquals(StandardCharsets.UTF_8, Inspection.detect(new byte[0]));
        assertEquals(StandardCharsets.UTF_16LE, Inspection.detect(new byte[] {(byte) 0xFF, (byte) 0xFE, 'a', 0}));
        assertEquals(StandardCharsets.UTF_16BE, Inspection.detect(new byte[] {(byte) 0xFE, (byte) 0xFF, 0, 'a'}));
        assertEquals(StandardCharsets.UTF_16LE, Inspection.detect("abcd".getBytes(StandardCharsets.UTF_16LE)));
        assertEquals(StandardCharsets.UTF_16BE, Inspection.detect("abcd".getBytes(StandardCharsets.UTF_16BE)));
        assertNull(Inspection.detect(new byte[] {'a', 'b', 'c', 'd', 'e', 'f', 'g', 0}), "one stray NUL: binary");
        assertNull(Inspection.detect(new byte[] {0, 'a', 'b', 0, 'c', 0, 0, 'd'}), "zeros in no 16-bit pattern");
        assertNull(Inspection.detect(new byte[] {0, 0, 0, 'a', 0, 0, 0, 'b'}), "UTF-32 is not supported, so it is refused");
        // odd-length UTF-16 cannot decode
        assertFalse(Inspection.of(new byte[] {'a', 0, 'b'}).inspectable());
        assertFalse(Inspection.of(new byte[Inspection.MAX_BYTES + 1]).inspectable());
        assertFalse(Inspection.of(new byte[] {(byte) 0xC3, 0x28}).inspectable(), "invalid UTF-8");
        assertEquals(Optional.empty(), Inspection.of(new byte[] {(byte) 0xC3, 0x28}).redacted());
        assertEquals(Optional.empty(), Inspection.of(new byte[] {(byte) 0xC3, 0x28}).redactedBytes());
    }

    @Test
    void redactionJoinsOverlapsAndKeepsTheRest() {
        // a PAN glued to an e-mail address: two overlapping findings become one redaction
        Inspection i = Inspection.of("mail ABCPD1234E@corp.example now".getBytes(StandardCharsets.UTF_8));
        assertEquals(2, i.findings().size());
        assertEquals("mail [REDACTED:PAN] now", i.redacted().orElseThrow());
        assertFalse(i.truncated());
        assertTrue(i.toString().contains("inspectable=true"));
        assertFalse(i.toString().contains("corp"));
        Inspection clean = Inspection.of("nothing to see".getBytes(StandardCharsets.UTF_8));
        assertEquals("nothing to see", clean.redacted().orElseThrow());
        assertArrayEquals("nothing to see".getBytes(StandardCharsets.UTF_8), clean.redactedBytes().orElseThrow());
        assertTrue(Inspection.of(new byte[0]).findings().isEmpty());
    }

    @Test
    void resultsHoldTogether() {
        assertThrows(IllegalArgumentException.class,
                () -> new GuardResult(GuardResult.Verdict.REDACTED, GuardResult.Reason.NONE, granted(), List.of(), null));
        assertThrows(IllegalArgumentException.class,
                () -> new GuardResult(GuardResult.Verdict.ALLOWED, GuardResult.Reason.NONE, granted(), List.of(), new byte[1]));
        GuardResult allowed = new GuardResult(GuardResult.Verdict.ALLOWED, GuardResult.Reason.NONE, granted(), List.of(), null);
        GuardResult same = new GuardResult(GuardResult.Verdict.ALLOWED, GuardResult.Reason.NONE, granted(), List.of(), null);
        GuardResult refused = new GuardResult(GuardResult.Verdict.REFUSED, GuardResult.Reason.ENGINE, granted(), List.of(), null);
        GuardResult redacted = new GuardResult(GuardResult.Verdict.REDACTED, GuardResult.Reason.SENSITIVE_DATA, granted(),
                List.of(new Finding(FindingType.PAN, 0, 10)), new byte[] {1, 2});
        assertEquals(allowed, same);
        assertEquals(allowed.hashCode(), same.hashCode());
        assertFalse(allowed.equals(refused));
        assertFalse(allowed.equals("text"));
        assertFalse(redacted.equals(new GuardResult(GuardResult.Verdict.REDACTED, GuardResult.Reason.SENSITIVE_DATA, granted(),
                List.of(new Finding(FindingType.PAN, 0, 10)), new byte[] {1, 3})));
        assertEquals(Optional.empty(), allowed.content());
        assertTrue(allowed.userMessage().startsWith("Access granted"));
        assertTrue(refused.userMessage().contains("r-1"));
        assertTrue(allowed.allowed() && redacted.allowed() && !refused.allowed());
        assertArrayEquals(new byte[] {9}, allowed.forward(new byte[] {9}).orElseThrow());
        assertArrayEquals(new byte[] {1, 2}, redacted.forward(new byte[] {9}).orElseThrow());
        assertEquals(Optional.empty(), refused.forward(new byte[] {9}));
        // the copies handed out cannot change the result
        redacted.content().orElseThrow()[0] = 99;
        assertArrayEquals(new byte[] {1, 2}, redacted.content().orElseThrow());
        assertTrue(redacted.toString().contains("<redacted, 2 bytes>"));
    }

    @Test
    void dlpPolicyDefaultsAndOverrides() {
        DlpPolicy d = DlpPolicy.defaults();
        assertEquals(DlpAction.BLOCK, d.action(FindingType.CARD_NUMBER, dev.dwarpal.domain.DataClassification.PUBLIC));
        assertEquals(DlpAction.REDACT, d.action(FindingType.PAN, dev.dwarpal.domain.DataClassification.CONFIDENTIAL));
        assertEquals(DlpAction.AUDIT, d.action(FindingType.AADHAAR, dev.dwarpal.domain.DataClassification.RESTRICTED));
        assertEquals(DlpAction.BLOCK, d.action(FindingType.PRIVATE_KEY, dev.dwarpal.domain.DataClassification.RESTRICTED));
        assertEquals(DlpAction.AUDIT, d.action(FindingType.EMAIL, dev.dwarpal.domain.DataClassification.PUBLIC));
        assertEquals(DlpAction.BLOCK, d.uninspectable(dev.dwarpal.domain.DataClassification.INTERNAL));
        assertEquals(DlpAction.BLOCK, DlpAction.AUDIT.stricter(DlpAction.BLOCK));
        assertEquals(DlpAction.REDACT, DlpAction.REDACT.stricter(DlpAction.AUDIT));
    }

    // ---- detector branches --------------------------------------------------------------------------

    private static List<FindingType> types(String text) {
        return DetectorsTest.types(text);
    }

    @Test
    void privateKeyBlocksWithAndWithoutAnEndLine() {
        String begin = "-----BEGIN " + "RSA PRIVATE KEY-----";
        String end = "-----END " + "RSA PRIVATE KEY-----";
        String crlf = "x\r\n" + begin + "\r\nAAAA\r\n" + end + "\r\ny";
        Finding f = Detectors.scan(crlf).get(0);
        assertEquals(FindingType.PRIVATE_KEY, f.type());
        assertEquals(crlf.indexOf(end) + end.length(), f.end());
        // far END marker: only the BEGIN line counts, not 100 KB of unrelated text
        String far = begin + "\n" + "a".repeat(70_000) + "\n" + end;
        assertEquals(begin.length(), Detectors.scan(far).get(0).end());
        // two blocks
        assertEquals(2, Detectors.scan(begin + "\nA\n" + end + "\n" + begin + "\nB\n" + end).size());
        // a marker with no newline at all
        assertEquals(List.of(FindingType.PRIVATE_KEY), types("BEGIN " + "PRIVATE KEY"));
        assertEquals(List.of(), types("BEGIN PRIVATE"));
        assertEquals(List.of(), types("BEGIN "));
    }

    @Test
    void tokensAtTheEdges() {
        assertEquals(List.of(), types("gh" + "p_"));
        assertEquals(List.of(), types("gh"));
        assertEquals(List.of(), types("github" + "_pat_short"));
        assertEquals(List.of(FindingType.GITHUB_TOKEN, FindingType.GITHUB_TOKEN),
                types("gh" + "o_" + "b".repeat(36) + " gh" + "s_" + "C9".repeat(18)));
        assertEquals(List.of(), types("xo" + "x"));
        assertEquals(List.of(), types("xo" + "xb"));
        assertEquals(List.of(FindingType.SLACK_TOKEN), types("xo" + "xp-" + "12-34-56-78-90"));
        assertEquals(List.of(), types("AK" + "IA"));
        assertEquals(List.of(), types("AK" + "IA" + "ABCDEFGHIJKLMNO"));
    }

    @Test
    void wordsAndEmailsAtTheEdges() {
        assertEquals(List.of(FindingType.PAN), types("ABCPD\u200b1234E"));
        assertEquals(List.of(FindingType.IFSC), types("SBIN\u200b0001234"));
        assertEquals(List.of(), types("ABCPD1234"));
        assertEquals(List.of(), types("ABCPD1234E1"));
        assertEquals(List.of(), types("A".repeat(40)));
        assertEquals(List.of(), types("ABCPD1234"));
        assertEquals(List.of(), types("ABC1D1234E"));
        assertEquals(List.of(), types("ABCPDX234E"));
        assertEquals(List.of(), types("SBIN0ABCDEF"));
        assertEquals(List.of(), types("SB1N0001234"));
        assertEquals(List.of(FindingType.EMAIL), types("<a.b@c-d.example>"));
        assertEquals(List.of(), types("a@b.c-"));
        assertEquals(List.of(), types("a@b.-xy"));
        assertEquals(List.of(), types("a@bcd"));
        assertEquals(List.of(), types("x@@y"));
        assertEquals(List.of(FindingType.EMAIL), types("@@a@b.example"));
        assertEquals(List.of(FindingType.EMAIL), types("a" + "b".repeat(100) + "@c.example"));
    }

    @Test
    void numbersAtTheEdges() {
        assertEquals(List.of(), types("4111111111111111111111111"), "25 digits");
        assertEquals(List.of(), types("4111-"));
        assertEquals(List.of(), types("4111 abc"));
        assertEquals(List.of(FindingType.CARD_NUMBER), types("(4111 1111 1111 1111)"));
        assertEquals(List.of(FindingType.CARD_NUMBER, FindingType.CARD_NUMBER), types("4111111111111111, 4111111111111111"));
        assertEquals(List.of(), types("0000000000000000"));
        assertEquals(List.of(), types("5555555555555555"));
        assertEquals(List.of(FindingType.CARD_NUMBER), types("5555555555554444"));
        assertEquals(List.of(FindingType.CARD_NUMBER), types("3782 822463 10005"));
    }
}

package dev.dwarpal.casb;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.edge.ClientProofs;
import dev.dwarpal.edge.EdgeFixtures;
import dev.dwarpal.edge.EdgeGrant;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Red-team pass on the CASB. Each r-test is a probe that was first run against the unfixed code and
 * failed (the breach worked); the fix then made it pass, and it stays as a regression test. The
 * "held" tests are attacks that never worked.
 */
class CasbRedTeamTest {

    private final EdgeFixtures.World w = EdgeFixtures.world();
    private final KeyPair key = Ed25519.generateKeyPair();
    private final DataGuard guard = new DataGuard(w.authority, id -> w.directory.resource(id).map(Resource::classification),
            DlpPolicy.defaults(), w.audit, w.clock);

    private EdgeGrant session() {
        EdgeResult r = w.open(key, w.request().resource("drive").build());
        assertEquals(EdgeResult.Status.OPENED, r.status());
        return r.grant().orElseThrow();
    }

    private GuardResult upload(byte[] content) {
        EdgeGrant grant = session();
        EdgeRequest r = w.request().resource("drive").action(Action.WRITE).build();
        return guard.upload(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), r, w.clock.now()), r, content);
    }

    private GuardResult upload(String text) {
        return upload(text.getBytes(StandardCharsets.UTF_8));
    }

    // R5 ----------------------------------------------------------------------------------------

    @Test
    void r5_aFloodOfHarmlessFindingsCannotPushASecretOutOfTheReport() {
        String flood = "a@b.example ".repeat(Detectors.MAX_PER_TYPE + 500);
        GuardResult r = upload(flood + DetectorsTest.awsKey());
        assertEquals(GuardResult.Verdict.REFUSED, r.verdict(), "the key at the end must still be found");
        assertTrue(r.findings().stream().anyMatch(f -> f.type() == FindingType.AWS_ACCESS_KEY));
        assertTrue(Detectors.scan(flood + DetectorsTest.awsKey()).size() <= FindingType.values().length * Detectors.MAX_PER_TYPE);
    }

    @Test
    void r5_redactionNeverLeavesFindingsBehindWhenTheReportIsFull() {
        DlpPolicy redact = DlpPolicy.builder().action(FindingType.EMAIL, DataClassification.INTERNAL, DlpAction.REDACT).build();
        DataGuard g = new DataGuard(w.authority, id -> w.directory.resource(id).map(Resource::classification), redact, w.audit, w.clock);
        EdgeGrant grant = session();
        EdgeRequest small = w.request().resource("drive").action(Action.WRITE).build();
        GuardResult ok = g.upload(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), small, w.clock.now()), small,
                "a@b.example".getBytes(StandardCharsets.UTF_8));
        assertEquals(GuardResult.Verdict.REDACTED, ok.verdict());
        EdgeRequest big = w.request().resource("drive").action(Action.WRITE).build();
        byte[] many = "a@b.example ".repeat(Detectors.MAX_PER_TYPE + 10).getBytes(StandardCharsets.UTF_8);
        GuardResult r = g.upload(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), big, w.clock.now()), big, many);
        assertEquals(GuardResult.Verdict.REFUSED, r.verdict(), "a partly redacted file would leak the rest");
        assertEquals(GuardResult.Reason.SENSITIVE_DATA, r.reason());
    }

    // R6 ----------------------------------------------------------------------------------------

    @Test
    void r6_textInUtf16IsInspectedLikeAnyOtherText() {
        String text = "card " + DetectorsTest.CARD + " end";
        for (java.nio.charset.Charset cs : List.of(StandardCharsets.UTF_16LE, StandardCharsets.UTF_16BE)) {
            GuardResult r = upload(text.getBytes(cs));
            assertEquals(GuardResult.Verdict.REFUSED, r.verdict(), cs + " without a byte order mark");
            assertEquals(List.of(FindingType.CARD_NUMBER), r.findings().stream().map(Finding::type).toList(), cs.name());
        }
        byte[] withBom = ("\ufeff" + text).getBytes(StandardCharsets.UTF_16LE);
        assertEquals(GuardResult.Verdict.REFUSED, upload(withBom).verdict(), "UTF-16LE with a byte order mark");
        byte[] bomBe = ("\ufeff" + text).getBytes(StandardCharsets.UTF_16BE);
        assertEquals(GuardResult.Verdict.REFUSED, upload(bomBe).verdict(), "UTF-16BE with a byte order mark");
        // clean UTF-16 text passes, binary with stray NUL bytes does not
        assertEquals(GuardResult.Verdict.ALLOWED, upload("hello world, nothing here".getBytes(StandardCharsets.UTF_16LE)).verdict());
        assertEquals(GuardResult.Reason.UNINSPECTABLE, upload(new byte[] {'a', 0, 'b', 'c', 'd', 'e', 'f', 'g', 'h'}).reason());
    }

    @Test
    void r6_redactedUtf16StaysUtf16() {
        DlpPolicy redact = DlpPolicy.builder().action(FindingType.CARD_NUMBER, DataClassification.INTERNAL, DlpAction.REDACT).build();
        DataGuard g = new DataGuard(w.authority, id -> w.directory.resource(id).map(Resource::classification), redact, w.audit, w.clock);
        EdgeGrant grant = session();
        EdgeRequest r = w.request().resource("drive").action(Action.WRITE).build();
        GuardResult res = g.upload(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), r, w.clock.now()), r,
                ("pay " + DetectorsTest.CARD).getBytes(StandardCharsets.UTF_16LE));
        assertEquals(GuardResult.Verdict.REDACTED, res.verdict());
        assertArrayEquals("pay [REDACTED:CARD_NUMBER]".getBytes(StandardCharsets.UTF_16LE), res.content().orElseThrow());
    }

    // R7 ----------------------------------------------------------------------------------------

    @Test
    void r7_invisibleSeparatorsAndOtherDigitsDoNotHideANumber() {
        String c = DetectorsTest.CARD;
        List<String> disguised = List.of(
                c.substring(0, 4) + "\u200b" + c.substring(4, 8) + "\u200b" + c.substring(8, 12) + "\u200b" + c.substring(12),
                c.substring(0, 4) + "\u00a0" + c.substring(4, 8) + "\u00a0" + c.substring(8, 12) + "\u00a0" + c.substring(12),
                c.substring(0, 4) + "\u2009" + c.substring(4, 8) + "\u2009" + c.substring(8, 12) + "\u2009" + c.substring(12),
                c.substring(0, 4) + "\u00ad" + c.substring(4, 8) + "\u00ad" + c.substring(8, 12) + "\u00ad" + c.substring(12),
                c.replace('4', '\uff14').replace('1', '\uff11'),
                c.replace('1', '\u0661'));
        for (String d : disguised) {
            assertEquals(List.of(FindingType.CARD_NUMBER), Detectors.scan("x " + d + " y").stream().map(Finding::type).toList(),
                    d.codePoints().mapToObj(Integer::toHexString).toList().toString());
        }
        String a = DetectorsTest.AADHAAR;
        assertEquals(List.of(FindingType.AADHAAR), Detectors.scan(a.substring(0, 4) + "\u200b" + a.substring(4)).stream().map(Finding::type).toList());
    }

    @Test
    void r7_theRedactedSpanCoversTheWholeDisguisedNumber() {
        String c = DetectorsTest.CARD;
        String disguised = c.substring(0, 8) + "\u200b" + c.substring(8);
        Inspection i = Inspection.of(("pay " + disguised + " now").getBytes(StandardCharsets.UTF_8));
        assertEquals("pay [REDACTED:CARD_NUMBER] now", i.redacted().orElseThrow());
    }

    // R8 ----------------------------------------------------------------------------------------

    @Test
    @Timeout(60)
    void r8_manyKeyMarkersWithoutAnEndMarkerScanInLinearTime() {
        String marker = "-----BEGIN " + "PRIVATE KEY-----\n";
        String text = marker.repeat(2_000_000 / marker.length());
        long start = System.nanoTime();
        List<Finding> found = Detectors.scan(text);
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertTrue(found.stream().allMatch(f -> f.type() == FindingType.PRIVATE_KEY));
        assertFalse(found.isEmpty());
        assertTrue(ms < 2000, "scanning 2 MB took " + ms + " ms: quadratic behaviour");
    }

    // R9 ----------------------------------------------------------------------------------------

    @Test
    void r9_aCallerHasOneSafeWayToGetTheBytesToForward() {
        byte[] original = "keep me: nothing sensitive".getBytes(StandardCharsets.UTF_8);
        GuardResult clean = upload(original);
        assertArrayEquals(original, clean.forward(original).orElseThrow());
        GuardResult blocked = upload(DetectorsTest.CARD);
        assertTrue(blocked.forward(original).isEmpty(), "nothing goes on after a refusal");

        DlpPolicy redact = DlpPolicy.builder().action(FindingType.CARD_NUMBER, DataClassification.INTERNAL, DlpAction.REDACT).build();
        DataGuard g = new DataGuard(w.authority, id -> w.directory.resource(id).map(Resource::classification), redact, w.audit, w.clock);
        EdgeGrant grant = session();
        EdgeRequest r = w.request().resource("drive").action(Action.WRITE).build();
        byte[] sensitive = ("pay " + DetectorsTest.CARD).getBytes(StandardCharsets.UTF_8);
        GuardResult res = g.upload(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), r, w.clock.now()), r, sensitive);
        assertArrayEquals("pay [REDACTED:CARD_NUMBER]".getBytes(StandardCharsets.UTF_8), res.forward(sensitive).orElseThrow(),
                "forward() hands back the redacted bytes, never the original");
    }

    // held: attacks that did not work -----------------------------------------------------------

    @Test
    void held_aStolenTokenFromAnotherDeviceEndsTheSessionAndInspectsNothing() {
        EdgeGrant grant = session();
        EdgeRequest r = w.request().resource("drive").action(Action.WRITE).device("phone-thief").build();
        GuardResult res = guard.upload(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), r, w.clock.now()), r,
                "harmless".getBytes(StandardCharsets.UTF_8));
        assertEquals(GuardResult.Verdict.REFUSED, res.verdict());
        assertTrue(res.result().sessionEnded(), "token presented from another device: the session is revoked");
        EdgeRequest again = w.request().resource("drive").action(Action.READ).build();
        assertEquals(GuardResult.Verdict.REFUSED, guard.access(grant.token(),
                ClientProofs.sign(key.getPrivate(), grant.sessionId(), again, w.clock.now()), again).verdict());
    }

    @Test
    void held_theClientCannotClaimAClassificationOrManagedDevice() {
        // a DataGuard asks the directory for the classification; the request has no field to lie in
        GuardResult r = upload("pay " + DetectorsTest.CARD);
        assertEquals(GuardResult.Reason.SENSITIVE_DATA, r.reason());
        assertEquals(1L, w.sink.snapshot().stream().filter(x -> x.type().equals(DataGuard.AUDIT_TYPE)).count());
    }

    @Test
    void held_splittingASecretAcrossLinesOrWordsGivesNoFalseAlarmsOnOrdinaryNumbers() {
        // a column of order numbers one per line is not one long number
        String column = "4111\n1111\n1111\n1111\n";
        assertEquals(List.of(), Detectors.scan(column));
        // timestamps, phone numbers and dates in text
        assertEquals(List.of(), Detectors.scan("2026-11-04 12:30:45, +91 98765 43210, 10.0.0.1, 192.168.100.200"));
    }
}

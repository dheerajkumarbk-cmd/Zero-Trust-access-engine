package dev.dwarpal.casb;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.edge.ClientProofs;
import dev.dwarpal.edge.EdgeFixtures;
import dev.dwarpal.edge.EdgeGrant;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.SessionAuthority;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The CASB data guard against the shared Dwarpal world: real sessions, real engine, real audit chain. */
class DataGuardTest {

    private final EdgeFixtures.World w = EdgeFixtures.world();
    private final KeyPair key = Ed25519.generateKeyPair();
    /** Who the follow-up requests come from; Alice on her laptop unless a test says otherwise. */
    private java.util.function.UnaryOperator<EdgeFixtures.RequestBuilder> who = b -> b;

    private DataGuard guard(DlpPolicy policy) {
        return new DataGuard(w.authority, id -> w.directory.resource(id).map(Resource::classification), policy, w.audit,
                w.clock);
    }

    private DataGuard guard() {
        return guard(DlpPolicy.defaults());
    }

    private EdgeGrant session(EdgeFixtures.RequestBuilder login) {
        EdgeResult r = w.open(key, login.build());
        assertEquals(EdgeResult.Status.OPENED, r.status());
        return r.grant().orElseThrow();
    }

    private EdgeGrant aliceSession() {
        return session(w.request().resource("drive"));
    }

    private GuardResult upload(DataGuard g, EdgeGrant grant, String text) {
        EdgeRequest r = who.apply(w.request()).resource("drive").action(Action.WRITE).build();
        return g.upload(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), r, w.clock.now()), r,
                text.getBytes(StandardCharsets.UTF_8));
    }

    private GuardResult access(DataGuard g, EdgeGrant grant, Action action) {
        EdgeRequest r = who.apply(w.request()).resource("drive").action(action).build();
        return g.access(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), r, w.clock.now()), r);
    }

    private List<AuditRecord> dlpRecords() {
        return w.sink.snapshot().stream().filter(r -> r.type().equals(DataGuard.AUDIT_TYPE)).toList();
    }

    // ---- uploads ---------------------------------------------------------------------------------

    @Test
    void cleanUploadsGoThrough() {
        GuardResult r = upload(guard(), aliceSession(), "quarterly notes, nothing sensitive, call 555 0100");
        assertEquals(GuardResult.Verdict.ALLOWED, r.verdict());
        assertTrue(r.allowed());
        assertEquals(List.of(), r.findings());
        assertEquals(0, dlpRecords().size(), "nothing found, nothing to record");
    }

    @Test
    void uploadWithAValidCardNumberIsBlocked() {
        GuardResult r = upload(guard(), aliceSession(), "invoice paid with card " + DetectorsTest.CARD + " thanks");
        assertEquals(GuardResult.Verdict.REFUSED, r.verdict());
        assertEquals(GuardResult.Reason.SENSITIVE_DATA, r.reason());
        assertFalse(r.allowed());
        assertEquals(List.of(FindingType.CARD_NUMBER), r.findings().stream().map(Finding::type).toList());
        assertTrue(r.userMessage().contains(r.reference()));
        assertFalse(r.userMessage().contains("card"), "the user is not told what was found");
        assertFalse(r.toString().contains("4111"));
        assertEquals(1, dlpRecords().size(), "the block is audited");
    }

    @Test
    void sixteenDigitNumberFailingLuhnIsAllowed() {
        GuardResult r = upload(guard(), aliceSession(), "order number 4111111111111112 shipped");
        assertEquals(GuardResult.Verdict.ALLOWED, r.verdict());
        assertEquals(List.of(), r.findings());
    }

    @Test
    void aadhaarWithValidChecksumIsBlockedAndInvalidIsAllowed() {
        EdgeGrant grant = aliceSession();
        assertEquals(GuardResult.Verdict.REFUSED, upload(guard(), grant, "uid " + DetectorsTest.AADHAAR).verdict());
        String wrong = DetectorsTest.AADHAAR.substring(0, 11) + (char) ('0' + (DetectorsTest.AADHAAR.charAt(11) - '0' + 3) % 10);
        assertEquals(GuardResult.Verdict.ALLOWED, upload(guard(), grant, "uid " + wrong).verdict());
    }

    @Test
    void secretsAreAlwaysBlocked() {
        EdgeGrant grant = aliceSession();
        assertEquals(GuardResult.Verdict.REFUSED, upload(guard(), grant, DetectorsTest.privateKeyBlock()).verdict());
        assertEquals(GuardResult.Verdict.REFUSED, upload(guard(), grant, "k=" + DetectorsTest.awsKey()).verdict());
    }

    @Test
    void auditOnlyFindingsPassAndAreRecordedWithoutValues() {
        GuardResult r = upload(guard(), aliceSession(), "contact priya@corp.example for branch SBIN0001234");
        assertEquals(GuardResult.Verdict.ALLOWED, r.verdict());
        assertEquals(2, r.findings().size());
        AuditRecord rec = dlpRecords().get(0);
        assertTrue(rec.payloadJson().contains("EMAIL"));
        assertTrue(rec.payloadJson().contains("IFSC"));
        assertTrue(rec.payloadJson().contains("\"action\":\"AUDIT\""));
        assertFalse(rec.payloadJson().contains("priya"), "values never reach the audit trail");
        assertFalse(rec.payloadJson().contains("SBIN"));
        assertEquals("alice", rec.actor());
    }

    @Test
    void redactionRemovesTheValueAndKeepsTheRest() {
        DlpPolicy redact = DlpPolicy.builder().action(FindingType.CARD_NUMBER, DataClassification.INTERNAL, DlpAction.REDACT).build();
        GuardResult r = upload(guard(redact), aliceSession(), "pay " + DetectorsTest.CARD + " now, mail a@b.example");
        assertEquals(GuardResult.Verdict.REDACTED, r.verdict());
        assertTrue(r.allowed());
        String out = new String(r.content().orElseThrow(), StandardCharsets.UTF_8);
        assertEquals("pay [REDACTED:CARD_NUMBER] now, mail [REDACTED:EMAIL]", out);
        assertFalse(r.toString().contains("REDACTED:CARD"), "toString shows no content");
        assertTrue(r.toString().contains("<redacted"));
        assertEquals(1, dlpRecords().size());
        assertArrayEquals(r.content().orElseThrow(), r.content().orElseThrow());
        assertEquals(r, r);
        assertEquals(r.hashCode(), r.hashCode());
    }

    @Test
    void strictestActionAmongFindingsWins() {
        DlpPolicy redact = DlpPolicy.builder().action(FindingType.CARD_NUMBER, DataClassification.INTERNAL, DlpAction.REDACT).build();
        GuardResult r = upload(guard(redact), aliceSession(), DetectorsTest.CARD + " " + DetectorsTest.awsKey());
        assertEquals(GuardResult.Verdict.REFUSED, r.verdict(), "a secret in the same file blocks the whole upload");
    }

    @Test
    void contentThatCannotBeReadIsRefusedByDefault() {
        EdgeGrant grant = aliceSession();
        EdgeRequest r = w.request().resource("drive").action(Action.WRITE).build();
        byte[] binary = {(byte) 0xFF, (byte) 0xFE, 0, 1, 2};
        GuardResult g = guard().upload(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), r, w.clock.now()), r, binary);
        assertEquals(GuardResult.Verdict.REFUSED, g.verdict());
        assertEquals(GuardResult.Reason.UNINSPECTABLE, g.reason());
        // an operator can choose to let it through with an audit record
        DlpPolicy lenient = DlpPolicy.builder().uninspectable(DataClassification.INTERNAL, DlpAction.AUDIT).build();
        EdgeRequest r2 = w.request().resource("drive").action(Action.WRITE).build();
        GuardResult g2 = guard(lenient).upload(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), r2, w.clock.now()), r2, binary);
        assertEquals(GuardResult.Verdict.ALLOWED, g2.verdict());
        assertTrue(dlpRecords().stream().anyMatch(x -> x.payloadJson().contains("\"inspectable\":\"false\"")));
        assertThrows(IllegalArgumentException.class, () -> DlpPolicy.builder().uninspectable(DataClassification.INTERNAL, DlpAction.REDACT));
    }

    @Test
    void oversizedUploadsAreRefusedNotSkipped() {
        EdgeGrant grant = aliceSession();
        EdgeRequest r = w.request().resource("drive").action(Action.WRITE).build();
        byte[] huge = new byte[Inspection.MAX_BYTES + 1];
        java.util.Arrays.fill(huge, (byte) 'a');
        GuardResult g = guard().upload(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), r, w.clock.now()), r, huge);
        assertEquals(GuardResult.Reason.UNINSPECTABLE, g.reason());
        assertFalse(g.allowed());
    }

    @Test
    void anUploadThatCannotBeAuditedIsRefused() {
        AuditLog broken;
        try {
            broken = new AuditLog(KeyGenerator.getInstance("HmacSHA256").generateKey(), rec -> {
                throw new IllegalStateException("disk full");
            });
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        DataGuard g = new DataGuard(w.authority, id -> Optional.of(DataClassification.INTERNAL), DlpPolicy.defaults(), broken, w.clock);
        EdgeGrant grant = aliceSession();
        EdgeRequest r = w.request().resource("drive").action(Action.WRITE).build();
        GuardResult res = g.upload(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), r, w.clock.now()), r,
                "mail me at a@b.example".getBytes(StandardCharsets.UTF_8));
        assertEquals(GuardResult.Verdict.REFUSED, res.verdict());
        assertEquals(GuardResult.Reason.AUDIT_UNAVAILABLE, res.reason());
        // blocking needs no record to be safe
        EdgeRequest r2 = w.request().resource("drive").action(Action.WRITE).build();
        GuardResult blocked = g.upload(grant.token(), ClientProofs.sign(key.getPrivate(), grant.sessionId(), r2, w.clock.now()), r2,
                DetectorsTest.CARD.getBytes(StandardCharsets.UTF_8));
        assertEquals(GuardResult.Reason.SENSITIVE_DATA, blocked.reason());
    }

    @Test
    void unknownResourcesAreRefused() {
        DataGuard g = new DataGuard(w.authority, id -> Optional.empty(), DlpPolicy.defaults(), w.audit, w.clock);
        assertEquals(GuardResult.Reason.UNKNOWN_RESOURCE, upload(g, aliceSession(), "hello").reason());
        DataGuard nul = new DataGuard(w.authority, id -> null, DlpPolicy.defaults(), w.audit, w.clock);
        assertEquals(GuardResult.Reason.UNKNOWN_RESOURCE, upload(nul, aliceSession(), "hello").reason());
    }

    @Test
    void refusalAuditsAreThrottled() {
        EdgeGrant grant = aliceSession();
        DataGuard g = guard();
        for (int i = 0; i < 60; i++) {
            assertEquals(GuardResult.Verdict.REFUSED, upload(g, grant, DetectorsTest.CARD).verdict());
        }
        assertEquals(20, dlpRecords().size(), "a flood of blocked uploads cannot flood the audit trail");
    }

    // ---- sessions, actions and read-only ---------------------------------------------------------

    @Test
    void readAndDownloadGoThroughTheEngine() {
        EdgeGrant grant = aliceSession();
        assertEquals(GuardResult.Verdict.ALLOWED, access(guard(), grant, Action.READ).verdict());
        assertEquals(GuardResult.Verdict.ALLOWED, access(guard(), grant, Action.DOWNLOAD).verdict());
    }

    @Test
    void wrongActionsForTheCallAreRefused() {
        EdgeGrant grant = aliceSession();
        assertEquals(GuardResult.Reason.WRONG_ACTION, access(guard(), grant, Action.WRITE).reason());
        assertEquals(GuardResult.Reason.WRONG_ACTION, access(guard(), grant, Action.ADMIN).reason());
        EdgeRequest r = w.request().resource("drive").action(Action.READ).build();
        assertEquals(GuardResult.Reason.WRONG_ACTION, guard().upload(grant.token(),
                ClientProofs.sign(key.getPrivate(), grant.sessionId(), r, w.clock.now()), r, new byte[0]).reason());
    }

    @Test
    void readOnlySessionCannotDownloadOrUpload() {
        who = b -> b.subject("carol").device("phone-carol");
        EdgeGrant grant = session(who.apply(w.request()).resource("drive"));
        assertTrue(grant.restricted(), "unmanaged device: P-21 makes SaaS data read-only");
        GuardResult read = access(guard(), grant, Action.READ);
        assertEquals(GuardResult.Verdict.ALLOWED, read.verdict(), read + " " + read.result());
        GuardResult dl = access(guard(), grant, Action.DOWNLOAD);
        assertEquals(GuardResult.Verdict.REFUSED, dl.verdict());
        GuardResult up = upload(guard(), grant, "harmless text");
        assertEquals(GuardResult.Verdict.REFUSED, up.verdict());
    }

    @Test
    void readOnlyIsRememberedEvenIfALaterAnswerSaysGranted() {
        List<EdgeResult.Status> answers = new ArrayList<>(List.of(EdgeResult.Status.GRANTED_LIMITED, EdgeResult.Status.GRANTED));
        SessionAuthority forgetful = stub(() -> answers.isEmpty() ? EdgeResult.Status.GRANTED : answers.remove(0), false);
        DataGuard g = new DataGuard(forgetful, id -> Optional.of(DataClassification.INTERNAL), DlpPolicy.defaults(), w.audit, w.clock);
        EdgeRequest read = w.request().resource("drive").action(Action.READ).build();
        SignatureProof proof = new SignatureProof("sess-1", Instant.EPOCH, "AAAA");
        assertEquals(GuardResult.Verdict.ALLOWED, g.access("t", proof, read).verdict());
        EdgeRequest dl = w.request().resource("drive").action(Action.DOWNLOAD).build();
        GuardResult r = g.access("t", proof, dl);
        assertEquals(GuardResult.Reason.READ_ONLY, r.reason(), "a session that was read-only stays read-only");
        // another session is not affected
        assertEquals(GuardResult.Verdict.ALLOWED, g.access("t", new SignatureProof("sess-2", Instant.EPOCH, "AAAA"), dl).verdict());
    }

    @Test
    void stepUpAndEveryRefusalFromTheEngineStopTheRequest() {
        EdgeRequest read = w.request().resource("drive").action(Action.READ).build();
        SignatureProof proof = new SignatureProof("sess-1", Instant.EPOCH, "AAAA");
        DataGuard stepUp = new DataGuard(stub(() -> EdgeResult.Status.STEP_UP, false), id -> Optional.of(DataClassification.INTERNAL),
                DlpPolicy.defaults(), w.audit, w.clock);
        GuardResult s = stepUp.access("t", proof, read);
        assertEquals(GuardResult.Verdict.STEP_UP, s.verdict());
        assertTrue(s.result().challenge().isPresent());
        assertFalse(s.allowed());
        for (EdgeResult.Status st : List.of(EdgeResult.Status.DENIED, EdgeResult.Status.REJECTED, EdgeResult.Status.OPENED)) {
            DataGuard g = new DataGuard(stub(() -> st, false), id -> Optional.of(DataClassification.INTERNAL), DlpPolicy.defaults(),
                    w.audit, w.clock);
            assertEquals(GuardResult.Verdict.REFUSED, g.access("t", proof, read).verdict(), st.name());
        }
    }

    @Test
    void aFailingOrSilentAuthorityIsARefusal() {
        EdgeRequest read = w.request().resource("drive").action(Action.READ).build();
        SignatureProof proof = new SignatureProof("sess-1", Instant.EPOCH, "AAAA");
        DataGuard throwing = new DataGuard(stub(null, true), id -> Optional.of(DataClassification.INTERNAL), DlpPolicy.defaults(),
                w.audit, w.clock);
        assertEquals(GuardResult.Reason.ENGINE, throwing.access("t", proof, read).reason());
        DataGuard silent = new DataGuard(stub(null, false), id -> Optional.of(DataClassification.INTERNAL), DlpPolicy.defaults(),
                w.audit, w.clock);
        assertEquals(GuardResult.Reason.ENGINE, silent.access("t", proof, read).reason());
    }

    @Test
    void stolenTokensAndForgedProofsDoNotGetPastTheEngine() {
        EdgeGrant grant = aliceSession();
        KeyPair thief = Ed25519.generateKeyPair();
        EdgeRequest r = w.request().resource("drive").action(Action.READ).build();
        GuardResult res = guard().access(grant.token(), ClientProofs.sign(thief.getPrivate(), grant.sessionId(), r, w.clock.now()), r);
        assertEquals(GuardResult.Verdict.REFUSED, res.verdict());
        // replaying the same request is refused too
        EdgeRequest again = w.request().resource("drive").action(Action.READ).build();
        SignatureProof good = ClientProofs.sign(key.getPrivate(), grant.sessionId(), again, w.clock.now());
        assertEquals(GuardResult.Verdict.ALLOWED, guard().access(grant.token(), good, again).verdict());
        assertEquals(GuardResult.Verdict.REFUSED, guard().access(grant.token(), good, again).verdict());
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private interface Answer {
        EdgeResult.Status next();
    }

    /** A session authority whose {@code use} answers as told ({@code null} answer: returns null; {@code explode}: throws). */
    private static SessionAuthority stub(Answer answer, boolean explode) {
        return new SessionAuthority() {
            @Override
            public EdgeResult open(EdgeRequest login, PublicKey sessionKey, Optional<SignatureProof> deviceBinding) {
                throw new UnsupportedOperationException();
            }

            @Override
            public EdgeResult use(String token, SignatureProof proof, EdgeRequest request) {
                if (explode) {
                    throw new IllegalStateException("engine down");
                }
                if (answer == null) {
                    return null;
                }
                EdgeResult.Status s = answer.next();
                return new EdgeResult(s, request.requestId(), EdgeResult.genericMessage(s, request.requestId()),
                        s == EdgeResult.Status.GRANTED_LIMITED,
                        s == EdgeResult.Status.STEP_UP ? Optional.of(dev.dwarpal.domain.AuthMethod.WEBAUTHN) : Optional.empty(),
                        Optional.empty(), false);
            }

            @Override
            public EdgeResult decide(EdgeRequest request) {
                throw new UnsupportedOperationException();
            }
        };
    }
}

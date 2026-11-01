package dev.dwarpal.admin;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.crypto.TrustedKey;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.engine.PolicyEngineTest;
import dev.dwarpal.risk.SignalSnapshot;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Privileged access to the policy plane: four-eyes, key purpose, integrity, rollback, audit. */
class PolicyInstallerTest {

    private static final Instant NOW = Fixtures.T0;
    private static final KeyPair ASHA = Ed25519.generateKeyPair();
    private static final KeyPair ASHA_SPARE = Ed25519.generateKeyPair();
    private static final KeyPair RAVI = Ed25519.generateKeyPair();
    private static final KeyPair DEVICE = Ed25519.generateKeyPair();

    private static final KeyRing ADMIN_KEYS = new KeyRing(List.of(
            key("asha-1", KeyPurpose.POLICY_SIGNER, "asha", ASHA),
            key("asha-2", KeyPurpose.POLICY_SIGNER, "asha", ASHA_SPARE),
            key("ravi-1", KeyPurpose.POLICY_SIGNER, "ravi", RAVI),
            key("agent-x", KeyPurpose.DEVICE_AGENT, "laptop-x", DEVICE)));

    private static final String LOCKDOWN = """
            version: "lockdown-2"
            algorithm: DENY_OVERRIDES
            default: DENY
            policies: []
            """;

    private final SecretKey auditKey = newKey();
    private final InMemoryAuditSink sink = new InMemoryAuditSink();
    private final PolicyInstaller installer = new PolicyInstaller(
            PolicyEngineTest.engine().withDirectory(Fixtures.directoryFor(Fixtures.request().build())),
            1, ADMIN_KEYS, 2, new AuditLog(auditKey, sink), Clock.fixed(NOW, ZoneOffset.UTC));

    private static TrustedKey key(String id, KeyPurpose purpose, String owner, KeyPair kp) {
        return new TrustedKey(id, purpose, owner, kp.getPublic(), NOW.minus(Duration.ofDays(90)), NOW.plus(Duration.ofDays(90)));
    }

    private static SecretKey newKey() {
        try {
            return KeyGenerator.getInstance("HmacSHA256").generateKey();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static SignatureProof approve(KeyPair kp, String keyId, long seq, String yaml, Instant at) {
        return new SignatureProof(keyId, at, Ed25519.sign(kp.getPrivate(), SignedMessages.policyBundle(seq, yaml, at)));
    }

    private static SignatureProof approve(KeyPair kp, String keyId, long seq, String yaml) {
        return approve(kp, keyId, seq, yaml, NOW.minusSeconds(60));
    }

    private Outcome aliceOutcome() {
        return installer.decide(Fixtures.request().build(), SignalSnapshot.empty()).outcome();
    }

    private String lastAuditType() {
        List<AuditRecord> all = sink.snapshot();
        return all.get(all.size() - 1).type();
    }

    @Test
    void twoDistinctAdministratorsCanInstallAndItIsAudited() {
        assertEquals(Outcome.ALLOW, aliceOutcome());
        PolicyInstaller.Result r = installer.install(new PolicyBundle(2, LOCKDOWN,
                List.of(approve(ASHA, "asha-1", 2, LOCKDOWN), approve(RAVI, "ravi-1", 2, LOCKDOWN))), "asha");
        assertTrue(r.installed(), r.reason());
        assertEquals(Outcome.DENY, aliceOutcome(), "new policy is live");
        assertEquals(2, installer.currentSequence());
        assertEquals("POLICY_INSTALLED", lastAuditType());
        assertTrue(sink.snapshot().get(0).payloadJson().contains("[asha, ravi]"));
        assertTrue(AuditLog.verify(sink.snapshot(), auditKey, null).intact());
    }

    @Test
    void oneAdministratorAloneCannotChangePolicyEvenWithTwoKeys() {
        PolicyInstaller.Result r = installer.install(new PolicyBundle(2, LOCKDOWN,
                List.of(approve(ASHA, "asha-1", 2, LOCKDOWN), approve(ASHA_SPARE, "asha-2", 2, LOCKDOWN))), "asha");
        assertFalse(r.installed());
        assertTrue(r.reason().contains("1 distinct valid approver"), r.reason());
        assertEquals(Outcome.ALLOW, aliceOutcome(), "old policy still live");
        assertEquals("POLICY_REJECTED", lastAuditType());
    }

    @Test
    void textEditedAfterApprovalIsRejected() {
        String approved = LOCKDOWN;
        String tampered = LOCKDOWN.replace("default: DENY", "default: PERMIT");
        PolicyInstaller.Result r = installer.install(new PolicyBundle(2, tampered,
                List.of(approve(ASHA, "asha-1", 2, approved), approve(RAVI, "ravi-1", 2, approved))), "mallory");
        assertFalse(r.installed());
        assertEquals("POLICY_REJECTED", lastAuditType());
    }

    @Test
    void rollbackToAnOldButValidlySignedBundleIsRefused() {
        assertTrue(installer.install(new PolicyBundle(2, LOCKDOWN,
                List.of(approve(ASHA, "asha-1", 2, LOCKDOWN), approve(RAVI, "ravi-1", 2, LOCKDOWN))), "asha").installed());
        PolicyInstaller.Result replay = installer.install(new PolicyBundle(2, LOCKDOWN,
                List.of(approve(ASHA, "asha-1", 2, LOCKDOWN), approve(RAVI, "ravi-1", 2, LOCKDOWN))), "asha");
        assertFalse(replay.installed());
        assertTrue(replay.reason().contains("rollback"), replay.reason());
        PolicyInstaller.Result older = installer.install(new PolicyBundle(1, LOCKDOWN,
                List.of(approve(ASHA, "asha-1", 1, LOCKDOWN), approve(RAVI, "ravi-1", 1, LOCKDOWN))), "asha");
        assertFalse(older.installed());
    }

    @Test
    void approvalForOneSequenceCannotBeReusedForAnother() {
        PolicyInstaller.Result r = installer.install(new PolicyBundle(3, LOCKDOWN,
                List.of(approve(ASHA, "asha-1", 2, LOCKDOWN), approve(RAVI, "ravi-1", 2, LOCKDOWN))), "asha");
        assertFalse(r.installed());
    }

    @Test
    void nonAdminKeysAndStaleApprovalsDoNotCount() {
        PolicyInstaller.Result deviceKey = installer.install(new PolicyBundle(2, LOCKDOWN,
                List.of(approve(ASHA, "asha-1", 2, LOCKDOWN), approve(DEVICE, "agent-x", 2, LOCKDOWN))), "asha");
        assertFalse(deviceKey.installed());
        PolicyInstaller.Result stale = installer.install(new PolicyBundle(2, LOCKDOWN,
                List.of(approve(ASHA, "asha-1", 2, LOCKDOWN, NOW.minus(Duration.ofDays(8))),
                        approve(RAVI, "ravi-1", 2, LOCKDOWN))), "asha");
        assertFalse(stale.installed());
    }

    @Test
    void validlyApprovedButUnsafePolicyIsStillRejected() {
        String conflicting = """
                version: "bad-2"
                algorithm: DENY_OVERRIDES
                default: DENY
                policies:
                  - id: A
                    when: {roleIn: [x]}
                    effect: PERMIT
                  - id: B
                    when: {roleIn: [x]}
                    effect: DENY
                """;
        PolicyInstaller.Result r = installer.install(new PolicyBundle(2, conflicting,
                List.of(approve(ASHA, "asha-1", 2, conflicting), approve(RAVI, "ravi-1", 2, conflicting))), "asha");
        assertFalse(r.installed());
        assertTrue(r.reason().contains("policy rejected"), r.reason());
    }

    @Test
    void ifTheInstallCannotBeAuditedNothingIsInstalled() {
        PolicyInstaller blind = new PolicyInstaller(
                PolicyEngineTest.engine().withDirectory(Fixtures.directoryFor(Fixtures.request().build())),
                1, ADMIN_KEYS, 2, new AuditLog(auditKey, rec -> {
                    throw new IllegalStateException("audit store down");
                }), Clock.fixed(NOW, ZoneOffset.UTC));
        assertThrows(IllegalStateException.class, () -> blind.install(new PolicyBundle(2, LOCKDOWN,
                List.of(approve(ASHA, "asha-1", 2, LOCKDOWN), approve(RAVI, "ravi-1", 2, LOCKDOWN))), "asha"));
        assertEquals(1, blind.currentSequence());
        assertEquals(Outcome.ALLOW, blind.decide(Fixtures.request().build(), SignalSnapshot.empty()).outcome());
    }

    @Test
    void constructionAndBundleAreValidated() {
        assertThrows(IllegalArgumentException.class, () -> new PolicyInstaller(installer.currentEngine(), 0, ADMIN_KEYS, 0,
                new AuditLog(auditKey, sink), Clock.systemUTC()));
        assertThrows(IllegalArgumentException.class, () -> new PolicyInstaller(installer.currentEngine(), -1, ADMIN_KEYS, 1,
                new AuditLog(auditKey, sink), Clock.systemUTC()));
        assertThrows(IllegalArgumentException.class, () -> new PolicyBundle(0, LOCKDOWN, List.of()));
        assertThrows(IllegalArgumentException.class, () -> installer.install(new PolicyBundle(2, LOCKDOWN, List.of()), "bad id\n"));
    }
}

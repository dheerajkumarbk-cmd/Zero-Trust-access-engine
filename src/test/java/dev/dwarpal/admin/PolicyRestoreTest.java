package dev.dwarpal.admin;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
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
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The start-only, once-only way a saved policy bundle is put back. */
class PolicyRestoreTest {

    private static final Instant NOW = Fixtures.T0;
    private static final KeyPair ASHA = Ed25519.generateKeyPair();
    private static final KeyPair RAVI = Ed25519.generateKeyPair();
    private static final KeyRing KEYS = new KeyRing(List.of(key("asha-1", "asha", ASHA), key("ravi-1", "ravi", RAVI)));
    private static final String LOCKDOWN = "version: \"lockdown-2\"\nalgorithm: DENY_OVERRIDES\ndefault: DENY\npolicies: []\n";
    private static final String LOCKDOWN_3 = LOCKDOWN.replace("lockdown-2", "lockdown-3");

    private final AtomicBoolean auditDown = new AtomicBoolean();
    private final InMemoryAuditSink sink = new InMemoryAuditSink();
    private final AuditLog audit = new AuditLog(newKey(), rec -> {
        if (auditDown.get()) {
            throw new IllegalStateException("audit store down");
        }
        sink.write(rec);
    });

    private PolicyInstaller installer(long initial) {
        return new PolicyInstaller(PolicyEngineTest.engine().withDirectory(Fixtures.directoryFor(Fixtures.request().build())),
                initial, KEYS, 2, audit, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static TrustedKey key(String id, String owner, KeyPair kp) {
        return new TrustedKey(id, KeyPurpose.POLICY_SIGNER, owner, kp.getPublic(), NOW.minus(Duration.ofDays(90)),
                NOW.plus(Duration.ofDays(90)));
    }

    private static SecretKey newKey() {
        try {
            return KeyGenerator.getInstance("HmacSHA256").generateKey();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static SignatureProof approve(KeyPair kp, String id, long seq, String yaml) {
        return new SignatureProof(id, NOW, Ed25519.sign(kp.getPrivate(), SignedMessages.policyBundle(seq, yaml, NOW)));
    }

    private boolean audited(String type) {
        return sink.snapshot().stream().anyMatch(r -> r.type().equals(type));
    }

    private Outcome outcome(PolicyInstaller i) {
        return i.decide(Fixtures.request().build(), SignalSnapshot.empty()).outcome();
    }

    @Test
    void worksOnceAtStartAndIsAuditedBeforeTakingEffect() {
        PolicyInstaller i = installer(0);
        Outcome before = outcome(i);
        PolicyInstaller.Result r = i.restore(LOCKDOWN, 4, "installed earlier");
        assertTrue(r.installed(), r.reason());
        assertEquals(4, i.currentSequence());
        assertEquals("lockdown-2", i.currentEngine().policySet().version());
        assertEquals(Outcome.DENY, outcome(i));
        assertTrue(before != Outcome.DENY, "the starting policy did not deny");
        assertTrue(audited("POLICY_RESTORED"));
        assertFalse(i.restore(LOCKDOWN_3, 5, "again").installed(), "only once");
        assertEquals(4, i.currentSequence());
    }

    @Test
    void refusedAfterAnInstall() {
        PolicyInstaller i = installer(0);
        assertTrue(i.install(new PolicyBundle(1, LOCKDOWN, List.of(approve(ASHA, "asha-1", 1, LOCKDOWN),
                approve(RAVI, "ravi-1", 1, LOCKDOWN))), "asha").installed());
        assertFalse(i.restore(LOCKDOWN_3, 9, "late").installed());
        assertEquals(1, i.currentSequence());
        assertEquals("lockdown-2", i.currentEngine().policySet().version());
    }

    @Test
    void refusedWhenTheSequenceIsNotHigher() {
        PolicyInstaller i = installer(3);
        assertFalse(i.restore(LOCKDOWN, 3, "same").installed());
        assertFalse(i.restore(LOCKDOWN, 2, "lower").installed());
        assertEquals(3, i.currentSequence());
        assertFalse(audited("POLICY_RESTORED"));
        assertTrue(i.restore(LOCKDOWN, 4, "higher").installed(), "a refused try does not use up the one restore");
    }

    @Test
    void refusedWhenTheAuditRefuses() {
        PolicyInstaller i = installer(0);
        Outcome before = outcome(i);
        auditDown.set(true);
        assertFalse(i.restore(LOCKDOWN, 1, "x").installed());
        assertEquals(0, i.currentSequence());
        assertEquals(before, outcome(i));
        auditDown.set(false);
        assertTrue(i.restore(LOCKDOWN, 1, "x").installed());
    }

    @Test
    void refusedForBadYaml() {
        PolicyInstaller i = installer(0);
        for (String bad : List.of("!!java.lang.ProcessBuilder [calc]", "version: x\nversion: y\n", "default: DENY\n", "")) {
            assertFalse(i.restore(bad, 1, "x").installed(), bad);
        }
        assertEquals(0, i.currentSequence());
        assertFalse(audited("POLICY_RESTORED"));
    }
}

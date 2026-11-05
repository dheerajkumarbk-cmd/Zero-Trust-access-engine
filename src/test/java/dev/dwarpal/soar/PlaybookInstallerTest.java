package dev.dwarpal.soar;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;
import dev.dwarpal.soc.Verdict;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Two-person approval of playbook changes, like policy bundles. */
class PlaybookInstallerTest {

    private final SoarWorld w = new SoarWorld();
    private final List<PlaybookInstaller.Installed> activated = new ArrayList<>();
    private final PlaybookInstaller installer = new PlaybookInstaller(w.compiler(true), w.keys, 2, 0, w.audit, w.clock,
            i -> {
                activated.add(i);
                w.soar.activate(i);
            });

    private static final String AGGRESSIVE = SoarWorld.TEST_PLAYBOOKS.replace("version: \"test-1\"", "version: \"test-2\"")
            .replace("  - rule: pam-refused\n    steps: []", "  - rule: pam-refused\n    steps:\n"
                    + "      - revoke: subject");

    @Test
    void theAggressiveFileReallyDiffers() {
        assertTrue(AGGRESSIVE.contains("pam-refused\n    steps:\n      - revoke: subject"));
    }

    @Test
    void oneAdministratorCannotChangePlaybooks() {
        PlaybookInstaller.Result r = installer.install(SoarWorld.bundle(1, AGGRESSIVE, w.now(), "adm1", SoarWorld.ADM1),
                "adm1");
        assertFalse(r.installed());
        assertTrue(r.reason().contains("1 distinct"));
        // two keys of the same person count once
        r = installer.install(SoarWorld.bundle(1, AGGRESSIVE, w.now(), "adm1", SoarWorld.ADM1, "adm1-b",
                SoarWorld.ADM1_SECOND), "adm1");
        assertFalse(r.installed());
        assertTrue(activated.isEmpty());
        assertEquals(2, w.audited("PLAYBOOKS_REJECTED"));
    }

    @Test
    void approvalsMustCoverThisExactTextAndBeFreshAndOfTheRightPurpose() {
        PlaybookBundle signed = SoarWorld.bundle(1, SoarWorld.TEST_PLAYBOOKS, w.now(), "adm1", SoarWorld.ADM1, "adm2",
                SoarWorld.ADM2);
        PlaybookBundle edited = new PlaybookBundle(1, AGGRESSIVE, signed.approvals());
        assertFalse(installer.install(edited, "adm1").installed(), "any edit voids the approvals");
        PlaybookBundle old = SoarWorld.bundle(1, AGGRESSIVE, w.now().minus(Duration.ofDays(8)), "adm1", SoarWorld.ADM1,
                "adm2", SoarWorld.ADM2);
        assertFalse(installer.install(old, "adm1").installed(), "stale approvals");
        // an analyst's verdict key (wrong purpose) and a policy-bundle signature (wrong domain) do not count
        SignatureProof analyst = new SignatureProof("soc-cleo", w.now(), Ed25519.sign(SoarWorld.CLEO.getPrivate(),
                PlaybookBundle.signedMessage(1, AGGRESSIVE, w.now())));
        SignatureProof policyDomain = new SignatureProof("adm2", w.now(), Ed25519.sign(SoarWorld.ADM2.getPrivate(),
                SignedMessages.policyBundle(1, AGGRESSIVE, w.now())));
        PlaybookBundle mixed = new PlaybookBundle(1, AGGRESSIVE, List.of(
                SoarWorld.bundle(1, AGGRESSIVE, w.now(), "adm1", SoarWorld.ADM1).approvals().getFirst(), analyst,
                policyDomain));
        assertFalse(installer.install(mixed, "adm1").installed());
        assertTrue(activated.isEmpty());
    }

    @Test
    void aFileThatRemovesTheGuardRailsIsRefusedEvenWithTwoApprovals() {
        String noRails = SoarWorld.TEST_PLAYBOOKS.replace("version: \"test-1\"", "version: \"test-3\"")
                .replace("deny: {target: subject, for: P1D}", "deny: {target: subject, for: P365D}")
                .replace("watch: {target: ip, ratio: 10, halfLife: P1D}", "revoke: subject");
        PlaybookInstaller.Result r = installer.install(SoarWorld.bundle(1, noRails, w.now(), "adm1", SoarWorld.ADM1,
                "adm2", SoarWorld.ADM2), "adm1");
        assertFalse(r.installed());
        assertTrue(r.findings().size() >= 2, r.findings().toString());
        assertFalse(installer.install(SoarWorld.bundle(2, "version: [", w.now(), "adm1", SoarWorld.ADM1, "adm2",
                SoarWorld.ADM2), "adm1").installed());
        assertTrue(activated.isEmpty());
    }

    @Test
    void anOlderBundleCannotBePutBack() {
        assertTrue(installer.install(SoarWorld.bundle(5, AGGRESSIVE, w.now(), "adm1", SoarWorld.ADM1, "adm2",
                SoarWorld.ADM2), "adm1").installed());
        assertEquals(5, installer.sequence());
        assertEquals(5, w.soar.playbookSequence());
        assertEquals("test-2", w.soar.playbookVersion());
        PlaybookInstaller.Result r = installer.install(SoarWorld.bundle(4, SoarWorld.TEST_PLAYBOOKS, w.now(), "adm1",
                SoarWorld.ADM1, "adm2", SoarWorld.ADM2), "adm2");
        assertFalse(r.installed());
        assertTrue(r.reason().contains("rollback"));
        assertEquals(1, w.audited("PLAYBOOKS_INSTALLED"));
    }

    @Test
    void noAuditNoInstall() {
        w.auditDown.set(true);
        PlaybookInstaller.Result r = installer.install(SoarWorld.bundle(1, AGGRESSIVE, w.now(), "adm1", SoarWorld.ADM1,
                "adm2", SoarWorld.ADM2), "adm1");
        assertFalse(r.installed());
        assertTrue(activated.isEmpty());
        assertEquals(0, installer.sequence());
        w.auditDown.set(false);
        assertTrue(installer.install(SoarWorld.bundle(1, AGGRESSIVE, w.now(), "adm1", SoarWorld.ADM1, "adm2",
                SoarWorld.ADM2), "adm1").installed());
    }

    @Test
    void theTwoPersonRuleCannotBeConfiguredAway() {
        assertThrows(IllegalArgumentException.class, () -> new PlaybookInstaller(w.compiler(true), w.keys, 1, 0, w.audit,
                w.clock, i -> { }));
        assertThrows(IllegalArgumentException.class, () -> new PlaybookInstaller(w.compiler(true), w.keys, 2, -1, w.audit,
                w.clock, i -> { }));
    }

    @Test
    void rejectionFloodsAreCountedNotAudited() {
        for (int i = 0; i < 30; i++) {
            installer.install(SoarWorld.bundle(1, AGGRESSIVE, w.now(), "adm1", SoarWorld.ADM1), "someone");
        }
        assertEquals(20, w.audited("PLAYBOOKS_REJECTED"));
        assertEquals(10, installer.suppressedRejections());
        // and the flood blocks nobody
        assertTrue(installer.install(SoarWorld.bundle(1, AGGRESSIVE, w.now(), "adm1", SoarWorld.ADM1, "adm2",
                SoarWorld.ADM2), "adm1").installed());
    }

    /** A new playbook version applies to new cases; a case keeps the version that first acted on it. */
    @Test
    void aCaseKeepsThePlaybookVersionThatActedOnIt() {
        String before = w.raise("pam-refused", Severity.MEDIUM, Entity.subject("alice"));
        w.ranker.priorities.put("pam-refused", dev.dwarpal.soc.Priority.P3);
        // the old version (no action) decides the first case; then the aggressive version is installed
        Soar.Result first = w.decide("ana", before, Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(0, first.actions());
        assertTrue(installer.install(SoarWorld.bundle(1, AGGRESSIVE, w.now(), "adm1", SoarWorld.ADM1, "adm2",
                SoarWorld.ADM2), "adm1").installed());
        w.later(Duration.ofMinutes(1));
        String after = w.raise("pam-refused", Severity.MEDIUM, Entity.subject("carol"));
        Soar.Result second = w.decide("ana", after, Verdict.Outcome.TRUE_POSITIVE);
        assertEquals(1, second.actions(), "the new version revokes carol");
    }
}

package dev.dwarpal.soar;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The start-only, once-only way a saved playbook bundle is put back. */
class PlaybookRestoreTest {

    private final SoarWorld w = new SoarWorld();
    private final List<PlaybookInstaller.Installed> activated = new ArrayList<>();
    private final PlaybookInstaller installer = new PlaybookInstaller(w.compiler(true), w.keys, 2, 0, w.audit, w.clock,
            activated::add);

    private static final String OTHER = SoarWorld.TEST_PLAYBOOKS.replace("version: \"test-1\"", "version: \"test-2\"");

    @Test
    void worksOnceAtStartAndActivatesTheSet() {
        PlaybookInstaller.Result r = installer.restore(SoarWorld.TEST_PLAYBOOKS, 3, "installed earlier");
        assertTrue(r.installed(), r.reason());
        assertEquals(3, installer.sequence());
        assertEquals(1, activated.size());
        assertEquals(3, activated.getFirst().sequence());
        assertEquals("test-1", activated.getFirst().set().version());
        assertEquals(1, w.audited("PLAYBOOKS_RESTORED"));
        assertFalse(installer.restore(OTHER, 4, "again").installed(), "only once");
        assertEquals(1, activated.size());
    }

    @Test
    void refusedAfterAnInstall() {
        assertTrue(installer.install(SoarWorld.bundle(1, OTHER, w.now(), "adm1", SoarWorld.ADM1, "adm2", SoarWorld.ADM2),
                "adm1").installed());
        assertFalse(installer.restore(SoarWorld.TEST_PLAYBOOKS, 5, "late").installed());
        assertEquals(1, installer.sequence());
        assertEquals(1, activated.size());
    }

    @Test
    void refusedWhenTheSequenceIsNotHigher() {
        PlaybookInstaller at2 = new PlaybookInstaller(w.compiler(true), w.keys, 2, 2, w.audit, w.clock, activated::add);
        assertFalse(at2.restore(SoarWorld.TEST_PLAYBOOKS, 2, "same").installed());
        assertFalse(at2.restore(SoarWorld.TEST_PLAYBOOKS, 1, "lower").installed());
        assertTrue(activated.isEmpty());
        assertEquals(0, w.audited("PLAYBOOKS_RESTORED"));
    }

    @Test
    void refusedWhenTheAuditRefuses() {
        w.auditDown.set(true);
        assertFalse(installer.restore(SoarWorld.TEST_PLAYBOOKS, 1, "x").installed());
        assertTrue(activated.isEmpty());
        assertEquals(0, installer.sequence());
        w.auditDown.set(false);
        assertTrue(installer.restore(SoarWorld.TEST_PLAYBOOKS, 1, "x").installed());
    }

    @Test
    void refusedForBadOrUnsafeYaml() {
        String noRails = SoarWorld.TEST_PLAYBOOKS.replace("deny: {target: subject, for: P1D}",
                "deny: {target: subject, for: P365D}");
        for (String bad : List.of("!!java.lang.ProcessBuilder [calc]", "version: x\nversion: y\n", "", noRails)) {
            assertFalse(installer.restore(bad, 1, "x").installed(), bad);
        }
        assertTrue(activated.isEmpty());
        assertEquals(0, installer.sequence());
    }
}

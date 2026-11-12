package dev.dwarpal.console.lab;

import dev.dwarpal.lab.scenarios.RuleSandbox;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Every sandbox example does what its label says: the linter accepts the good ones and refuses the bad ones. */
class ExamplesTest {

    private final RuleSandbox sandbox = new RuleSandbox();

    @Test
    void everyExampleDoesWhatItSays() {
        int rules = 0;
        int playbooks = 0;
        for (Examples.Example e : Examples.all()) {
            boolean accepted;
            String detail;
            if (e.kind().equals("rule")) {
                RuleSandbox.RuleResult r = sandbox.rule(null, "tester", e.yaml(), false);
                accepted = r.accepted();
                detail = r.findings().toString();
                rules++;
            } else {
                RuleSandbox.PlaybookResult r = sandbox.playbook(e.yaml());
                accepted = r.accepted();
                detail = r.findings().toString();
                playbooks++;
            }
            assertEquals(e.expect().equals("accepted"), accepted, e.id() + ": " + detail);
            assertFalse(e.teaches().isBlank());
        }
        assertTrue(rules >= 5 && playbooks >= 4, "both kinds, good and bad");
    }

    @Test
    void theForgeableEvidenceExampleIsRefusedForTheRightReason() {
        Examples.Example e = Examples.all().stream().filter(x -> x.id().equals("playbook-forgeable")).findFirst().orElseThrow();
        RuleSandbox.PlaybookResult r = sandbox.playbook(e.yaml());
        assertFalse(r.accepted());
        assertTrue(r.findings().stream().anyMatch(f -> f.level().equals("ERROR") && f.message().toLowerCase().contains("collected")),
                r.findings().toString());
        assertTrue(r.plans().isEmpty(), "nothing is described for a refused file");
    }

    @Test
    void theAcceptedPlaybookIsDescribedInPlainWords() {
        Examples.Example e = Examples.all().stream().filter(x -> x.id().equals("playbook-watch")).findFirst().orElseThrow();
        RuleSandbox.PlaybookResult r = sandbox.playbook(e.yaml());
        assertTrue(r.accepted(), r.findings().toString());
        assertEquals(1, r.plans().size());
        assertEquals("beacon-from-document-process", r.plans().get(0).rule());
        assertTrue(r.plans().get(0).steps().stream().anyMatch(s -> s.contains("isolate the device")));
        assertTrue(r.plans().get(0).steps().stream().anyMatch(s -> s.startsWith("watch the subject")));
    }
}

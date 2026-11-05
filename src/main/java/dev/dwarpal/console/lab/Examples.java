package dev.dwarpal.console.lab;

import java.util.List;

/**
 * Starting points for the sandbox: rules and playbooks that work, and ones the linter refuses, each with the
 * outcome the learner should see. {@code ExamplesTest} runs every one, so the stated outcome is the real one.
 */
final class Examples {

    /** @param expect {@code accepted} or {@code refused} */
    record Example(String id, String kind, String title, String yaml, String expect, String teaches) {
    }

    private static final List<Example> ALL = List.of(
            new Example("rule-usb", "rule", "Any USB drive plugged in", """
                    version: 1
                    rules:
                      - id: lab-usb-mount
                        title: A USB drive was plugged in
                        severity: MEDIUM
                        techniques: [T1052.001]
                        match: 'dataset = endpoint and action = usb.mount'
                    """, "accepted", "The simplest rule: every matching event raises an alert. Run it to see how many."),
            new Example("rule-flows", "rule", "Many firewall flows to one address", """
                    version: 1
                    rules:
                      - id: lab-chatty-device
                        title: One device made many flows to one destination
                        severity: HIGH
                        techniques: [T1071]
                        threshold:
                          where: 'dataset = firewall and action = network.flow'
                          by: [device, dst]
                          within: 1h
                          count: 20
                    """, "accepted", "A threshold rule: a count per key inside a sliding window. Beacons trip it; try raising the count."),
            new Example("rule-sequence", "rule", "PowerShell, then a USB drive", """
                    version: 1
                    rules:
                      - id: lab-ps-then-usb
                        title: Encoded PowerShell followed by a USB drive on one device
                        severity: HIGH
                        techniques: [T1059.001, T1052.001]
                        sequence:
                          by: device
                          within: 30m
                          steps:
                            - where: 'dataset = endpoint and action = process.start and process = powershell.exe and cmd ~ " -enc"'
                            - where: 'dataset = endpoint and action = usb.mount'
                    """, "accepted", "A sequence rule: steps in order for one key. This is half of the stolen-laptop rule."),
            new Example("rule-never-fires", "rule", "A rule that can never fire", """
                    version: 1
                    rules:
                      - id: lab-impossible
                        title: Needs two different datasets in one event
                        severity: LOW
                        techniques: [T1071]
                        match: 'dataset = firewall and dataset = endpoint'
                    """, "refused", "The linter refuses a rule that contradicts itself: a silent rule looks like safety and is not."),
            new Example("rule-bad-technique", "rule", "An invented MITRE technique", """
                    version: 1
                    rules:
                      - id: lab-made-up
                        title: Uses a technique nobody defined
                        severity: LOW
                        techniques: [T9999]
                        match: 'dataset = endpoint'
                    """, "refused", "Techniques come from a fixed list, so every report speaks the same language."),
            new Example("rule-alias", "rule", "A YAML alias (the classic bomb)", """
                    version: 1
                    rules: &r
                      - id: lab-alias
                        title: aliases are refused
                        severity: LOW
                        techniques: [T1071]
                        match: 'dataset = endpoint'
                    again: *r
                    """, "refused", "Rule files are safe YAML: no objects, no aliases, no duplicate keys."),
            new Example("playbook-watch", "playbook", "Isolate the laptop after a beacon", """
                    version: "lab.1"
                    playbooks:
                      - rule: beacon-from-document-process
                        description: Watch the person, isolate the laptop
                        steps:
                          - isolate: device
                          - watch: {target: subject, ratio: 10, halfLife: P1D}
                    """, "accepted", "Isolation is allowed here because this rule rests on the laptop's signed sensor."),
            new Example("playbook-forgeable", "playbook", "Isolate on forgeable evidence", """
                    version: "lab.2"
                    playbooks:
                      - rule: cloud-download-volume
                        description: Isolate when the cloud log says so
                        steps:
                          - isolate: device
                    """, "refused", "The linter refuses a destructive step on a rule whose evidence is only collected: anyone could forge it."),
            new Example("playbook-too-long", "playbook", "A deny that never ends", """
                    version: "lab.3"
                    playbooks:
                      - rule: honeytoken-touched
                        description: Deny for a month
                        steps:
                          - deny: {target: subject, for: P30D}
                    """, "refused", "Guard rails hold whatever the file says: a deny cannot outlast the deployment's limit."),
            new Example("playbook-secret", "playbook", "A secret in a playbook", """
                    version: "lab.4"
                    playbooks:
                      - rule: encoded-powershell
                        description: password=hunter2hunter2hunter2
                        steps:
                          - watch: {target: device, ratio: 10, halfLife: P1D}
                    """, "refused", "Files never carry secrets; connectors hold their own configuration."));

    private Examples() {
    }

    static List<Example> all() {
        return ALL;
    }
}

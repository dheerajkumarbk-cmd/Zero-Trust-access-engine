package dev.dwarpal.lab.scenarios;

import java.util.List;
import java.util.Optional;

/**
 * The guided walkthroughs: for each scenario a short path through the analyst console, the MITRE technique, what
 * the same thing looks like in a commercial product, and what the learner should notice. This one list feeds the
 * guide pages and the Markdown files under {@code docs/layer-6/guide} (a test fails if the files are stale), and
 * {@code ScenarioGuideTest} runs every scenario on a real lab and checks the decisions and priorities named in
 * {@link ScenarioCatalog}, so a walkthrough cannot drift from what the lab shows.
 *
 * <p>The commercial lines name product families to help the learner map the idea onto tools they may meet; they are
 * descriptions of the kind of detection such products offer, not claims about any product's exact behaviour.
 */
public final class Walkthroughs {

    /**
     * @param scenario   the scenario id
     * @param summary    one sentence
     * @param steps      the path through the console, in order
     * @param mitre      technique ids with names and tactic
     * @param commercial what the same thing looks like in a commercial SIEM, SOAR or XDR
     * @param notice     what the learner should notice
     */
    public record Walkthrough(String scenario, String title, String summary, List<String> steps, List<String> mitre,
                              List<String> commercial, List<String> notice) {
        public Walkthrough {
            steps = List.copyOf(steps);
            mitre = List.copyOf(mitre);
            commercial = List.copyOf(commercial);
            notice = List.copyOf(notice);
        }
    }

    private static final String START = "Open Lab, Scenarios. Press Launch on this scenario and read what the attacker "
            + "does. The launch tells you the person (and laptop) it is about. If the clock is paused, resume it or "
            + "fast-forward (Lab, Controls).";

    private static final List<Walkthrough> ALL = List.of(
            new Walkthrough("A1", "A1 Credential stuffing from abroad",
                    "A leaked password is tried from Russia; Dwarpal refuses it, and the proof is in the audit trail, not the queue.",
                    List.of(START,
                            "Open the Alert queue and filter by the person. Nothing urgent is there: that is correct, the attack was stopped before it became an incident.",
                            "Open the Audit explorer, or Hunt with: subject = <person>. Find the access decision with outcome DENY.",
                            "Open it and read the factors: new address, new country, an unknown computer. Each has a weight; together the chance of attack is about 80 per cent, enough to refuse.",
                            "Open the person's Entity page: their risk went up and will fade with time."),
                    List.of("T1110.004 Credential Stuffing (credential-access)"),
                    List.of("An identity-protection product (for example Microsoft Entra ID Protection or Okta) raises a risky sign-in with 'leaked credentials' or 'unfamiliar location' and its conditional access blocks or asks for MFA."),
                    List.of("A denied login is not an alert. The access engine and the SOC are two layers: one blocks, the other hunts what got through.",
                            "Why it was denied is recorded with numbers, so a person can check the decision by hand.")),
            new Walkthrough("A2", "A2 Login from a cloud server in the same country",
                    "The attacker rents a cloud server in India so the country looks normal; the cloud provider's network gives it away.",
                    List.of(START,
                            "Hunt with: subject = <person>, find the DENY decision.",
                            "Read the factors: a new address with a bad reputation (the cloud provider's network is on the threat list), and an unknown computer. The country is the usual one, which is why this is harder than A1 for a country-based rule.",
                            "Compare it with A1: same outcome, different reasons."),
                    List.of("T1078 Valid Accounts (initial-access)"),
                    List.of("Products flag sign-ins from hosting or VPN providers ('anonymous or hosting IP' risk detections) and combine them with device trust."),
                    List.of("Country alone is a weak signal; the network type and the device matter more.")),
            new Walkthrough("A3", "A3 Residential proxy in the person's own city",
                    "The location looks right, so the engine does not refuse; it asks for a second factor the attacker does not have.",
                    List.of(START,
                            "Hunt with: subject = <person>. The decision is STEP_UP, not DENY.",
                            "Read why: the address is new but on the person's own provider, and the computer is unknown. The chance of attack is low (about one per cent), above the step-up line but far below the deny line, and the request carries no verified second factor, so the engine challenges rather than refuses.",
                            "Think about what STEP_UP does to an attacker who has only a password."),
                    List.of("T1090.003 Multi-hop Proxy (command-and-control)"),
                    List.of("Conditional access asks for MFA on 'unfamiliar sign-in properties'; a stolen password alone does not complete it."),
                    List.of("Three outcomes exist (ALLOW, STEP_UP, DENY), and the middle one is the one that costs attackers most.")),
            new Walkthrough("A4", "A4 Impossible travel",
                    "A normal login, then the same account from London twenty minutes later.",
                    List.of(START,
                            "Fast-forward 30 minutes so both requests have run.",
                            "Hunt with: subject = <person>. The first decision is ALLOW, the second DENY.",
                            "Open the DENY: the impossible-travel factor shows the distance and the speed it implies, about 8,000 km in twenty minutes."),
                    List.of("T1078 Valid Accounts (initial-access)"),
                    List.of("'Atypical travel' or 'impossible travel' risk detections in identity products, and 'impossible travel' policies in cloud-app security tools."),
                    List.of("The first, legitimate login is what makes the second one impossible: detections remember.")),
            new Walkthrough("A5", "A5 Login through Tor",
                    "The attacker hides behind a Tor exit node, which is on the threat list.",
                    List.of(START,
                            "Hunt with: subject = <person> and read the DENY decision.",
                            "The factors include 'ip-reputation': the address is a known Tor exit."),
                    List.of("T1090.003 Multi-hop Proxy (command-and-control)"),
                    List.of("An 'anonymous IP address' risk detection, fed by threat-intelligence lists of Tor exits."),
                    List.of("A list is only as good as its last update; the lab's list is a short fixed one.")),
            new Walkthrough("A6", "A6 Stolen laptop used from the owner's network",
                    "The engine allows the login (its known blind spot); the laptop's signed sensor shows the theft, and the SOC raises a P1 it may act on.",
                    List.of(START,
                            "Fast-forward 20 minutes: the sensor's events arrive in a batch a minute after the burst ends.",
                            "Open the Alert queue and filter by the laptop. Find the P1 'stolen-laptop-collection' and the P2 'encoded-powershell'.",
                            "Read why it is P1: high severity, the device's risk, the asset's value, and nothing in it rests only on collected evidence.",
                            "Open the case. In the timeline find the three steps in order: an encoded PowerShell, a USB drive, bulk reads of finance files. Open each evidence link to the audit record.",
                            "Open the ATT&CK view: the techniques PowerShell, Exfiltration over USB and Data from Network Shared Drive light up.",
                            "Decide: sign a verdict TRUE_POSITIVE. The playbook isolates the laptop and watches the person. In Response, the isolation shows as pending until the laptop's own sensor key acknowledges it.",
                            "Sign the same verdict again: it is refused, a verdict is single use."),
                    List.of("T1059.001 PowerShell (execution)", "T1052.001 Exfiltration over USB (exfiltration)",
                            "T1039 Data from Network Shared Drive (collection)", "T1560 Archive Collected Data (collection)"),
                    List.of("An endpoint-detection product (for example Microsoft Defender for Endpoint, CrowdStrike Falcon) flags encoded PowerShell and USB mass storage; a SOAR playbook (for example in Cortex XSOAR or a Sentinel playbook) isolates the host after approval."),
                    List.of("The engine allowed the login: no network check can see a thief who looks like the owner. Only the device's own telemetry shows it.",
                            "The alert may act because the sensor signs its batches: the evidence cannot be forged by someone on the network.",
                            "Isolation is 'pending' until the device confirms it; a command sent is not the same as an effect achieved.")),
            new Walkthrough("A7", "A7 Password spray",
                    "One address tries passwords for fifteen accounts, then logs in as this person.",
                    List.of(START,
                            "Fast-forward five minutes.",
                            "Hunt with: ip = 198.51.100.66. It finds the one request from that address: the fifteen failed attempts are counted by the engine's failure log, not stored as events.",
                            "Open that request's decision: DENY, and the factor list includes 'password-spray', the failures counted against the address.",
                            "Open the address's Entity page."),
                    List.of("T1110.003 Password Spraying (credential-access)"),
                    List.of("Identity products flag 'password spray' from many failures spread over many accounts; web gateways block the address."),
                    List.of("One failure per account looks harmless; fifteen accounts from one address does not. The unit that matters is the source.")),
            new Walkthrough("A8", "A8 Beaconing to a command server",
                    "A program started by a document calls the same address every minute; two sources agree, so the SOC may isolate the laptop.",
                    List.of(START,
                            "Fast-forward two hours. Beaconing takes time to look like a rhythm.",
                            "Open the Alert queue and filter by the laptop. Find the P1 'beacon-from-document-process' and the P2 'beacon-regular-destination'.",
                            "Compare them: both are about the same laptop and address. The P1 rests on the signed sensor and the firewall; the P2 only on the firewall, so it is not actionable.",
                            "Open the P1 case and read the timeline: a document-spawned process, then many connections to one rare address.",
                            "Open Hunt and run: dataset = firewall and dst = 203.0.113.66 | count by device. Compare the firewall's view with the sensor's.",
                            "Open the Entity page for the laptop: the behaviour model's 'beacon' finding shows the regular gaps between connections.",
                            "Decide: TRUE_POSITIVE. The playbook isolates the laptop; watch Response until the sensor acknowledges."),
                    List.of("T1071 Application Layer Protocol (command-and-control)"),
                    List.of("Network detection (for example in Splunk Enterprise Security, Elastic Security or Microsoft Sentinel) has 'beaconing' analytics based on regular intervals; an endpoint product confirms the parent process and can contain the host."),
                    List.of("Two independent sources turned a P2 into a P1.",
                            "Same facts, different evidence class, different power: the firewall-only alert can never trigger an action by itself.")),
            new Walkthrough("A9", "A9 Mass download and external share from cloud storage",
                    "Forty times the usual volume in an hour, then a folder shared outside; real alerts, but capped because cloud logs are forgeable.",
                    List.of(START,
                            "Fast-forward 70 minutes.",
                            "Open the Alert queue and filter by the person. The top alert is a P2, 'cloud-bulk-download-then-external-share'; 'cloud-download-volume' is P3.",
                            "Open the case and read the 'why this rank' lines: they say 'only collected evidence' and 'no destructive action'.",
                            "Open Hunt: dataset = cloud and subject = <person> | count by op. Find the share to partner-mail.example.",
                            "Decide as an analyst: the playbook only watches the person. Anything stronger is your call, outside the automatic path."),
                    List.of("T1567.002 Exfiltration to Cloud Storage (exfiltration)"),
                    List.of("Cloud-app security products (for example Microsoft Defender for Cloud Apps) flag 'mass download by a single user' and 'unusual external sharing'; data-loss-prevention tools classify what left."),
                    List.of("Anyone with access to the cloud log could write these lines, so Dwarpal does not let them trigger an action.",
                            "A P2 with no automatic response is a decision for a human, which is the point.")),
            new Walkthrough("L5", "L5 Quarter-end download (harmless)",
                    "A false-positive check: a lot of downloading, all inside the company.",
                    List.of(START,
                            "Fast-forward an hour.",
                            "Open the Alert queue and filter by the person. No correlation rule fired; at most a P4 note about volume.",
                            "Open the Entity page: the behaviour model noted the volume as unusual, and the note is low because the evidence is only collected and nothing else is unusual.",
                            "Compare with A9: similar volume, no external share, no alert worth a person's time."),
                    List.of(),
                    List.of("Tuning: suppress or lower the priority for known busy periods and roles; a good SOC measures false-positive rates per rule."),
                    List.of("What the SOC does not raise is as important as what it does.",
                            "The same volume as A9 is harmless here, because the external share is missing.")),
            new Walkthrough("L6", "L6 Administrator's signed PowerShell (harmless)",
                    "An administrator runs the signed backup script, as every working day.",
                    List.of(START,
                            "Fast-forward five minutes.",
                            "Open the Alert queue: nothing about the administrator's laptop.",
                            "Hunt with: dataset = endpoint and process = powershell.exe. Find the event with signer corp-it, and compare with A6's encoded PowerShell, which has no signer.",
                            "Open the ATT&CK view: PowerShell is covered, but the rule asks for an encoded command, not any PowerShell."),
                    List.of(),
                    List.of("Allow-listing of signed administrative scripts, application control (for example WDAC or AppLocker) and parent-process context in the detection."),
                    List.of("A rule about what is unusual about the activity ('encoded command') beats a rule about the tool ('PowerShell').")),
            new Walkthrough("QUIET", "A quiet day",
                    "Six hours of ordinary activity: the baseline that makes everything else stand out.",
                    List.of(START,
                            "Fast-forward six hours.",
                            "Open the Alert queue: no new P1 or P2. A few P3 or P4 notes may appear for people active outside their usual hours.",
                            "Open the Overview: sources healthy, no breached SLA from this run."),
                    List.of(),
                    List.of("A normal day's volume and its baseline noise: analysts learn what quiet looks like before judging what is loud."),
                    List.of("Even a quiet day produces low-priority notes; priorities exist to keep them out of the way.")));

    private Walkthroughs() {
    }

    public static List<Walkthrough> all() {
        return ALL;
    }

    public static Optional<Walkthrough> byScenario(String id) {
        return ALL.stream().filter(w -> w.scenario().equals(id)).findFirst();
    }

    /** One walkthrough as Markdown, with the scenario's own texts (the files under {@code docs/layer-6/guide}). */
    public static String markdown(Walkthrough w) {
        Scenario s = ScenarioCatalog.byId(w.scenario()).orElseThrow();
        StringBuilder b = new StringBuilder();
        b.append("# ").append(w.title()).append("\n\n");
        b.append("*Generated from the lab's own guide data (`Walkthroughs`) and checked against a running lab by "
                + "`ScenarioGuideTest`; do not edit by hand.*\n\n");
        b.append(w.summary()).append("\n\n");
        b.append("## What the attacker does\n\n").append(s.attacker()).append("\n\n");
        b.append("## What the defender should see\n\n").append(s.defender()).append("\n\n");
        if (!s.decisions().isEmpty()) {
            b.append("Access engine decisions, in order: ").append(String.join(", ", s.decisions())).append(".\n\n");
        }
        if (!s.expects().isEmpty()) {
            b.append("| Alert | Priority | May a playbook act on it |\n|---|---|---|\n");
            s.expects().forEach(e -> b.append("| `").append(e.rule()).append("` | ").append(e.priority()).append(" | ")
                    .append(e.actionable() ? "yes (verified evidence)" : "no (collected evidence only)").append(" |\n"));
            b.append("\n");
        }
        b.append("Nothing about this scenario is more urgent than ").append(s.ceiling()).append(".\n\n");
        b.append("## Your path through the console\n\n");
        int n = 1;
        for (String step : w.steps()) {
            b.append(n++).append(". ").append(step).append("\n");
        }
        b.append("\n## MITRE ATT&CK\n\n");
        if (w.mitre().isEmpty()) {
            b.append("None: this is a harmless look-alike or a baseline.\n");
        } else {
            w.mitre().forEach(m -> b.append("- ").append(m).append("\n"));
        }
        b.append("\n## In a commercial product\n\n");
        w.commercial().forEach(c -> b.append("- ").append(c).append("\n"));
        b.append("\n## What to notice\n\n");
        w.notice().forEach(c -> b.append("- ").append(c).append("\n"));
        return b.toString();
    }
}

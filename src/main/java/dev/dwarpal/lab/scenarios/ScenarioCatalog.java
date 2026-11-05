package dev.dwarpal.lab.scenarios;

import dev.dwarpal.lab.scenarios.Plans.Context;
import dev.dwarpal.lab.scenarios.Plans.Plan;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * The scenarios a learner can launch: A1 to A9 as the simulation defines them, the look-alikes L5 and L6, and a
 * quiet day. The texts say what the attacker does and what the defender should see; the decisions, priorities and
 * rules named here are checked against a real lab by {@code ScenarioGuideTest}, so a text cannot promise something
 * the lab does not show.
 */
public final class ScenarioCatalog {

    /** Who a scenario is about. */
    enum Cast { ANYONE, FINANCE, ADMIN, NOBODY }

    record Def(Scenario info, Cast cast, Function<Context, Plan> build) {
    }

    private static final String QUEUE_QUIET = " The SOC queue stays quiet or shows at most a low-priority (P4) note;"
            + " the proof is in the audit trail: search Dwarpal's own records for the person.";

    private static final List<Def> ALL = List.of(
            def("A1", Scenario.Kind.ATTACK, "Credential stuffing from abroad", List.of("T1110.004 Credential Stuffing"),
                    "An attacker has a list of leaked passwords and tries one of them for this person from a server in "
                            + "Russia, on a computer Dwarpal has never seen.",
                    "The access engine refuses the login on the spot (DENY): new address, new country, unknown computer."
                            + QUEUE_QUIET,
                    1, List.of("DENY"), "P4", List.of(), Cast.ANYONE, Plans::a1),
            def("A2", Scenario.Kind.ATTACK, "Login from a cloud server in the same country", List.of("T1078 Valid Accounts"),
                    "The attacker rents a cloud server in India so that the country looks normal, and logs in with the "
                            + "stolen password from an unknown computer.",
                    "The engine refuses (DENY): the network belongs to a cloud provider, which is on the threat list."
                            + QUEUE_QUIET,
                    1, List.of("DENY"), "P4", List.of(), Cast.ANYONE, Plans::a2),
            def("A3", Scenario.Kind.ATTACK, "Residential proxy in the person's own city", List.of("T1090.003 Multi-hop Proxy"),
                    "The attacker uses a proxy that makes the login appear to come from the person's own city and "
                            + "ISP, from an unknown computer.",
                    "The place looks right, so the engine does not refuse; it asks for a second factor (STEP_UP) because "
                            + "the computer is new. A password alone cannot pass it." + QUEUE_QUIET,
                    1, List.of("STEP_UP"), "P4", List.of(), Cast.ANYONE, Plans::a3),
            def("A4", Scenario.Kind.ATTACK, "Impossible travel", List.of("T1078 Valid Accounts"),
                    "The person logs in normally. Twenty minutes later the same account logs in from London.",
                    "The first login is allowed (ALLOW), the second refused (DENY): 8,000 km in twenty minutes."
                            + QUEUE_QUIET,
                    21, List.of("ALLOW", "DENY"), "P4", List.of(), Cast.ANYONE, Plans::a4),
            def("A5", Scenario.Kind.ATTACK, "Login through Tor", List.of("T1090.003 Multi-hop Proxy"),
                    "The attacker hides behind a Tor exit node.",
                    "Known Tor exit addresses are on the threat list: DENY." + QUEUE_QUIET,
                    1, List.of("DENY"), "P4", List.of(), Cast.ANYONE, Plans::a5),
            def("A6", Scenario.Kind.ATTACK, "Stolen laptop used from the owner's network", List.of(
                    "T1059.001 PowerShell", "T1052.001 Exfiltration over USB", "T1039 Data from Network Shared Drive",
                    "T1560 Archive Collected Data"),
                    "A thief uses the person's own laptop, with the owner's security key from the same bag, from a "
                            + "network the engine knows, so the login looks right. On the laptop a hidden encoded "
                            + "PowerShell runs, a USB drive is plugged in, finance files are read and archived.",
                    "The engine allows the login (its known blind spot). The laptop's signed sensor events show the rest: "
                            + "the SOC raises a P1 case, 'stolen-laptop-collection', on signed evidence, so a playbook "
                            + "may isolate the laptop once an analyst signs a verdict.",
                    14, List.of("ALLOW"), "P1", List.of(
                    new Scenario.Expect("stolen-laptop-collection", "P1", true, "D"),
                    new Scenario.Expect("encoded-powershell", "P2", true, "D")), Cast.ANYONE, Plans::a6),
            def("A7", Scenario.Kind.ATTACK, "Password spray", List.of("T1110.003 Password Spraying"),
                    "One address tries passwords against fifteen accounts, then logs in as this person.",
                    "The failed attempts are counted against the address, and the login from it is refused (DENY)."
                            + QUEUE_QUIET,
                    3, List.of("DENY"), "P4", List.of(), Cast.ANYONE, Plans::a7),
            def("A8", Scenario.Kind.ATTACK, "Beaconing to a command server", List.of(
                    "T1071 Application Layer Protocol"),
                    "A program started from a Word document connects to the same rare outside address every minute for "
                            + "two hours, the rhythm of malware waiting for orders.",
                    "Two sources agree, the laptop's signed sensor and the firewall: a P1 case, "
                            + "'beacon-from-document-process', on evidence a playbook may act on. The firewall-only "
                            + "'beacon-regular-destination' for the same laptop is P2 and can never trigger an "
                            + "action by itself.",
                    123, List.of(), "P1", List.of(
                    new Scenario.Expect("beacon-from-document-process", "P1", true, "D"),
                    new Scenario.Expect("beacon-regular-destination", "P2", false, "D")), Cast.ANYONE, Plans::a8),
            def("A9", Scenario.Kind.ATTACK, "Mass download and external share from cloud storage", List.of(
                    "T1567.002 Exfiltration to Cloud Storage"),
                    "In one hour one person downloads about forty times their normal volume, then shares the folder with "
                            + "an outside address.",
                    "The cloud service's log is easy to forge, so the alerts are real but capped: "
                            + "'cloud-bulk-download-then-external-share' is P2 and 'cloud-download-volume' P3, neither "
                            + "can trigger a destructive action. A human has to decide.",
                    62, List.of(), "P2", List.of(
                    new Scenario.Expect("cloud-bulk-download-then-external-share", "P2", false, "D"),
                    new Scenario.Expect("cloud-download-volume", "P3", false, "D")), Cast.ANYONE, Plans::a9),
            def("L5", Scenario.Kind.LOOK_ALIKE, "Quarter-end download (harmless)", List.of(),
                    "A finance person downloads sixty large spreadsheets at quarter end. Everything stays inside the "
                            + "company.",
                    "The false positive the lab checks for: no correlation rule fires. The behaviour model notes the "
                            + "large volume at P4 (the lowest priority) and cannot act on it.",
                    46, List.of(), "P4", List.of(), Cast.FINANCE, Plans::l5),
            def("L6", Scenario.Kind.LOOK_ALIKE, "Administrator's signed PowerShell (harmless)", List.of(),
                    "An IT administrator runs the company's signed backup script in PowerShell, as every working day.",
                    "PowerShell is on the watch list, but a signed script from an administrator is not an incident: "
                            + "no alert at all.",
                    2, List.of(), "P4", List.of(), Cast.ADMIN, Plans::l6),
            def("QUIET", Scenario.Kind.BASELINE, "A quiet day", List.of(),
                    "Nothing happens but work: people with no earlier suspicion use ordinary programs, browse and "
                            + "download a little (six hours of scenario time).",
                    "No incident: at most a few P3 or P4 notes about activity outside a person's usual hours. This is "
                            + "what normal looks like, so the others stand out.",
                    360, List.of(), "P3", List.of(), Cast.NOBODY, Plans::quiet));

    private ScenarioCatalog() {
    }

    private static Def def(String id, Scenario.Kind kind, String title, List<String> techniques, String attacker,
                           String defender, int minutes, List<String> decisions, String ceiling,
                           List<Scenario.Expect> expects, Cast cast, Function<Context, Plan> build) {
        return new Def(new Scenario(id, kind, title, techniques, attacker, defender, minutes, decisions, ceiling,
                expects), cast, build);
    }

    /** All scenarios, in the order the screen shows them. */
    public static List<Scenario> all() {
        return ALL.stream().map(Def::info).toList();
    }

    public static Optional<Scenario> byId(String id) {
        return ALL.stream().map(Def::info).filter(s -> s.id().equals(id)).findFirst();
    }

    static Optional<Def> def(String id) {
        return ALL.stream().filter(d -> d.info().id().equals(id)).findFirst();
    }
}

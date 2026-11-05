package dev.dwarpal.soc;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The MITRE ATT&CK (Enterprise) techniques Dwarpal's rules, detectors and simulated scenarios refer to. Rules
 * tag alerts with these ids; part E measures coverage against this list. Adding a technique is a code change,
 * so a rule file cannot invent ids that no report knows.
 */
public final class Techniques {

    private static final Map<String, Technique> ALL = new LinkedHashMap<>();

    public static final Technique BRUTE_FORCE = add("T1110", "Brute Force", "credential-access");
    public static final Technique PASSWORD_SPRAYING = add("T1110.003", "Password Spraying", "credential-access");
    public static final Technique CREDENTIAL_STUFFING = add("T1110.004", "Credential Stuffing", "credential-access");
    public static final Technique MFA_REQUEST_GENERATION = add("T1621", "Multi-Factor Authentication Request Generation",
            "credential-access");
    public static final Technique STEAL_SESSION_COOKIE = add("T1539", "Steal Web Session Cookie", "credential-access");
    public static final Technique VALID_ACCOUNTS = add("T1078", "Valid Accounts", "initial-access");
    public static final Technique MULTI_HOP_PROXY = add("T1090.003", "Multi-hop Proxy", "command-and-control");
    public static final Technique APPLICATION_LAYER_PROTOCOL = add("T1071", "Application Layer Protocol",
            "command-and-control");
    public static final Technique POWERSHELL = add("T1059.001", "PowerShell", "execution");
    public static final Technique OBFUSCATED_FILES = add("T1027", "Obfuscated Files or Information", "defense-evasion");
    public static final Technique ABUSE_ELEVATION = add("T1548", "Abuse Elevation Control Mechanism",
            "privilege-escalation");
    public static final Technique ACCOUNT_MANIPULATION = add("T1098", "Account Manipulation", "persistence");
    public static final Technique DATA_FROM_NETWORK_SHARE = add("T1039", "Data from Network Shared Drive", "collection");
    public static final Technique ARCHIVE_COLLECTED_DATA = add("T1560", "Archive Collected Data", "collection");
    public static final Technique EXFIL_TO_CLOUD_STORAGE = add("T1567.002", "Exfiltration to Cloud Storage",
            "exfiltration");
    public static final Technique EXFIL_OVER_USB = add("T1052.001", "Exfiltration over USB", "exfiltration");
    public static final Technique INDICATOR_REMOVAL = add("T1070", "Indicator Removal", "defense-evasion");
    public static final Technique IMPAIR_DEFENSES = add("T1562", "Impair Defenses", "defense-evasion");

    private Techniques() {
    }

    private static Technique add(String id, String name, String tactic) {
        Technique t = new Technique(id, name, tactic);
        ALL.put(id, t);
        return t;
    }

    /** The technique with this id, if Dwarpal knows it. */
    public static Optional<Technique> byId(String id) {
        return Optional.ofNullable(ALL.get(id));
    }

    /** Every known technique, in a fixed order. */
    public static List<Technique> all() {
        return List.copyOf(ALL.values());
    }
}

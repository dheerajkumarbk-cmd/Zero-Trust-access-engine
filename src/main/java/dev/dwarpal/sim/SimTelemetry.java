package dev.dwarpal.sim;

import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;

/**
 * Raw telemetry from three more sources for a {@link SimOrganisation}: a firewall (RFC 5424 syslog lines), an
 * endpoint sensor on every laptop (JSON lines in hourly batches signed by the device agent's key) and a cloud
 * file-sharing application (JSON lines). Every item carries its ground-truth label, which a collector must
 * never see: it is for measuring, not for detecting.
 *
 * <p>Besides everyday activity it contains attacks that only correlation across sources can see, and two
 * legitimate activities that look alarming on one source (false-positive checks):
 * <ul>
 *   <li>{@code A6_STOLEN_LAPTOP_AT_HOME}: at every A6 login of the base traffic (the engine allows them, the
 *       known blind spot), the laptop runs an encoded PowerShell, mounts a USB drive, reads many finance files
 *       and archives them.</li>
 *   <li>{@code A8_BEACONING}: on two laptops a new process started by a document connects to the same rare
 *       address every 60 seconds for two hours (endpoint and firewall).</li>
 *   <li>{@code A9_CLOUD_EXFIL}: one person downloads about 40 times their usual daily volume within an hour
 *       and shares a folder with an outside address (cloud).</li>
 *   <li>{@code L5_BIG_LEGIT_DOWNLOAD}: a finance person downloads a lot at quarter end, internal only.</li>
 *   <li>{@code L6_ADMIN_POWERSHELL}: IT administrators run a signed PowerShell script every working day.</li>
 *   <li>{@code NOISE}: a few malformed syslog lines, as real networks send.</li>
 * </ul>
 * The numbers are built by the same team as the detectors, so results on them measure consistency with the
 * threat model, not real-world accuracy.
 */
public final class SimTelemetry {

    public enum Source { FIREWALL, ENDPOINT, CLOUD }

    public enum Activity {
        NORMAL, NOISE, L5_BIG_LEGIT_DOWNLOAD, L6_ADMIN_POWERSHELL,
        A6_STOLEN_LAPTOP_AT_HOME, A8_BEACONING, A9_CLOUD_EXFIL;

        public boolean attack() {
            return name().startsWith("A");
        }
    }

    /** Anything the sources emit, in time order. */
    public sealed interface Item permits RawLine, EndpointBatch {
        Instant at();
    }

    /** One firewall or cloud line as it arrives. */
    public record RawLine(Source source, Instant at, String text, Activity activity, String userId) implements Item {
    }

    /** One signed endpoint batch: JSON lines, one per event; {@code activities} labels each line. */
    public record EndpointBatch(String deviceId, String keyId, long batch, Instant at, String body, String signature,
                                List<Activity> activities, String userId) implements Item {
        public EndpointBatch {
            activities = List.copyOf(activities);
        }

        /** The proof a collector verifies against the key ring ({@code DEVICE_AGENT}, bound to the device). */
        public SignatureProof proof() {
            return new SignatureProof(keyId, at, signature);
        }

        /** The message the signature covers. */
        public byte[] signedMessage() {
            return SignedMessages.endpointTelemetry(deviceId, batch, at, Digests.sha256Hex(body));
        }
    }

    public static final String FIREWALL_HOST = "fw01";
    public static final String C2_ADDRESS = "203.0.113.66";
    public static final int C2_PORT = 4444;
    public static final String EXTERNAL_SHARE = "partner-mail.example";
    public static final List<String> SAAS_ADDRESSES = List.of("198.51.100.10", "198.51.100.11", "198.51.100.12");
    private static final String[] DEPARTMENTS = {"engineering", "finance", "sales", "hr", "it"};
    private static final String[] APPS = {"code.exe", "chrome.exe", "teams.exe", "outlook.exe", "git.exe", "excel.exe"};

    private final SimOrganisation org;
    private final Random rnd;
    private final Map<String, String> departments = new LinkedHashMap<>();
    private final Map<String, String> leases = new LinkedHashMap<>();
    private final List<String> admins = new ArrayList<>();
    private final List<String> beaconing = new ArrayList<>();
    private final String exfiltrator;
    private final String quarterEnd;
    private final List<Item> items = new ArrayList<>();
    /** Endpoint events per device per hour, before sealing into batches. */
    private final Map<String, TreeMap<Instant, List<String[]>>> pending = new HashMap<>();
    private long fwSeq;

    private SimTelemetry(SimOrganisation org, List<SimOrganisation.Step> traffic) {
        this.org = org;
        this.rnd = new Random(org.seed * 31 + 7);
        for (int i = 0; i < org.users.size(); i++) {
            SimOrganisation.User u = org.users.get(i);
            departments.put(u.id(), DEPARTMENTS[i % DEPARTMENTS.length]);
            leases.put(address(i), u.laptop());
            if (i % DEPARTMENTS.length == 4 && admins.size() < 2) {
                admins.add(u.id());
            }
        }
        int n = org.users.size();
        beaconing.add(org.users.get(5 % n).id());
        beaconing.add(org.users.get(17 % n).id());
        exfiltrator = org.users.get(9 % n).id();
        quarterEnd = org.users.get(11 % n).id();     // index 11 is in finance (11 % 5 == 1)
        for (int i = 0; i < n; i++) {
            normalDays(i);
        }
        for (SimOrganisation.Step s : traffic) {
            if (s instanceof SimOrganisation.RequestStep r
                    && r.labelled().scenario() == SimOrganisation.Scenario.A6_STOLEN_LAPTOP_AT_HOME) {
                stolenLaptop(index(r.labelled().userId()), r.at());
            }
        }
        for (String b : beaconing) {
            beacon(index(b));
        }
        exfil(index(exfiltrator));
        bigLegitDownload(index(quarterEnd));
        noise();
        seal();
        items.sort(Comparator.comparing(Item::at));
    }

    /** Telemetry for {@code org}, aligned with {@code traffic} (the same list given to {@code org.run}). */
    public static SimTelemetry of(SimOrganisation org, List<SimOrganisation.Step> traffic) {
        return new SimTelemetry(org, traffic);
    }

    /** Every item, in time order. */
    public List<Item> items() {
        return List.copyOf(items);
    }

    /** Department of each person (for peer groups; a real deployment reads it from the directory). */
    public Map<String, String> departments() {
        return Map.copyOf(departments);
    }

    /** Internal address of each laptop (the DHCP leases a collector uses to name the device behind an address). */
    public Map<String, String> leases() {
        return Map.copyOf(leases);
    }

    public List<String> admins() {
        return List.copyOf(admins);
    }

    /** Who the labelled attacks and false-positive checks are about. */
    public Map<Activity, Set<String>> cast() {
        Map<Activity, Set<String>> m = new LinkedHashMap<>();
        m.put(Activity.A8_BEACONING, Set.copyOf(beaconing));
        m.put(Activity.A9_CLOUD_EXFIL, Set.of(exfiltrator));
        m.put(Activity.L5_BIG_LEGIT_DOWNLOAD, Set.of(quarterEnd));
        m.put(Activity.L6_ADMIN_POWERSHELL, Set.copyOf(admins));
        return m;
    }

    // ---- generation -----------------------------------------------------------------------------------------

    private static String address(int i) {
        return "10.20." + (i / 250) + "." + (i % 250 + 1);
    }

    private int index(String userId) {
        for (int i = 0; i < org.users.size(); i++) {
            if (org.users.get(i).id().equals(userId)) {
                return i;
            }
        }
        throw new IllegalArgumentException("unknown user " + userId);
    }

    private static Instant at(int day, int minute) {
        return SimOrganisation.DAY_ZERO.plus(Duration.ofDays(day)).plus(Duration.ofMinutes(minute));
    }

    private void normalDays(int i) {
        SimOrganisation.User u = org.users.get(i);
        boolean admin = admins.contains(u.id());
        for (int day = 0; day < 8; day++) {
            int start = u.habit1();
            int length = Math.max(60, u.habit2() - u.habit1());
            int apps = 5 + rnd.nextInt(4);
            for (int k = 0; k < apps; k++) {
                Instant t = at(day, start + rnd.nextInt(length)).plusSeconds(rnd.nextInt(60));
                String app = APPS[rnd.nextInt(APPS.length)];
                endpoint(i, t, Activity.NORMAL, "process.start", "process", app, "parent", "explorer.exe",
                        "cmd", app);
            }
            if (admin) {
                Instant t = at(day, start + 15);
                endpoint(i, t, Activity.L6_ADMIN_POWERSHELL, "process.start", "process", "powershell.exe",
                        "parent", "explorer.exe", "cmd", "powershell.exe -File C:/ops/backup.ps1", "signer", "corp-it");
            }
            int flows = 4 + rnd.nextInt(4);
            for (int k = 0; k < flows; k++) {
                Instant t = at(day, start + rnd.nextInt(length)).plusSeconds(rnd.nextInt(60));
                firewall(t, Activity.NORMAL, u.id(), "allow", address(i), 49152 + rnd.nextInt(16000),
                        SAAS_ADDRESSES.get(rnd.nextInt(SAAS_ADDRESSES.size())), 443, 2_000 + rnd.nextInt(200_000), "out-web");
            }
            int files = 2 + rnd.nextInt(4);
            for (int k = 0; k < files; k++) {
                Instant t = at(day, start + rnd.nextInt(length)).plusSeconds(rnd.nextInt(60));
                cloud(t, Activity.NORMAL, u.id(), i, "file.download", "/" + departments.get(u.id()) + "/doc-" + rnd.nextInt(500)
                        + ".docx", 200_000 + rnd.nextInt(4_000_000), "none");
            }
        }
    }

    private void stolenLaptop(int i, Instant login) {
        Activity a = Activity.A6_STOLEN_LAPTOP_AT_HOME;
        endpoint(i, login.minus(Duration.ofMinutes(3)), a, "process.start", "process", "powershell.exe",
                "parent", "explorer.exe", "cmd", "powershell.exe -nop -w hidden -enc SQBFAFgA");
        endpoint(i, login.plus(Duration.ofMinutes(1)), a, "usb.mount", "vendor", "generic-mass-storage",
                "serial", "usb-" + rnd.nextInt(100_000));
        for (int k = 0; k < 6; k++) {
            endpoint(i, login.plus(Duration.ofMinutes(2 + k)), a, "file.read", "path", "//fs01/finance/batch-" + k,
                    "count", Integer.toString(40 + rnd.nextInt(20)));
        }
        endpoint(i, login.plus(Duration.ofMinutes(9)), a, "process.start", "process", "7z.exe", "parent",
                "powershell.exe", "cmd", "7z.exe a e:/f.7z //fs01/finance");
    }

    private void beacon(int i) {
        SimOrganisation.User u = org.users.get(i);
        Instant start = at(3, u.habit1() + 30);
        endpoint(i, start, Activity.A8_BEACONING, "process.start", "process", "updsvc.exe", "parent", "winword.exe",
                "cmd", "updsvc.exe /q");
        for (int k = 1; k <= 120; k++) {
            Instant t = start.plusSeconds(60L * k);
            endpoint(i, t, Activity.A8_BEACONING, "network.connect", "process", "updsvc.exe", "dst", C2_ADDRESS,
                    "dport", Integer.toString(C2_PORT));
            firewall(t, Activity.A8_BEACONING, u.id(), "allow", address(i), 50_000 + k, C2_ADDRESS, C2_PORT,
                    300 + rnd.nextInt(100), "out-any");
        }
    }

    private void exfil(int i) {
        SimOrganisation.User u = org.users.get(i);
        Instant start = at(5, u.habit1() + 60);
        for (int k = 0; k < 120; k++) {
            cloud(start.plusSeconds(30L * k), Activity.A9_CLOUD_EXFIL, u.id(), i, "file.download",
                    "/" + departments.get(u.id()) + "/archive-" + k + ".zip", 25_000_000 + rnd.nextInt(10_000_000), "none");
        }
        cloud(start.plus(Duration.ofMinutes(61)), Activity.A9_CLOUD_EXFIL, u.id(), i, "share.create",
                "/" + departments.get(u.id()) + "/archive", 0, EXTERNAL_SHARE);
    }

    private void bigLegitDownload(int i) {
        SimOrganisation.User u = org.users.get(i);
        // Day 7: no A6 that day, so the false-positive check is not mixed with an attack on the same person.
        Instant start = at(7, u.habit1() + 30);
        for (int k = 0; k < 60; k++) {
            cloud(start.plusSeconds(45L * k), Activity.L5_BIG_LEGIT_DOWNLOAD, u.id(), i, "file.download",
                    "/finance/quarter-close-" + k + ".xlsx", 8_000_000 + rnd.nextInt(4_000_000), "none");
        }
    }

    private void noise() {
        Instant t = at(2, 600);
        items.add(new RawLine(Source.FIREWALL, t, "<134>1 garbage", Activity.NOISE, ""));
        items.add(new RawLine(Source.FIREWALL, t.plusSeconds(1), "", Activity.NOISE, ""));
        items.add(new RawLine(Source.FIREWALL, t.plusSeconds(2),
                "<134>1 2026-11-04T10:00:02Z fw01 dwfw - - - action=allow src=10.20.0.1 dport=notanumber",
                Activity.NOISE, ""));
        items.add(new RawLine(Source.CLOUD, t.plusSeconds(3), "{\"time\":", Activity.NOISE, ""));
    }

    private void firewall(Instant t, Activity a, String userId, String action, String src, int sport, String dst,
                          int dport, int bytes, String rule) {
        String line = "<134>1 " + t + " " + FIREWALL_HOST + " dwfw " + (++fwSeq) + " - - action=" + action
                + " src=" + src + " sport=" + sport + " dst=" + dst + " dport=" + dport + " proto=tcp bytes=" + bytes
                + " rule=" + rule;
        items.add(new RawLine(Source.FIREWALL, t, line, a, userId));
    }

    private void cloud(Instant t, Activity a, String userId, int i, String op, String object, long bytes, String share) {
        String line = "{\"time\":\"" + t + "\",\"app\":\"drive\",\"user\":\"" + userId + "\",\"ip\":\"" + address(i)
                + "\",\"op\":\"" + op + "\",\"object\":\"" + object + "\",\"bytes\":" + bytes + ",\"share\":\""
                + share + "\"}";
        items.add(new RawLine(Source.CLOUD, t, line, a, userId));
    }

    /** Queues one endpoint event; {@code kv} are name, value pairs. */
    private void endpoint(int i, Instant t, Activity a, String type, String... kv) {
        SimOrganisation.User u = org.users.get(i);
        StringBuilder b = new StringBuilder("{\"ts\":\"").append(t).append("\",\"device\":\"").append(u.laptop())
                .append("\",\"user\":\"").append(u.id()).append("\",\"type\":\"").append(type).append('"');
        for (int k = 0; k + 1 < kv.length; k += 2) {
            b.append(",\"").append(kv[k]).append("\":\"").append(kv[k + 1]).append('"');
        }
        b.append('}');
        pending.computeIfAbsent(u.laptop(), d -> new TreeMap<>())
                .computeIfAbsent(t.truncatedTo(ChronoUnit.HOURS), h -> new ArrayList<>())
                .add(new String[]{t.toString(), b.toString(), a.name()});
    }

    /** Seals each device's hour of events into one signed batch, numbered from 1 per device. */
    private void seal() {
        for (int i = 0; i < org.users.size(); i++) {
            SimOrganisation.User u = org.users.get(i);
            TreeMap<Instant, List<String[]>> hours = pending.get(u.laptop());
            if (hours == null) {
                continue;
            }
            long batch = 0;
            for (Map.Entry<Instant, List<String[]>> h : hours.entrySet()) {
                List<String[]> lines = new ArrayList<>(h.getValue());
                lines.sort(Comparator.comparing(x -> x[0]));
                StringBuilder body = new StringBuilder();
                List<Activity> labels = new ArrayList<>();
                for (String[] l : lines) {
                    body.append(l[1]).append('\n');
                    labels.add(Activity.valueOf(l[2]));
                }
                Instant sealedAt = h.getKey().plus(Duration.ofHours(1));
                String text = body.toString();
                byte[] msg = SignedMessages.endpointTelemetry(u.laptop(), ++batch, sealedAt, Digests.sha256Hex(text));
                items.add(new EndpointBatch(u.laptop(), "agent-" + u.laptop(), batch, sealedAt, text,
                        Ed25519.sign(u.laptopKey().getPrivate(), msg), labels, u.id()));
            }
        }
    }
}

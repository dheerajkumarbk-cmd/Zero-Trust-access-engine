package dev.dwarpal.lab.scenarios;

import dev.dwarpal.lab.LabWorld;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.sim.SimRequests;
import dev.dwarpal.sim.SimTelemetry;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

/**
 * Builds the raw material of each scenario at the lab's current scenario time: Dwarpal requests for the engine,
 * firewall lines, cloud lines and endpoint events. Everything goes in through the real collectors and the real
 * engine ({@link LabWorld#inject}); nothing here writes an alert or touches the chain.
 *
 * <p>The shapes mirror {@code SimOrganisation} and {@code SimTelemetry} (the same lines, fields and numbers), moved
 * to start "now" instead of on a fixed day of the script.
 */
final class Plans {

    /** What a builder returns. */
    record Plan(List<Object> items, List<String> cast, List<String> devices, Instant from, Instant until) {
        Plan {
            items = List.copyOf(items);
            cast = List.copyOf(cast);
            devices = List.copyOf(devices);
        }
    }

    /** Who launches what, when, with which randomness. */
    record Context(LabWorld world, Instant start, long launch, Random rnd, SimOrganisation.User target,
                   int targetIndex, java.util.Set<String> keepOut) {
    }

    private static final String[][] CITIES = {
            {"mumbai", "19.07", "72.88"}, {"delhi", "28.61", "77.21"}, {"bengaluru", "12.97", "77.59"},
            {"chennai", "13.08", "80.27"}, {"hyderabad", "17.38", "78.48"}, {"pune", "18.52", "73.86"},
            {"kolkata", "22.57", "88.36"}};
    private static final String[] ISPS = {"AS24560", "AS55836", "AS45609", "AS9829", "AS17488"};
    private static final String[] APPS = {"code.exe", "chrome.exe", "teams.exe", "outlook.exe", "git.exe", "excel.exe"};

    private Plans() {
    }

    // ---- the login attacks (the engine decides; part A's rules and UEBA read the audit trail) ---------------

    static Plan a1(Context c) {
        SimOrganisation.User u = c.target();
        List<Object> items = new ArrayList<>();
        items.add(request(c, "a1", login(c, u, c.start(), "a1").device("pc-" + (100 + c.rnd().nextInt(899)))
                .unsignedPosture().network("45.155.205." + (1 + c.rnd().nextInt(249)), "AS49505", "RU", 55.75, 37.62)));
        return plan(c, items, List.of());
    }

    static Plan a2(Context c) {
        SimOrganisation.User u = c.target();
        List<Object> items = new ArrayList<>();
        items.add(request(c, "a2", login(c, u, c.start(), "a2").unsignedPosture()
                .network("3.6.82." + (1 + c.rnd().nextInt(249)), SimOrganisation.CLOUD_ASN, "IN", 19.07, 72.88)));
        return plan(c, items, List.of());
    }

    static Plan a3(Context c) {
        SimOrganisation.User u = c.target();
        String otherIsp = ISPS[(indexOf(ISPS, u.isp()) + 1) % ISPS.length];
        List<Object> items = new ArrayList<>();
        items.add(request(c, "a3", login(c, u, c.start(), "a3").unsignedPosture()
                .network("100.70.1." + (1 + c.rnd().nextInt(249)), otherIsp, "IN", lat(u), lon(u))));
        return plan(c, items, List.of());
    }

    /** A normal login, then twenty minutes later the same account from London. */
    static Plan a4(Context c) {
        SimOrganisation.User u = c.target();
        List<Object> items = new ArrayList<>();
        items.add(request(c, "a4n", login(c, u, c.start(), "a4n")));
        items.add(request(c, "a4", login(c, u, c.start().plus(Duration.ofMinutes(20)), "a4").unsignedPosture()
                .network("81.2.69.160", "AS20712", "GB", 51.507, -0.128)));
        return plan(c, items, List.of());
    }

    static Plan a5(Context c) {
        SimOrganisation.User u = c.target();
        List<Object> items = new ArrayList<>();
        items.add(request(c, "a5", login(c, u, c.start(), "a5").unsignedPosture()
                .network(SimOrganisation.TOR_EXIT, "AS9009", "DE", 50.11, 8.68)));
        return plan(c, items, List.of());
    }

    /** Fifteen failed logins for fifteen different accounts from one address, then a login from it for this account. */
    static Plan a7(Context c) {
        SimOrganisation.User u = c.target();
        List<Object> items = new ArrayList<>();
        for (int k = 0; k < 15; k++) {
            items.add(new SimOrganisation.FailureStep("victim" + k, SimOrganisation.SPRAY_IP,
                    c.start().plusSeconds(k)));
        }
        items.add(request(c, "a7", login(c, u, c.start().plus(Duration.ofMinutes(2)), "a7").unsignedPosture()
                .network(SimOrganisation.SPRAY_IP, "AS64511", "IN", 28.61, 77.21)));
        return plan(c, items, List.of());
    }

    // ---- the telemetry scenarios --------------------------------------------------------------------------

    /**
     * A6: the stolen laptop is used from the owner's home network (the engine allows it, its known blind spot): an
     * encoded PowerShell three minutes earlier, a USB drive, finance files read, an archive made.
     */
    static Plan a6(Context c) {
        SimOrganisation.User u = c.target();
        Instant login = c.start().plus(Duration.ofMinutes(4));
        Endpoint ep = new Endpoint(c, u);
        ep.add(login.minus(Duration.ofMinutes(3)), "process.start", "process", "powershell.exe", "parent",
                "explorer.exe", "cmd", "powershell.exe -nop -w hidden -enc SQBFAFgA");
        ep.add(login.plus(Duration.ofMinutes(1)), "usb.mount", "vendor", "generic-mass-storage", "serial",
                "usb-" + (10_000 + c.rnd().nextInt(80_000)));
        for (int k = 0; k < 6; k++) {
            ep.add(login.plus(Duration.ofMinutes(2 + k)), "file.read", "path", "//fs01/finance/batch-" + k, "count",
                    Integer.toString(40 + c.rnd().nextInt(20)));
        }
        ep.add(login.plus(Duration.ofMinutes(9)), "process.start", "process", "7z.exe", "parent", "powershell.exe",
                "cmd", "7z.exe a e:/f.7z //fs01/finance");
        List<Object> items = new ArrayList<>();
        // the thief also has the owner's security key (it was in the laptop bag), so the second factor is satisfied
        items.add(request(c, "a6", login(c, u, login, "a6")
                .authenticated(dev.dwarpal.domain.AuthMethod.WEBAUTHN, Duration.ofSeconds(30))));
        items.addAll(ep.batches());
        return plan(c, items, List.of(u.laptop()));
    }

    /** A8: a program started by a document connects to one rare address every minute for two hours. */
    static Plan a8(Context c) {
        SimOrganisation.User u = c.target();
        Instant s = c.start().plus(Duration.ofMinutes(1));
        Endpoint ep = new Endpoint(c, u);
        List<Object> items = new ArrayList<>();
        ep.add(s, "process.start", "process", "updsvc.exe", "parent", "winword.exe", "cmd", "updsvc.exe /q");
        for (int k = 1; k <= 120; k++) {
            Instant t = s.plusSeconds(60L * k);
            ep.add(t, "network.connect", "process", "updsvc.exe", "dst", SimTelemetry.C2_ADDRESS, "dport",
                    Integer.toString(SimTelemetry.C2_PORT));
            items.add(firewall(c, t, u, 50_000 + k, SimTelemetry.C2_ADDRESS, SimTelemetry.C2_PORT,
                    300 + c.rnd().nextInt(100), "out-any"));
        }
        items.addAll(ep.batches());
        return plan(c, items, List.of(u.laptop()));
    }

    /** A9: forty times the usual download volume in an hour, then a folder shared with an outside address. */
    static Plan a9(Context c) {
        SimOrganisation.User u = c.target();
        List<Object> items = new ArrayList<>();
        String dept = department(c, u);
        for (int k = 0; k < 120; k++) {
            items.add(cloud(c, c.start().plusSeconds(30L * k), u, "file.download", "/" + dept + "/archive-" + k
                    + ".zip", 25_000_000L + c.rnd().nextInt(10_000_000), "none"));
        }
        items.add(cloud(c, c.start().plus(Duration.ofMinutes(61)), u, "share.create", "/" + dept + "/archive", 0,
                SimTelemetry.EXTERNAL_SHARE));
        return plan(c, items, List.of(u.laptop()));
    }

    /** L5: a finance person downloads a lot at quarter end; everything stays inside. */
    static Plan l5(Context c) {
        SimOrganisation.User u = c.target();
        List<Object> items = new ArrayList<>();
        for (int k = 0; k < 60; k++) {
            items.add(cloud(c, c.start().plusSeconds(45L * k), u, "file.download", "/finance/quarter-close-" + k
                    + ".xlsx", 8_000_000L + c.rnd().nextInt(4_000_000), "none"));
        }
        return plan(c, items, List.of(u.laptop()));
    }

    /** L6: an IT administrator runs the signed backup script, as every working day. */
    static Plan l6(Context c) {
        SimOrganisation.User u = c.target();
        Endpoint ep = new Endpoint(c, u);
        ep.add(c.start().plus(Duration.ofMinutes(1)), "process.start", "process", "powershell.exe", "parent",
                "explorer.exe", "cmd", "powershell.exe -File C:/ops/backup.ps1", "signer", "corp-it");
        return plan(c, new ArrayList<>(ep.batches()), List.of(u.laptop()));
    }

    /** A quiet day, compressed into six hours: people who carry no earlier suspicion work, browse and download a little. */
    static Plan quiet(Context c) {
        List<Object> items = new ArrayList<>();
        List<SimOrganisation.User> users = c.world().org.users;
        for (int i = 0; i < users.size(); i++) {
            SimOrganisation.User u = users.get(i);
            if (c.keepOut().contains(u.id())) {
                continue;
            }
            Context cu = new Context(c.world(), c.start(), c.launch(), c.rnd(), u, i, c.keepOut());
            Endpoint ep = new Endpoint(cu, u);
            for (int k = 0; k < 5; k++) {
                String app = APPS[c.rnd().nextInt(APPS.length)];
                ep.add(c.start().plus(Duration.ofMinutes(2 + c.rnd().nextInt(350))), "process.start", "process", app,
                        "parent", "explorer.exe", "cmd", app);
            }
            items.addAll(ep.batches());
            for (int k = 0; k < 4; k++) {
                items.add(firewall(cu, c.start().plus(Duration.ofMinutes(2 + c.rnd().nextInt(350))), u,
                        49_152 + c.rnd().nextInt(16_000),
                        SimTelemetry.SAAS_ADDRESSES.get(c.rnd().nextInt(SimTelemetry.SAAS_ADDRESSES.size())), 443,
                        2_000 + c.rnd().nextInt(200_000), "out-web"));
            }
            for (int k = 0; k < 2; k++) {
                items.add(cloud(cu, c.start().plus(Duration.ofMinutes(2 + c.rnd().nextInt(350))), u, "file.download",
                        "/" + department(cu, u) + "/doc-" + c.rnd().nextInt(500) + ".docx",
                        200_000L + c.rnd().nextInt(4_000_000), "none"));
            }
        }
        return new Plan(items, List.of(), List.of(), c.start(), c.start().plus(Duration.ofHours(6)));
    }

    // ---- pieces --------------------------------------------------------------------------------------------

    private static Plan plan(Context c, List<Object> items, List<String> devices) {
        Instant last = c.start();
        for (Object o : items) {
            Instant at = o instanceof SimOrganisation.Step s ? s.at() : ((SimTelemetry.Item) o).at();
            if (at.isAfter(last)) {
                last = at;
            }
        }
        return new Plan(items, List.of(c.target().id()), devices, c.start(), last);
    }

    private static SimOrganisation.RequestStep request(Context c, String tag, SimRequests.Builder b) {
        return new SimOrganisation.RequestStep(new SimOrganisation.Labelled(b.build(), scenarioOf(tag),
                c.target().id()));
    }

    private static SimOrganisation.Scenario scenarioOf(String tag) {
        return switch (tag) {
            case "a1" -> SimOrganisation.Scenario.A1_FOREIGN_STUFFING;
            case "a2" -> SimOrganisation.Scenario.A2_DOMESTIC_CLOUD;
            case "a3" -> SimOrganisation.Scenario.A3_SAME_CITY_PROXY;
            case "a4" -> SimOrganisation.Scenario.A4_IMPOSSIBLE_TRAVEL;
            case "a5" -> SimOrganisation.Scenario.A5_TOR;
            case "a6" -> SimOrganisation.Scenario.A6_STOLEN_LAPTOP_AT_HOME;
            case "a7" -> SimOrganisation.Scenario.A7_SPRAY_IP;
            default -> SimOrganisation.Scenario.L1_NORMAL;
        };
    }

    /** A legitimate login of {@code u} from the usual place on the usual laptop, as {@code SimOrganisation} builds it. */
    private static SimRequests.Builder login(Context c, SimOrganisation.User u, Instant t, String tag) {
        String id = "lab" + c.launch() + "-" + u.id() + "-" + tag;
        return SimRequests.request().id(id).at(t).subject(u.id()).device(u.laptop())
                .postureSignedBy(u.laptopKey(), "agent-" + u.laptop())
                .network(u.kind() == SimOrganisation.Kind.ROAMER ? "100.100.7." + Math.floorMod(id.hashCode(), 250)
                                : "100.64." + u.id().substring(1) + ".10", u.isp(), "IN", lat(u), lon(u));
    }

    private static double lat(SimOrganisation.User u) {
        return Double.parseDouble(CITIES[u.city()][1]);
    }

    private static double lon(SimOrganisation.User u) {
        return Double.parseDouble(CITIES[u.city()][2]);
    }

    private static int indexOf(String[] a, String v) {
        for (int i = 0; i < a.length; i++) {
            if (a[i].equals(v)) {
                return i;
            }
        }
        return 0;
    }

    private static String department(Context c, SimOrganisation.User u) {
        return c.world().telemetry.departments().get(u.id());
    }

    /** The address the DHCP lease table gives this person's laptop. */
    static String address(int i) {
        return "10.20." + (i / 250) + "." + (i % 250 + 1);
    }

    private static SimTelemetry.RawLine firewall(Context c, Instant t, SimOrganisation.User u, int sport, String dst,
                                                 int dport, int bytes, String rule) {
        String line = "<134>1 " + t.truncatedTo(ChronoUnit.SECONDS) + " " + SimTelemetry.FIREWALL_HOST + " dwfw "
                + (c.launch() * 100_000 + Math.abs(sport)) + " - - action=allow src=" + address(c.targetIndex())
                + " sport=" + sport + " dst=" + dst + " dport=" + dport + " proto=tcp bytes=" + bytes + " rule=" + rule;
        return new SimTelemetry.RawLine(SimTelemetry.Source.FIREWALL, t, line, SimTelemetry.Activity.NORMAL, u.id());
    }

    private static SimTelemetry.RawLine cloud(Context c, Instant t, SimOrganisation.User u, String op, String object,
                                              long bytes, String share) {
        String line = "{\"time\":\"" + t.truncatedTo(ChronoUnit.SECONDS) + "\",\"app\":\"drive\",\"user\":\"" + u.id()
                + "\",\"ip\":\"" + address(c.targetIndex()) + "\",\"op\":\"" + op + "\",\"object\":\"" + object
                + "\",\"bytes\":" + bytes + ",\"share\":\"" + share + "\"}";
        return new SimTelemetry.RawLine(SimTelemetry.Source.CLOUD, t, line, SimTelemetry.Activity.NORMAL, u.id());
    }

    /**
     * One device's endpoint events, sealed into batches of at most an hour. The lab seals a batch a minute after
     * its last event (a real agent flushes every few minutes); {@code LabWorld} numbers and signs it with the
     * device's own agent key when it runs.
     */
    private static final class Endpoint {
        private final SimOrganisation.User u;
        private final TreeMap<Instant, String> lines = new TreeMap<>();
        private int serial;

        Endpoint(Context c, SimOrganisation.User u) {
            this.u = u;
        }

        void add(Instant t, String type, String... kv) {
            StringBuilder b = new StringBuilder("{\"ts\":\"").append(t.truncatedTo(ChronoUnit.SECONDS))
                    .append("\",\"device\":\"").append(u.laptop()).append("\",\"user\":\"").append(u.id())
                    .append("\",\"type\":\"").append(type).append('"');
            for (int k = 0; k + 1 < kv.length; k += 2) {
                b.append(",\"").append(kv[k]).append("\":\"").append(esc(kv[k + 1])).append('"');
            }
            // the key breaks ties between events of one second, so none is lost
            lines.put(t.truncatedTo(ChronoUnit.SECONDS).plusNanos(++serial), b.append('}').toString());
        }

        List<SimTelemetry.EndpointBatch> batches() {
            List<SimTelemetry.EndpointBatch> out = new ArrayList<>();
            Instant chunkStart = null;
            StringBuilder body = new StringBuilder();
            Instant last = null;
            for (Map.Entry<Instant, String> e : lines.entrySet()) {
                if (chunkStart != null && e.getKey().isAfter(chunkStart.plus(Duration.ofMinutes(59)))) {
                    out.add(seal(body, last));
                    body = new StringBuilder();
                    chunkStart = null;
                }
                if (chunkStart == null) {
                    chunkStart = e.getKey();
                }
                body.append(e.getValue()).append('\n');
                last = e.getKey();
            }
            if (last != null) {
                out.add(seal(body, last));
            }
            return out;
        }

        private SimTelemetry.EndpointBatch seal(StringBuilder body, Instant last) {
            Instant at = last.truncatedTo(ChronoUnit.SECONDS).plus(Duration.ofMinutes(1));
            return new SimTelemetry.EndpointBatch(u.laptop(), "agent-" + u.laptop(), 0, at, body.toString(), "unsigned",
                    List.of(), u.id());
        }

        private static String esc(String s) {
            return s.replace("\\", "\\\\").replace("\"", "\\\"");
        }
    }
}

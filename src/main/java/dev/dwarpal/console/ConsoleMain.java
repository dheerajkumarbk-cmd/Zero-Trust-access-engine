package dev.dwarpal.console;

import dev.dwarpal.directory.Database;
import dev.dwarpal.directory.DbSettings;
import dev.dwarpal.directory.Directory;
import dev.dwarpal.directory.DirectoryException;
import dev.dwarpal.directory.Migrator;
import dev.dwarpal.directory.PostgresDirectory;
import dev.dwarpal.edge.DevPki;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.lab.LabConfig;
import dev.dwarpal.lab.LabRunner;
import dev.dwarpal.lab.LabWorld;
import dev.dwarpal.soar.Analyst;

import javax.net.ssl.SSLContext;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The lab with its browser console: starts the simulated SOC ({@link LabWorld}), the scenario clock ({@link LabRunner})
 * and the console server, prints the address and the demo logins, and runs until stopped. Loopback only.
 *
 * <pre>
 *   ConsoleMain [--dir lab] [--seed 7] [--users 60] [--speed 60] [--warmup-days 3] [--port 8443] [--soc-port 0]
 *               [--rotate-days 7] [--db on|off|test]
 * </pre>
 * {@code --port} is the console's (the page you open); {@code --soc-port} is the SOC API's, which only the console
 * server calls (0 picks a free port). {@code --db on} (the default) keeps the people in the directory database, which
 * must be set up, migrated and running; {@code --db test} uses the throw-away test database; {@code --db off} runs
 * without a database, with the people from the people file only (the tests that do not need one).
 */
public final class ConsoleMain {

    private ConsoleMain() {
    }

    public static void main(String[] args) throws Exception {
        run(args, System.out);
    }

    static void run(String[] args, PrintStream out) throws Exception {
        // bound how long a client may take to send its request head (JDK server, read once when it first loads)
        System.setProperty("sun.net.httpserver.maxReqTime", "30");
        int consolePort = 8443;
        int socPort = 0;
        int rotateDays = 7;
        String dbMode = "on";
        String trailMode = "on";
        LabConfig config = LabConfig.defaults(Path.of("lab"));
        for (int i = 0; i < args.length; i += 2) {
            if (i + 1 >= args.length) {
                throw new IllegalArgumentException("missing value for " + args[i]);
            }
            String v = args[i + 1];
            switch (args[i]) {
                case "--dir" -> config = new LabConfig(Path.of(v), config.seed(), config.users(), config.speed(),
                        config.warmupDays(), config.port());
                case "--seed" -> config = new LabConfig(config.dir(), Long.parseLong(v), config.users(), config.speed(),
                        config.warmupDays(), config.port());
                case "--users" -> config = config.withUsers(Integer.parseInt(v));
                case "--speed" -> config = config.withSpeed(Double.parseDouble(v));
                case "--warmup-days" -> config = config.withWarmupDays(Integer.parseInt(v));
                case "--port" -> consolePort = Integer.parseInt(v);
                case "--soc-port" -> socPort = Integer.parseInt(v);
                case "--rotate-days" -> rotateDays = Integer.parseInt(v);
                case "--db" -> dbMode = v;
                case "--trail" -> trailMode = v;
                default -> throw new IllegalArgumentException("unknown option " + args[i]);
            }
        }
        config = config.withPort(socPort);
        out.println("Dwarpal lab console: preparing certificates and the simulated organisation (" + config.users()
                + " users, seed " + config.seed() + ")...");
        List<ConsoleAuth.Enrolment> people = DemoPeople.loadOrCreate(config.dir());
        // the directory decides who exists and with which roles; the people file only keeps their first secrets
        Directory directory = openDirectory(dbMode);
        if (directory == null) {
            out.println("Directory database: switched off for this run (--db off); the people come from the people file.");
        } else {
            DirectoryPeople.Result joined = DirectoryPeople.sync(directory, people, Clock.systemUTC());
            people = joined.people();
            Directory.Health health = directory.health();
            out.println("Directory: " + health.server() + ", tables at version " + health.schemaVersion() + ", "
                    + people.size() + " people can sign in (" + joined.movedIn() + " moved in by this start, "
                    + joined.skipped() + " not enrolled).");
        }
        ConsoleSettings settings = ConsoleSettings.defaults();
        // the session owns the world and the scenario clock and can rebuild both (reset to day zero)
        try (dev.dwarpal.lab.scenarios.LabSession session = dev.dwarpal.lab.scenarios.LabSession.open(config)) {
            LabWorld world = session.world();
            out.println("Warm-up done to " + world.now() + ", " + world.rankedNow().size() + " alerts already ranked.");
            DevPki pki = world.pki;
            SSLContext tls = TlsContexts.create(pki.keyStore("console"), pki.password(), pki.trustStore(), pki.password());
            Set<String> analysts = LabWorld.ANALYSTS.stream().map(Analyst::id).collect(Collectors.toSet());
            LabHandle lab = new LabHandle() {
                @Override
                public LabWorld world() {
                    return session.world();
                }

                @Override
                public LabRunner runner() {
                    return session.runner();
                }
            };
            SocChannel channel = new DelegatedSocChannel(pki, () -> lab.world().socApiUrl(),
                    () -> lab.world().delegationIssuer(), analysts, Duration.ofSeconds(10));
            ConsoleAuth auth = new ConsoleAuth(people, Clock.systemUTC(), settings.passwordIterations(),
                    settings.pinIterations(), config.dir().resolve("console").resolve("credentials.txt"),
                    Duration.ofDays(rotateDays));
            // what people and administrators do on the console is kept on disk, checked at every start
            ConsoleTrail trail = switch (trailMode) {
                case "on" -> ConsoleTrail.open(config.dir().resolve("console").resolve("trail"), Clock.systemUTC());
                case "off" -> null;
                default -> throw new IllegalArgumentException("--trail takes on or off");
            };
            out.println(trail == null ? "Audit trail on disk: switched off for this run (--trail off); records go into the lab's chain only."
                    : "Audit trail on disk: " + trail.records() + " records from earlier runs, checked and intact ("
                    + trail.dir().toAbsolutePath() + ").");
            ConsoleServer.Builder b = ConsoleServer.builder(lab, channel, new LabVerdictSigner(lab), auth, tls)
                    .settings(settings)
                    .passkeyLock(Duration.ofMinutes(15), Duration.ofMinutes(5))
                    .address(new InetSocketAddress(InetAddress.getLoopbackAddress(), consolePort));
            b.module(new dev.dwarpal.console.lab.LabModule(session));
            b.module(new dev.dwarpal.console.lab.GuideModule());
            b.module(new dev.dwarpal.console.admin.AdminModule(new dev.dwarpal.console.admin.LabAdminServices(session, directory)));
            if (trail != null) {
                b.trail(trail);
            }
            try (trail; ConsoleServer server = b.build().start()) {
                out.println();
                out.println("Console: " + server.url() + "   (loopback only)");
                out.println("Your browser must trust the lab's certificate authority: "
                        + config.dir().resolve("pki").resolve("ca.pem").toAbsolutePath());
                out.println("Demo logins (password and security-key PIN), kept in "
                        + config.dir().resolve("console").resolve("people.txt").toAbsolutePath() + ":");
                for (ConsoleAuth.Enrolment e : people) {
                    out.println(auth.hasOwnSecrets(e.person().id())
                            ? "  " + e.person().id() + "  " + e.person().roles() + "  has chosen their own password and PIN"
                            : "  " + e.person().id() + "  " + e.person().roles() + "  password " + e.password() + "  PIN "
                            + e.pin());
                }
                out.println("Scenario speed " + config.speed() + "x. Stop with Ctrl+C.");
                Thread main = Thread.currentThread();
                Runtime.getRuntime().addShutdownHook(new Thread(main::interrupt));
                try {
                    while (true) {
                        Thread.sleep(Duration.ofSeconds(10));
                        session.runner().failure().ifPresent(f -> out.println("The scenario clock stopped: " + f));
                    }
                } catch (InterruptedException e) {
                    out.println("Stopping.");
                }
            }
        }
    }

    /**
     * The directory database for this run, or null when switched off. It signs in as the low-privilege app user only
     * (the migrator's password is never read here) and refuses to start on tables of the wrong version.
     */
    static Directory openDirectory(String mode) {
        DbSettings.Target target = switch (mode) {
            case "off" -> null;
            case "on" -> DbSettings.Target.LAB;
            case "test" -> DbSettings.Target.TEST;
            default -> throw new IllegalArgumentException("--db takes on, off or test");
        };
        if (target == null) {
            return null;
        }
        try {
            Directory directory = new PostgresDirectory(new Database(DbSettings.fromEnvironment().app(target)));
            int version = directory.health().schemaVersion();
            if (version != Migrator.expectedVersion()) {
                throw new IllegalStateException("The directory tables are at version " + version + " but this build needs "
                        + Migrator.expectedVersion() + ". Build them first: java -cp target/classes;<postgresql jar> "
                        + "dev.dwarpal.directory.MigrateMain");
            }
            return directory;
        } catch (DirectoryException e) {
            throw new IllegalStateException("The directory database is not available (" + e.getMessage()
                    + "). Start the PostgreSQL service, check db/local.properties, or run with --db off.", e);
        }
    }
}

package dev.dwarpal.console;

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
 * </pre>
 * {@code --port} is the console's (the page you open); {@code --soc-port} is the SOC API's, which only the console
 * server calls (0 picks a free port).
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
                default -> throw new IllegalArgumentException("unknown option " + args[i]);
            }
        }
        config = config.withPort(socPort);
        out.println("Dwarpal lab console: preparing certificates and the simulated organisation (" + config.users()
                + " users, seed " + config.seed() + ")...");
        List<ConsoleAuth.Enrolment> people = DemoPeople.loadOrCreate(config.dir());
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
                    settings.pinIterations());
            ConsoleServer.Builder b = ConsoleServer.builder(lab, channel, new LabVerdictSigner(lab), auth, tls)
                    .settings(settings)
                    .address(new InetSocketAddress(InetAddress.getLoopbackAddress(), consolePort));
            b.module(new dev.dwarpal.console.lab.LabModule(session));
            b.module(new dev.dwarpal.console.lab.GuideModule());
            b.module(new dev.dwarpal.console.admin.AdminModule(new dev.dwarpal.console.admin.LabAdminServices(session)));
            try (ConsoleServer server = b.build().start()) {
                out.println();
                out.println("Console: " + server.url() + "   (loopback only)");
                out.println("Your browser must trust the lab's certificate authority: "
                        + config.dir().resolve("pki").resolve("ca.pem").toAbsolutePath());
                out.println("Demo logins (password and security-key PIN), kept in "
                        + config.dir().resolve("console").resolve("people.txt").toAbsolutePath() + ":");
                for (ConsoleAuth.Enrolment e : people) {
                    out.println("  " + e.person().id() + "  " + e.person().roles() + "  password " + e.password() + "  PIN "
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
}

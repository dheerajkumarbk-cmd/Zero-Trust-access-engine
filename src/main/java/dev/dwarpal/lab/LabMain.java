package dev.dwarpal.lab;

import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;

/**
 * {@code dwarpal lab}: starts the whole system on the simulated organisation and keeps it running until the
 * process is stopped. Free to run: nothing leaves the machine and the SOC API listens on the loopback address only.
 *
 * <pre>
 *   LabMain [--dir lab] [--seed 7] [--users 60] [--speed 60] [--warmup-days 3] [--port 8443]
 * </pre>
 */
public final class LabMain {

    private LabMain() {
    }

    public static void main(String[] args) throws Exception {
        CrashLog.install(CrashLog.logDirFor(args));
        run(args, System.out);
    }

    static void run(String[] args, PrintStream out) throws Exception {
        LabConfig config = parse(args);
        out.println("Dwarpal lab: preparing certificates and the simulated organisation (" + config.users() + " users, seed "
                + config.seed() + ")...");
        try (LabWorld world = LabWorld.create(config); LabRunner runner = new LabRunner(world, config.speed())) {
            LabWorld.Progress warm = world.warmUp(config.warmupDays());
            out.println("Warm-up done: " + warm.itemsRun() + " events to " + warm.now() + ", " + world.rankedNow().size()
                    + " alerts already ranked.");
            runner.start();
            out.println("SOC API (mutual TLS): " + world.socApiUrl());
            out.println("Certificates and secrets: " + config.dir().resolve("pki").toAbsolutePath());
            out.println("Scenario speed " + config.speed() + "x. Stop with Ctrl+C.");
            Thread main = Thread.currentThread();
            Runtime.getRuntime().addShutdownHook(new Thread(main::interrupt));
            try {
                while (true) {
                    Thread.sleep(Duration.ofSeconds(10));
                    runner.failure().ifPresent(f -> out.println("The scenario clock stopped: " + f));
                    if (runner.state() == LabRunner.State.FINISHED) {
                        out.println("The scenario script has ended; the lab stays up for review.");
                        Thread.sleep(Long.MAX_VALUE);
                    }
                }
            } catch (InterruptedException e) {
                out.println("Stopping.");
            }
        }
    }

    static LabConfig parse(String[] args) {
        LabConfig c = LabConfig.defaults(Path.of("lab"));
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (i + 1 >= args.length) {
                throw new IllegalArgumentException("missing value for " + a + "; options: " + Arrays.toString(
                        new String[]{"--dir", "--seed", "--users", "--speed", "--warmup-days", "--port"}));
            }
            String v = args[++i];
            switch (a) {
                case "--dir" -> c = new LabConfig(Path.of(v), c.seed(), c.users(), c.speed(), c.warmupDays(), c.port());
                case "--seed" -> c = new LabConfig(c.dir(), Long.parseLong(v), c.users(), c.speed(), c.warmupDays(), c.port());
                case "--users" -> c = c.withUsers(Integer.parseInt(v));
                case "--speed" -> c = c.withSpeed(Double.parseDouble(v));
                case "--warmup-days" -> c = c.withWarmupDays(Integer.parseInt(v));
                case "--port" -> c = c.withPort(Integer.parseInt(v));
                default -> throw new IllegalArgumentException("unknown option " + a);
            }
        }
        return c;
    }
}

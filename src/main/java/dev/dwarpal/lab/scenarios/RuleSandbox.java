package dev.dwarpal.lab.scenarios;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.audit.InMemoryAuditSink;
import dev.dwarpal.lab.LabWorld;
import dev.dwarpal.response.Play;
import dev.dwarpal.response.ResponseSettings;
import dev.dwarpal.siem.platform.CorrelationEngine;
import dev.dwarpal.siem.platform.RuleBook;
import dev.dwarpal.soar.PlaybookCompiler;
import dev.dwarpal.soar.PlaybookException;
import dev.dwarpal.soar.PlaybookSet;
import dev.dwarpal.soar.RuleCatalogue;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.SecurityEvent;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.function.LongSupplier;

/**
 * The "write your own rule" sandbox. A learner submits a correlation rule (the safe YAML of
 * {@link RuleBook}) or a playbook (the safe YAML of {@link PlaybookCompiler}), reads the linter's findings and runs a
 * valid rule against recorded events.
 *
 * <p><b>What keeps it safe.</b> A rule runs only in a throwaway engine, over a copy of the lab's recorded records held
 * in a private in-memory sink; its alerts go to a list in this class and nowhere else: not into the live
 * {@code CaseManager}, not into the chain, not to a playbook. Nothing a learner writes is ever installed. Input is
 * small ({@link #MAX_YAML} bytes, {@link #MAX_RULES} rules), only one run happens at a time, a person may run once
 * every {@link #MIN_GAP_MILLIS} ms, a run reads at most {@link #MAX_RECORDS} records and stops after
 * {@link #BUDGET}. YAML is read with the loaders' own safe settings (no objects, no aliases, no duplicate keys).
 * Linter messages name places and rule ids, never the submitted text.
 */
public final class RuleSandbox {

    public static final int MAX_YAML = 16 * 1024;
    public static final int MAX_RULES = 20;
    public static final int MAX_RECORDS = 100_000;
    public static final int MAX_SAMPLE = 25;
    public static final long MIN_GAP_MILLIS = 2_000;
    public static final Duration BUDGET = Duration.ofSeconds(8);

    private static final Map<String, SecurityEvent.Provenance> DATASETS = Map.of(
            "firewall", SecurityEvent.Provenance.COLLECTED, "endpoint", SecurityEvent.Provenance.SIGNED_SENSOR,
            "cloud", SecurityEvent.Provenance.COLLECTED);

    /** One linter finding. */
    public record Finding(String level, String where, String message) {
    }

    /** What a rule did over the recorded events: its matches, firings and the first alerts it would have raised. */
    public record RuleStat(String rule, long matched, long fired, long suppressed) {
    }

    /** An alert the learner's rule would have raised (never raised for real). */
    public record Sample(String rule, String severity, Instant at, List<String> entities, List<Long> evidence,
                         String summary) {
        public Sample {
            entities = List.copyOf(entities);
            evidence = List.copyOf(evidence);
        }
    }

    /** The outcome of a rule submission. */
    public record RuleResult(boolean accepted, List<Finding> findings, int rules, boolean ran, long eventsRead,
                             long alerts, List<RuleStat> stats, List<Sample> sample, List<String> silent, String note) {
        public RuleResult {
            findings = List.copyOf(findings);
            stats = List.copyOf(stats);
            sample = List.copyOf(sample);
            silent = List.copyOf(silent);
        }
    }

    /** What a playbook step would do, in plain words, for a rule of the learner's file. */
    public record Plan(String rule, List<String> steps) {
        public Plan {
            steps = List.copyOf(steps);
        }
    }

    /** The outcome of a playbook submission. */
    public record PlaybookResult(boolean accepted, List<Finding> findings, List<Plan> plans, String note) {
        public PlaybookResult {
            findings = List.copyOf(findings);
            plans = List.copyOf(plans);
        }
    }

    final Semaphore running = new Semaphore(1);
    private final LongSupplier wall;
    private final Map<String, Long> lastRun = new HashMap<>();

    public RuleSandbox() {
        this(System::currentTimeMillis);
    }

    RuleSandbox(LongSupplier wallMillis) {
        this.wall = wallMillis;
    }

    /** Lints a rule file; with {@code run} also replays the lab's recorded events through it. */
    public RuleResult rule(LabWorld world, String person, String yaml, boolean run) {
        String refused = tooBig(yaml);
        if (refused != null) {
            return failedRule(refused);
        }
        RuleBook book;
        try {
            book = RuleBook.load(yaml, DATASETS);
        } catch (RuleBook.RuleLoadException e) {
            List<Finding> f = new ArrayList<>();
            f.add(new Finding("ERROR", "<file>", e.getMessage()));
            e.findings().forEach(x -> f.add(new Finding(x.level().name(), x.rule(), x.message())));
            return new RuleResult(false, f, 0, false, 0, 0, List.of(), List.of(), List.of(), "Refused: nothing ran.");
        }
        List<Finding> findings = new ArrayList<>();
        book.warnings().forEach(x -> findings.add(new Finding(x.level().name(), x.rule(), x.message())));
        if (book.rules().size() > MAX_RULES) {
            findings.add(new Finding("ERROR", "<file>", "the sandbox takes at most " + MAX_RULES + " rules"));
            return new RuleResult(false, findings, book.rules().size(), false, 0, 0, List.of(), List.of(), List.of(),
                    "Refused: nothing ran.");
        }
        CorrelationEngine engine;
        List<Alert> raised = new ArrayList<>();
        try {
            engine = new CorrelationEngine(book, raised::add,
                    CorrelationEngine.Settings.defaults());
        } catch (IllegalArgumentException cannotFire) {
            findings.add(new Finding("ERROR", "<file>", cannotFire.getMessage()));
            return new RuleResult(false, findings, book.rules().size(), false, 0, 0, List.of(), List.of(), List.of(),
                    "Refused: nothing ran.");
        }
        if (!run) {
            return new RuleResult(true, findings, book.rules().size(), false, 0, 0, List.of(), List.of(), List.of(),
                    "The rule file is valid. Run it to see what it would have caught.");
        }
        if (!running.tryAcquire()) {
            return new RuleResult(true, findings, book.rules().size(), false, 0, 0, List.of(), List.of(), List.of(),
                    "Another run is in progress; try again in a moment.");
        }
        try {
            long now = wall.getAsLong();
            synchronized (lastRun) {
                Long last = lastRun.get(person);
                if (last != null && now - last < MIN_GAP_MILLIS) {
                    return new RuleResult(true, findings, book.rules().size(), false, 0, 0, List.of(), List.of(),
                            List.of(), "One run every " + MIN_GAP_MILLIS / 1000 + " seconds; try again.");
                }
                lastRun.put(person, now);
                if (lastRun.size() > 1_000) {
                    lastRun.clear();
                }
            }
            return replay(world, book, engine, raised, findings);
        } finally {
            running.release();
        }
    }

    private RuleResult replay(LabWorld world, RuleBook book, CorrelationEngine engine, List<Alert> raised,
                              List<Finding> findings) {
        // a private copy of the recorded records: the learner's engine never touches the live chain
        InMemoryAuditSink copy = new InMemoryAuditSink();
        long copied = 0;
        long seq = 0;
        boolean cut = false;
        while (copied < MAX_RECORDS) {
            List<AuditRecord> batch = world.org.sink.after(seq, 5_000);
            if (batch.isEmpty()) {
                break;
            }
            for (AuditRecord r : batch) {
                if (copied >= MAX_RECORDS) {
                    cut = true;
                    break;
                }
                copy.write(r);
                copied++;
                seq = r.sequence();
            }
        }
        AuditCursor cursor = AuditCursor.fromStart(copy, world.org.auditKey);
        long deadline = System.nanoTime() + BUDGET.toNanos();
        long read = 0;
        String note = cut ? "Recorded events cut at " + MAX_RECORDS + " records." : "All recorded events replayed.";
        while (true) {
            CorrelationEngine.Report rep = engine.run(cursor, 2_000);
            read += rep.read();
            if (rep.problem().isPresent()) {
                note = "The recorded copy could not be read to the end.";
                break;
            }
            if (rep.read() == 0) {
                break;
            }
            if (System.nanoTime() > deadline) {
                note = "Stopped after " + BUDGET.toSeconds() + " seconds: the rule is too expensive for the sandbox.";
                break;
            }
        }
        List<RuleStat> stats = new ArrayList<>();
        engine.statistics().forEach((id, s) -> stats.add(new RuleStat(id, s[0], s[1], s[2])));
        List<Sample> sample = new ArrayList<>();
        for (Alert a : raised) {
            if (sample.size() >= MAX_SAMPLE) {
                break;
            }
            sample.add(new Sample(a.rule(), a.severity().name(), a.raisedAt(), a.entities().stream()
                    .map(e -> e.kind().name().toLowerCase(java.util.Locale.ROOT) + " " + e.id()).toList(),
                    a.evidence().size() > 5 ? a.evidence().subList(0, 5) : a.evidence(), a.summary()));
        }
        return new RuleResult(true, findings, book.rules().size(), true, read, raised.size(), stats, sample,
                engine.silentRules(), note + " Nothing was raised for real: no case, no chain record, no playbook.");
    }

    /** Lints a playbook file against the shipped rules and the guard rails; never installs it. */
    public PlaybookResult playbook(String yaml) {
        String refused = tooBig(yaml);
        if (refused != null) {
            return new PlaybookResult(false, List.of(new Finding("ERROR", "<file>", refused)), List.of(),
                    "Refused: nothing was compiled.");
        }
        // lenient: a learner sees warnings too, but only errors refuse the file
        PlaybookCompiler compiler = new PlaybookCompiler(RuleCatalogue.reference(), ResponseSettings.defaults(),
                Set.of("ticket", "chat"), false);
        PlaybookCompiler.Compilation c;
        try {
            c = compiler.compile(yaml);
        } catch (PlaybookException e) {
            return new PlaybookResult(false, List.of(new Finding("ERROR", "<file>", e.getMessage())), List.of(),
                    "Refused: nothing was compiled.");
        }
        List<Finding> findings = c.findings().stream()
                .map(f -> new Finding(f.severity().name(), f.where(), f.message())).toList();
        List<Plan> plans = new ArrayList<>();
        c.set().ifPresent(set -> plans.addAll(describe(set, yaml)));
        return new PlaybookResult(c.accepted(), findings, plans, c.accepted()
                ? "The playbook compiles. A real change needs two administrators' signatures; the sandbox installs nothing."
                : "Refused by the linter. Nothing was compiled.");
    }

    private static List<Plan> describe(PlaybookSet set, String yaml) {
        List<Plan> out = new ArrayList<>();
        for (Map.Entry<String, Play> e : set.plays().entrySet()) {
            // only the rules the learner's file names: the others got the default play
            if (!yaml.contains(e.getKey())) {
                continue;
            }
            List<String> steps = new ArrayList<>();
            for (Play.Step s : e.getValue().steps()) {
                steps.add(words(s));
            }
            PlaybookSet.Extras x = set.extrasFor(e.getKey());
            if (x.isolate()) {
                steps.add("isolate the device at its sensor (counts as done only when the device's own key confirms)");
            }
            x.notifications().forEach(n -> steps.add("notify through " + n.connector() + " (" + n.template().key() + ")"));
            out.add(new Plan(e.getKey(), steps));
            if (out.size() >= 60) {
                break;
            }
        }
        return out;
    }

    private static String words(Play.Step s) {
        return switch (s) {
            case Play.Revoke r -> "revoke the " + kind(r.target()) + "'s sessions";
            case Play.Deny d -> "deny the " + kind(d.target()) + " for " + d.duration();
            case Play.Watch w -> "watch the " + kind(w.target()) + " (odds of attack multiplied by "
                    + String.format(java.util.Locale.ROOT, "%.0f", Math.exp(w.logLr())) + ", fading with half-life "
                    + w.halfLife() + ")";
        };
    }

    private static String kind(Entity.Kind k) {
        return k.name().toLowerCase(java.util.Locale.ROOT);
    }

    private static String tooBig(String yaml) {
        if (yaml == null || yaml.isBlank()) {
            return "nothing was submitted";
        }
        if (yaml.length() > MAX_YAML || yaml.getBytes(StandardCharsets.UTF_8).length > MAX_YAML) {
            return "the sandbox takes at most " + MAX_YAML + " bytes";
        }
        return null;
    }

    private static RuleResult failedRule(String why) {
        return new RuleResult(false, List.of(new Finding("ERROR", "<file>", why)), 0, false, 0, 0, List.of(), List.of(),
                List.of(), "Refused: nothing ran.");
    }
}

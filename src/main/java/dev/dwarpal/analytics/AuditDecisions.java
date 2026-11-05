package dev.dwarpal.analytics;

import dev.dwarpal.audit.AuditCursor;
import dev.dwarpal.audit.AuditEvent;
import dev.dwarpal.decision.Outcome;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Reads the engine's {@code ACCESS_DECISION} records back from the audit trail through an
 * {@link AuditCursor}, for analyses of what was actually decided (outcome mix, the posteriors a
 * sensitivity sweep re-decides). Reading only: the cursor never writes.
 *
 * <p>Fail closed: reading stops at the first break in the chain and the result says where; only
 * records before the break are used. A record whose fields do not parse (a forged record read without
 * the key, or a format change) is counted and skipped, never guessed at. Only the fields an analysis
 * needs are kept: no address, device or reasons.
 */
public final class AuditDecisions {

    public static final String TYPE = "ACCESS_DECISION";
    public static final int MAX_ENTRIES = 1_000_000;

    public record Entry(long sequence, String subject, String resource, String action, Outcome outcome,
                        String policy, double posterior) {
    }

    public record Result(List<Entry> entries, long verifiedThrough, long otherEvents, long malformed,
                         Optional<String> problem, boolean truncated) {
        public Result {
            entries = List.copyOf(entries);
            Objects.requireNonNull(problem, "problem");
        }

        public List<Double> posteriors() {
            return entries.stream().map(Entry::posterior).toList();
        }

        public DataSource source(String description) {
            return new DataSource(DataSource.Kind.AUDIT_TRAIL, description + (problem.isPresent()
                    ? ", chain broken after sequence " + verifiedThrough : ", verified through sequence " + verifiedThrough),
                    -1, 0, 0, entries.size());
        }
    }

    private AuditDecisions() {
    }

    /** Reads at most {@code max} decisions from {@code cursor}'s position on. */
    public static Result read(AuditCursor cursor, int max) {
        Objects.requireNonNull(cursor, "cursor");
        if (max < 1 || max > MAX_ENTRIES) {
            throw new IllegalArgumentException("max must be between 1 and " + MAX_ENTRIES);
        }
        List<Entry> out = new ArrayList<>();
        long last = cursor.checkpoint().sequence();
        long other = 0;
        long bad = 0;
        Optional<String> problem = Optional.empty();
        boolean truncated = false;
        while (true) {
            AuditCursor.Batch batch = cursor.next(Math.min(10_000, max - out.size() + 1));
            for (AuditEvent e : batch.events()) {
                last = e.sequence();
                if (!TYPE.equals(e.type())) {
                    other++;
                    continue;
                }
                Optional<Entry> parsed = parse(e);
                if (parsed.isEmpty()) {
                    bad++;
                } else if (out.size() < max) {
                    out.add(parsed.get());
                } else {
                    truncated = true;
                }
            }
            if (batch.problem().isPresent()) {
                problem = batch.problem();
                break;
            }
            if (batch.events().isEmpty() || truncated) {
                break;
            }
        }
        return new Result(out, last, other, bad, problem, truncated);
    }

    static Optional<Entry> parse(AuditEvent e) {
        try {
            String subject = e.field("subject").orElseThrow();
            String resource = e.field("resource").orElseThrow();
            String action = e.field("action").orElseThrow();
            Outcome outcome = Outcome.valueOf(e.field("outcome").orElseThrow());
            String policy = e.field("policy").orElseThrow();
            double p = Double.parseDouble(e.field("pAttack").orElseThrow());
            if (!(p >= 0 && p <= 1)) {
                return Optional.empty();
            }
            dev.dwarpal.domain.Validate.id(subject, "subject");
            dev.dwarpal.domain.Validate.id(resource, "resource");
            dev.dwarpal.domain.Validate.id(action, "action");
            dev.dwarpal.domain.Validate.id(policy, "policy");
            return Optional.of(new Entry(e.sequence(), subject, resource, action, outcome, policy, p));
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }
}

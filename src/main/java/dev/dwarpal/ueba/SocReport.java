package dev.dwarpal.ueba;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

import dev.dwarpal.analytics.DataSource;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.soc.EntityRisk;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.Verdict;

/**
 * The daily SOC report, in text for people and JSON for the console: alerts by priority, the riskiest entities,
 * mean time to verdict, the false-positive rate per rule, and MITRE coverage. Its first line is always the data
 * source and its caveat, so a number never travels without them.
 */
public final class SocReport {

    public static final int MAX_ALERTS = 1_000_000;
    public static final int MAX_VERDICTS = 1_000_000;
    public static final int TOP = 10;

    /** One verdict as the case book recorded it. */
    public record VerdictRecord(String alertId, String rule, Instant raisedAt, Instant decidedAt,
                                Verdict.Outcome outcome) {
        public VerdictRecord {
            Validate.id(alertId, "alertId");
            Validate.id(rule, "rule");
            Objects.requireNonNull(raisedAt, "raisedAt");
            Objects.requireNonNull(decidedAt, "decidedAt");
            Objects.requireNonNull(outcome, "outcome");
            if (decidedAt.isBefore(raisedAt)) {
                throw new IllegalArgumentException("a verdict cannot come before its alert");
            }
        }
    }

    /** False positives of one rule: {@code fp} of {@code decided}, with the Laplace estimate (fp+1)/(n+2). */
    public record RuleRate(String rule, long decided, long falsePositives) {
        public double estimate() {
            return (falsePositives + 1.0) / (decided + 2.0);
        }
    }

    private final DataSource source;
    private final LocalDate day;
    private final Map<Priority, Long> byPriority;
    private final long notActionable;
    private final List<EntityRisk.RiskView> top;
    private final long verdicts;
    private final Duration meanTimeToVerdict;
    private final List<RuleRate> rates;
    private final MitreCoverage coverage;

    private SocReport(DataSource source, LocalDate day, Map<Priority, Long> byPriority, long notActionable,
                      List<EntityRisk.RiskView> top, long verdicts, Duration meanTimeToVerdict, List<RuleRate> rates,
                      MitreCoverage coverage) {
        this.source = source;
        this.day = day;
        this.byPriority = Map.copyOf(byPriority);
        this.notActionable = notActionable;
        this.top = List.copyOf(top);
        this.verdicts = verdicts;
        this.meanTimeToVerdict = meanTimeToVerdict;
        this.rates = List.copyOf(rates);
        this.coverage = coverage;
    }

    /**
     * The report for one UTC day: alerts raised that day, verdicts given that day, risk at the end of the day.
     */
    public static SocReport daily(DataSource source, LocalDate day, List<RankedAlert> alerts, EntityRisk risk,
                                  List<VerdictRecord> verdicts, TechniqueMap techniques) {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(day, "day");
        Objects.requireNonNull(risk, "risk");
        Objects.requireNonNull(techniques, "techniques");
        if (alerts.size() > MAX_ALERTS || verdicts.size() > MAX_VERDICTS) {
            throw new IllegalArgumentException("at most " + MAX_ALERTS + " alerts and " + MAX_VERDICTS + " verdicts");
        }
        Instant from = day.atStartOfDay(ZoneOffset.UTC).toInstant();
        Instant to = from.plus(Duration.ofDays(1));
        Map<Priority, Long> byPriority = new EnumMap<>(Priority.class);
        for (Priority p : Priority.values()) {
            byPriority.put(p, 0L);
        }
        long notActionable = 0;
        List<RankedAlert> today = new ArrayList<>();
        for (RankedAlert r : alerts) {
            Instant t = r.alert().raisedAt();
            if (!t.isBefore(from) && t.isBefore(to)) {
                today.add(r);
                byPriority.merge(r.priority(), 1L, Long::sum);
                if (!r.actionable()) {
                    notActionable++;
                }
            }
        }
        long n = 0;
        long totalMillis = 0;
        Map<String, long[]> perRule = new TreeMap<>();
        for (VerdictRecord v : verdicts) {
            if (v.decidedAt().isBefore(from) || !v.decidedAt().isBefore(to)) {
                continue;
            }
            n++;
            totalMillis += Duration.between(v.raisedAt(), v.decidedAt()).toMillis();
            long[] c = perRule.computeIfAbsent(v.rule(), r -> new long[2]);
            c[0]++;
            if (v.outcome() == Verdict.Outcome.FALSE_POSITIVE) {
                c[1]++;
            }
        }
        List<RuleRate> rates = new ArrayList<>();
        perRule.forEach((r, c) -> rates.add(new RuleRate(r, c[0], c[1])));
        Duration mttv = n == 0 ? null : Duration.ofMillis(totalMillis / n);
        return new SocReport(source, day, byPriority, notActionable, risk.top(TOP, to), n, mttv, rates,
                MitreCoverage.of(techniques, today));
    }

    public Map<Priority, Long> byPriority() {
        return byPriority;
    }

    public List<EntityRisk.RiskView> top() {
        return top;
    }

    public List<RuleRate> rates() {
        return rates;
    }

    public MitreCoverage coverage() {
        return coverage;
    }

    public String text() {
        String nl = System.lineSeparator();
        StringBuilder b = new StringBuilder();
        b.append(source.statement()).append(nl);
        b.append("Dwarpal daily SOC report for ").append(day).append(" (UTC)").append(nl).append(nl);
        b.append("Alerts by priority:");
        for (Priority p : Priority.values()) {
            b.append(' ').append(p).append('=').append(byPriority.get(p));
        }
        b.append(nl).append("  of which ").append(notActionable)
                .append(" backed only by collected evidence (no destructive action)").append(nl).append(nl);
        b.append("Top risky entities at the end of the day:").append(nl);
        if (top.isEmpty()) {
            b.append("  none").append(nl);
        }
        for (EntityRisk.RiskView v : top) {
            b.append(String.format(Locale.ROOT, "  %-8s %-20s %5.1f %-8s %s%n", v.entity().kind(), v.entity().id(),
                    v.score(), v.level(), v.contributions().isEmpty() ? "" : v.contributions().get(0).reason()));
        }
        b.append(nl).append("Verdicts: ").append(verdicts);
        b.append(meanTimeToVerdict == null ? ", mean time to verdict: no verdicts"
                : ", mean time to verdict: " + meanTimeToVerdict.toMinutes() + " min");
        b.append(nl).append("False positives per rule (fp of decided, Laplace estimate (fp+1)/(n+2)):").append(nl);
        if (rates.isEmpty()) {
            b.append("  none").append(nl);
        }
        for (RuleRate r : rates) {
            b.append(String.format(Locale.ROOT, "  %-28s %d of %d  (%.2f)%n", r.rule(), r.falsePositives(), r.decided(),
                    r.estimate()));
        }
        b.append(nl).append(coverage.text());
        return b.toString();
    }

    public String json() {
        JsonOut j = new JsonOut();
        j.open('{').name("dataSource").open('{').field("kind", source.kind().name())
                .field("description", source.description()).field("statement", source.statement()).close('}');
        j.field("day", day.toString());
        j.name("alertsByPriority").open('{');
        for (Priority p : Priority.values()) {
            j.field(p.name(), byPriority.get(p));
        }
        j.close('}').field("notActionable", notActionable);
        j.name("topEntities").open('[');
        for (EntityRisk.RiskView v : top) {
            j.open('{').field("kind", v.entity().kind().name()).field("id", v.entity().id()).field("score", v.score())
                    .field("level", v.level().name()).name("contributions").open('[');
            for (EntityRisk.Contribution c : v.contributions()) {
                j.open('{').field("source", c.source()).field("weight", c.weight()).field("at", c.at().toString())
                        .field("reason", c.reason()).close('}');
            }
            j.close(']').close('}');
        }
        j.close(']').field("verdicts", verdicts);
        j.name("meanTimeToVerdictMinutes");
        if (meanTimeToVerdict == null) {
            j.value("none");
        } else {
            j.value(meanTimeToVerdict.toMinutes());
        }
        j.name("falsePositivesPerRule").open('[');
        for (RuleRate r : rates) {
            j.open('{').field("rule", r.rule()).field("decided", r.decided()).field("falsePositives", r.falsePositives())
                    .field("laplaceEstimate", r.estimate()).close('}');
        }
        j.close(']').name("mitre");
        coverage.json(j);
        j.close('}');
        return j.toString();
    }
}

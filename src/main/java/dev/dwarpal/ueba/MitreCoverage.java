package dev.dwarpal.ueba;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;

import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.Technique;
import dev.dwarpal.soc.Techniques;

/**
 * Which of the techniques Dwarpal knows ({@link Techniques#all()}) have at least one rule or detector, and which
 * were seen in a set of ranked alerts. "Covered" means "a rule exists that points to it", not "it would be caught":
 * the report says so.
 */
public final class MitreCoverage {

    /** One technique: the rules that point to it and how many of the given alerts did. */
    public record Line(Technique technique, List<String> rules, long observed) {
        public Line {
            rules = List.copyOf(rules);
        }

        public boolean covered() {
            return !rules.isEmpty();
        }
    }

    private final List<Line> lines;

    private MitreCoverage(List<Line> lines) {
        this.lines = List.copyOf(lines);
    }

    public static MitreCoverage of(TechniqueMap map, Collection<RankedAlert> alerts) {
        Objects.requireNonNull(map, "map");
        Objects.requireNonNull(alerts, "alerts");
        Map<String, Long> seen = new LinkedHashMap<>();
        for (RankedAlert r : alerts) {
            for (Technique t : r.techniques()) {
                seen.merge(t.id(), 1L, Long::sum);
            }
        }
        List<Line> lines = new ArrayList<>();
        for (Technique t : Techniques.all()) {
            TreeSet<String> rules = new TreeSet<>();
            for (Map.Entry<String, List<Technique>> e : map.rules().entrySet()) {
                if (e.getValue().contains(t)) {
                    rules.add(e.getKey());
                }
            }
            lines.add(new Line(t, new ArrayList<>(rules), seen.getOrDefault(t.id(), 0L)));
        }
        return new MitreCoverage(lines);
    }

    public List<Line> lines() {
        return lines;
    }

    public long covered() {
        return lines.stream().filter(Line::covered).count();
    }

    public int total() {
        return lines.size();
    }

    public String text() {
        StringBuilder b = new StringBuilder();
        b.append(String.format(Locale.ROOT, "MITRE ATT&CK coverage: %d of %d known techniques have a rule or detector%n",
                covered(), total()));
        b.append("(a rule pointing to a technique is not proof that every use of it is caught)").append(System.lineSeparator());
        for (Line l : lines) {
            b.append(String.format(Locale.ROOT, "  %-9s %-22s %-45s %s, seen %d%n", l.technique().id(),
                    l.technique().tactic(), l.technique().name(), l.covered() ? String.join(" ", l.rules()) : "NOT COVERED",
                    l.observed()));
        }
        return b.toString();
    }

    void json(JsonOut j) {
        j.open('{').field("covered", covered()).field("total", total()).name("techniques").open('[');
        for (Line l : lines) {
            j.open('{').field("id", l.technique().id()).field("name", l.technique().name())
                    .field("tactic", l.technique().tactic()).name("rules").open('[');
            l.rules().forEach(j::value);
            j.close(']').field("observed", l.observed()).close('}');
        }
        j.close(']').close('}');
    }

    public String json() {
        JsonOut j = new JsonOut();
        json(j);
        return j.toString();
    }
}

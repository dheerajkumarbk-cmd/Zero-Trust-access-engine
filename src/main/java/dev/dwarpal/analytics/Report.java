package dev.dwarpal.analytics;

import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.OptionalDouble;

/**
 * A finished analysis, printable as plain text or JSON. Both forms start with the {@link DataSource}
 * statement, so the numbers cannot be quoted without their data and caveat.
 *
 * <p>Everything in a report is text the analysis chose to put there: identifiers (subject, resource,
 * policy), counts and rates. Request ids, addresses, device ids and evidence are never added by the
 * analyses in this package. Labels and values are sanitised and cut, so a hostile identifier cannot
 * forge a line of the text report; JSON is escaped by {@link JsonWriter}. Sizes are bounded.
 */
public final class Report {

    public static final int MAX_SECTIONS = 64;
    public static final int MAX_LINES = 2_000;
    public static final int MAX_LABEL = 160;
    public static final int MAX_VALUE = 400;

    /** One line: a label and either text, a number, or "n/a" (a rate with no data). */
    public record Line(String label, String text, OptionalDouble number) {
        public Line {
            label = Sanitize.text(Objects.requireNonNull(label, "label"), MAX_LABEL);
            text = Sanitize.text(Objects.requireNonNull(text, "text"), MAX_VALUE);
            Objects.requireNonNull(number, "number");
            if (number.isPresent() && !Double.isFinite(number.getAsDouble())) {
                throw new IllegalArgumentException("a report number must be finite");
            }
        }
    }

    public record Section(String name, List<Line> lines) {
        public Section {
            name = Sanitize.text(Objects.requireNonNull(name, "name"), MAX_LABEL);
            lines = List.copyOf(lines);
        }
    }

    private final String title;
    private final DataSource source;
    private final List<Section> sections;

    private Report(String title, DataSource source, List<Section> sections) {
        this.title = title;
        this.source = source;
        this.sections = List.copyOf(sections);
    }

    public static Builder builder(String title, DataSource source) {
        return new Builder(title, source);
    }

    public String title() {
        return title;
    }

    public DataSource source() {
        return source;
    }

    public List<Section> sections() {
        return sections;
    }

    /** The line with this label in this section, if any (for tests and callers). */
    public java.util.Optional<Line> line(String section, String label) {
        return sections.stream().filter(s -> s.name().equals(section)).flatMap(s -> s.lines().stream())
                .filter(l -> l.label().equals(label)).findFirst();
    }

    public String text() {
        StringBuilder sb = new StringBuilder(1024);
        sb.append(title).append('\n').append(source.statement()).append('\n');
        for (Section s : sections) {
            sb.append('\n').append("== ").append(s.name()).append(" ==").append('\n');
            for (Line l : s.lines()) {
                sb.append("  ").append(l.label()).append(": ").append(l.text()).append('\n');
            }
        }
        return sb.toString();
    }

    public String json() {
        JsonValue.JObject.Builder src = JsonValue.object()
                .put("kind", source.kind().name())
                .put("description", source.description())
                .put("seed", JsonValue.num(source.seed()))
                .put("users", JsonValue.num(source.users()))
                .put("days", JsonValue.num(source.days()))
                .put("requests", JsonValue.num(source.requests()))
                .put("statement", source.statement());
        List<JsonValue> secs = new ArrayList<>();
        for (Section s : sections) {
            List<JsonValue> lines = new ArrayList<>();
            for (Line l : s.lines()) {
                lines.add(JsonValue.object().put("label", l.label()).put("text", l.text())
                        .put("value", l.number().isPresent() ? new JsonValue.JNumber(number(l.number().getAsDouble()))
                                : JsonValue.nul())
                        .build());
            }
            secs.add(JsonValue.object().put("name", s.name()).put("lines", new JsonValue.JArray(lines)).build());
        }
        return JsonWriter.write(JsonValue.object().put("title", title).put("source", src.build())
                .put("sections", new JsonValue.JArray(secs)).build());
    }

    static String number(double d) {
        return String.format(Locale.ROOT, "%.6f", d);
    }

    public static final class Builder {
        private final String title;
        private final DataSource source;
        private final List<Section> sections = new ArrayList<>();
        private String current;
        private List<Line> lines;
        private int total;

        private Builder(String title, DataSource source) {
            this.title = Sanitize.text(Objects.requireNonNull(title, "title"), MAX_LABEL);
            this.source = Objects.requireNonNull(source, "source");
        }

        public Builder section(String name) {
            close();
            if (sections.size() >= MAX_SECTIONS) {
                throw new IllegalStateException("too many report sections");
            }
            current = name;
            lines = new ArrayList<>();
            return this;
        }

        public Builder text(String label, String text) {
            return add(new Line(label, text, OptionalDouble.empty()));
        }

        public Builder number(String label, double value) {
            if (!Double.isFinite(value)) {
                return text(label, "n/a");
            }
            return add(new Line(label, Report.number(value), OptionalDouble.of(value)));
        }

        /** A rate that may be undefined (no data in its denominator): printed as "n/a", JSON null. */
        public Builder rate(String label, OptionalDouble value) {
            return value.isPresent() ? number(label, value.getAsDouble()) : text(label, "n/a");
        }

        public Builder count(String label, long value) {
            return add(new Line(label, Long.toString(value), OptionalDouble.of(value)));
        }

        private Builder add(Line l) {
            if (lines == null) {
                throw new IllegalStateException("start a section first");
            }
            if (++total > MAX_LINES) {
                throw new IllegalStateException("too many report lines");
            }
            lines.add(l);
            return this;
        }

        private void close() {
            if (current != null) {
                sections.add(new Section(current, lines));
                current = null;
                lines = null;
            }
        }

        public Report build() {
            close();
            return new Report(title, source, sections);
        }
    }
}

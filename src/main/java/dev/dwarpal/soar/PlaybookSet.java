package dev.dwarpal.soar;

import dev.dwarpal.domain.Validate;
import dev.dwarpal.response.Play;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A compiled, linted playbook file: for each rule, part B's {@link Play} (what the guard-railed playbooks run) and
 * the extras part B does not know about (isolating devices at the sensor, notifying people through connectors).
 *
 * @param version  the file's own version label
 * @param sha256   SHA-256 of the exact file text (what the approvers signed)
 * @param plays    the play for every rule the file or the catalogue names
 * @param fallback the play for a rule the catalogue does not know (never destructive)
 * @param extras   isolation and notifications per rule; rules without extras are absent
 */
public record PlaybookSet(String version, String sha256, Map<String, Play> plays, Play fallback,
                          Map<String, Extras> extras) {

    /** The strongest watch a play may place on collected evidence alone: x10. */
    public static final double COLLECTED_MAX_LOG_LR = Math.log(10);
    /** The longest half-life of such a watch: one day. */
    public static final java.time.Duration COLLECTED_MAX_HALF_LIFE = java.time.Duration.ofDays(1);

    /** A notification: which connector, and which fixed template (playbook files never carry free text to send). */
    public record Notify(String connector, Template template) {
        public Notify {
            Validate.id(connector, "notify.connector");
            Objects.requireNonNull(template, "notify.template");
        }
    }

    /** The fixed messages a playbook can send. Their text is built from ids, never from alert payloads. */
    public enum Template {
        ACTION_TAKEN("action-taken"), DEVICE_ISOLATED("device-isolated"), NEEDS_SECOND_ANALYST("needs-second-analyst");

        private final String key;

        Template(String key) {
            this.key = key;
        }

        public String key() {
            return key;
        }

        static java.util.Optional<Template> of(String key) {
            for (Template t : values()) {
                if (t.key.equals(key)) {
                    return java.util.Optional.of(t);
                }
            }
            return java.util.Optional.empty();
        }
    }

    /**
     * @param isolate whether the devices the alert names are isolated at their sensor once the play has run in full
     * @param notifications notifications sent when the play runs (at most {@link PlaybookCompiler#MAX_NOTIFY})
     */
    public record Extras(boolean isolate, List<Notify> notifications) {
        public Extras {
            notifications = List.copyOf(notifications);
        }

        public static Extras none() {
            return new Extras(false, List.of());
        }
    }

    public PlaybookSet {
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(sha256, "sha256");
        plays = Map.copyOf(plays);
        Objects.requireNonNull(fallback, "fallback");
        extras = Map.copyOf(extras);
    }

    public Play playFor(String rule) {
        return plays.getOrDefault(rule, fallback);
    }

    public Extras extrasFor(String rule) {
        return extras.getOrDefault(rule, Extras.none());
    }

    /** The same set with every destructive step removed and watches capped: what runs on collected-only evidence. */
    public PlaybookSet watchOnly() {
        Map<String, Play> safe = new java.util.LinkedHashMap<>();
        plays.forEach((rule, play) -> safe.put(rule, watches(play)));
        Map<String, Extras> notifyOnly = new java.util.LinkedHashMap<>();
        extras.forEach((rule, x) -> notifyOnly.put(rule, new Extras(false, x.notifications())));
        return new PlaybookSet(version, sha256, safe, watches(fallback), notifyOnly);
    }

    /**
     * Watch-only steps: destructive steps removed, and each watch capped at {@link #COLLECTED_MAX_LOG_LR} with a
     * half-life of at most {@link #COLLECTED_MAX_HALF_LIFE}, because the person it names may only have been named
     * by a forged line (red-team finding F-R1).
     */
    private static Play watches(Play p) {
        return new Play(p.steps().stream().filter(s -> !s.destructive())
                .map(s -> s instanceof Play.Watch w ? new Play.Watch(w.target(), Math.min(w.logLr(), COLLECTED_MAX_LOG_LR),
                        w.halfLife().compareTo(COLLECTED_MAX_HALF_LIFE) > 0 ? COLLECTED_MAX_HALF_LIFE : w.halfLife()) : s)
                .toList());
    }
}

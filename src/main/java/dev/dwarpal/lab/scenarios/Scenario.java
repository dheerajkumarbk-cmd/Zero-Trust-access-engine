package dev.dwarpal.lab.scenarios;

import java.util.List;
import java.util.Objects;

/**
 * One scenario a learner can launch: what it is, what the attacker does, what a defender should see. The texts are
 * plain words for the screen; {@link #expects} is checked against a real lab by the tests, so the guide cannot
 * promise something the lab does not show.
 *
 * @param id         short stable name used in routes, for example {@code A8}
 * @param kind       attack, look-alike (looks alarming, harmless) or baseline (ordinary activity)
 * @param techniques MITRE ATT&amp;CK ids with names, for the screen
 * @param attacker   what the attacker (or the harmless user) does, in plain words; shown before the run
 * @param defender   what the defender should see afterwards
 * @param minutes    how much scenario time the scenario takes to play out
 * @param decisions  what the access engine decides for the scenario's login requests, in order (verified by tests)
 * @param ceiling    the most urgent priority any alert about the cast may reach (P1 to P4); verified by tests
 * @param expects    what the SOC really produces (verified by tests); empty when the queue stays quiet
 */
public record Scenario(String id, Kind kind, String title, List<String> techniques, String attacker, String defender,
                       int minutes, List<String> decisions, String ceiling, List<Expect> expects) {

    public enum Kind { ATTACK, LOOK_ALIKE, BASELINE }

    /**
     * An alert the scenario should produce for the cast person or device.
     *
     * @param rule       the rule id as it appears in the queue
     * @param priority   the priority the queue gives it (P1 to P4), or "P3 or lower" style bound in {@code atMost}
     * @param actionable whether a destructive response may act on it (verified evidence)
     * @param engine     which engine raises it: A (part A rules), D (correlation rules), E (UEBA)
     */
    public record Expect(String rule, String priority, boolean actionable, String engine) {
        public Expect {
            Objects.requireNonNull(rule, "rule");
            Objects.requireNonNull(priority, "priority");
            Objects.requireNonNull(engine, "engine");
        }
    }

    public Scenario {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(kind, "kind");
        techniques = List.copyOf(techniques);
        decisions = List.copyOf(decisions);
        expects = List.copyOf(expects);
    }
}

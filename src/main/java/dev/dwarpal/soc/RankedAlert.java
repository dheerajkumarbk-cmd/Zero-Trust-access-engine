package dev.dwarpal.soc;

import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * An alert with its place in the analyst's queue (part E ranks, part F shows).
 *
 * @param priority   P1 (look now) to P4 (look when there is time)
 * @param score      0 to 100, for ordering within a priority
 * @param techniques MITRE ATT&CK techniques the alert points to, at most 8, no duplicates
 * @param actionable whether the evidence includes anything beyond {@link SecurityEvent.Provenance#COLLECTED}
 *                   events, that is, whether a destructive playbook may act on it at all
 * @param reasons    why it got this priority, short sanitised lines, at most 8
 */
public record RankedAlert(Alert alert, Priority priority, double score, List<Technique> techniques,
                          boolean actionable, List<String> reasons) {

    public static final int MAX_TECHNIQUES = 8;
    public static final int MAX_REASONS = 8;
    public static final int MAX_REASON = 160;

    public RankedAlert {
        Objects.requireNonNull(alert, "alert");
        Objects.requireNonNull(priority, "priority");
        Validate.finite(score, "score");
        if (score < 0 || score > 100) {
            throw new IllegalArgumentException("score must be 0 to 100");
        }
        techniques = List.copyOf(techniques);
        if (techniques.size() > MAX_TECHNIQUES || techniques.stream().distinct().count() != techniques.size()) {
            throw new IllegalArgumentException("at most " + MAX_TECHNIQUES + " distinct techniques");
        }
        if (reasons.size() > MAX_REASONS) {
            throw new IllegalArgumentException("at most " + MAX_REASONS + " reasons");
        }
        List<String> clean = new ArrayList<>(reasons.size());
        for (String r : reasons) {
            String s = Sanitize.text(Objects.requireNonNull(r, "reason"), MAX_REASON);
            clean.add(s.length() > MAX_REASON ? s.substring(0, MAX_REASON) : s);
        }
        reasons = List.copyOf(clean);
    }
}

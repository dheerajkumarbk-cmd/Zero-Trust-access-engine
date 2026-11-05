package dev.dwarpal.soc;

import dev.dwarpal.domain.Sanitize;

import java.util.Objects;

/**
 * A MITRE ATT&CK technique or sub-technique, for example {@code T1110.003} (password spraying). Rules and
 * detectors tag their alerts with techniques so coverage can be measured and analysts share a vocabulary.
 *
 * @param id     {@code T} and four digits, optionally {@code .} and three digits
 * @param name   the technique's name, sanitised, at most 80 characters
 * @param tactic the ATT&CK tactic it serves, for example {@code credential-access}; lower case and dashes
 */
public record Technique(String id, String name, String tactic) {

    public Technique {
        Objects.requireNonNull(id, "technique.id");
        if (!validId(id)) {
            throw new IllegalArgumentException("technique ids look like T1110 or T1110.003");
        }
        String n = Sanitize.text(Objects.requireNonNull(name, "technique.name"), 80);
        name = n.length() > 80 ? n.substring(0, 80) : n;
        Objects.requireNonNull(tactic, "technique.tactic");
        if (tactic.isEmpty() || tactic.length() > 40 || !tactic.chars().allMatch(c -> (c >= 'a' && c <= 'z') || c == '-')) {
            throw new IllegalArgumentException("tactics are lower case with dashes");
        }
    }

    static boolean validId(String id) {
        if (id.length() != 5 && id.length() != 9) {
            return false;
        }
        if (id.charAt(0) != 'T' || !digits(id, 1, 5)) {
            return false;
        }
        return id.length() == 5 || (id.charAt(5) == '.' && digits(id, 6, 9));
    }

    private static boolean digits(String s, int from, int to) {
        for (int i = from; i < to; i++) {
            if (s.charAt(i) < '0' || s.charAt(i) > '9') {
                return false;
            }
        }
        return true;
    }
}

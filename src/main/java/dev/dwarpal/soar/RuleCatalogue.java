package dev.dwarpal.soar;

import dev.dwarpal.domain.Validate;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The detection rules playbooks may be written for, and what the linter must know about each: what kind of
 * evidence its alerts can rest on, and whether the person it names is the target of an attack rather than
 * the suspect. Supplied by the deployment from the rule engines (part A's rules in code, part D's rule files),
 * never by the playbook file itself.
 */
public final class RuleCatalogue {

    public static final int MAX_RULES = 2_000;

    /** What a rule's alerts can be supported by. */
    public enum Evidence {
        /** Only records Dwarpal wrote itself (keyed audit chain) or signed sensor batches. */
        VERIFIED,
        /** Sometimes verified, sometimes only collected: decided per alert at run time. */
        MIXED,
        /**
         * Only events from sources that cannot prove who sent them (syslog, exported files). Anyone on the network
         * can make such an alert name anyone, so a destructive step on it is refused when the file is loaded.
         */
        COLLECTED_ONLY
    }

    /**
     * @param namesVictim whether the person the alert names is the one being attacked (a deny storm aimed at them,
     *                    MFA fatigue): denying or isolating them would hand the attacker a denial of service
     */
    public record Rule(String id, Evidence evidence, boolean namesVictim) {
        public Rule {
            Validate.id(id, "rule.id");
            Objects.requireNonNull(evidence, "rule.evidence");
        }
    }

    private final Map<String, Rule> rules;

    public RuleCatalogue(Iterable<Rule> rules) {
        Map<String, Rule> m = new LinkedHashMap<>();
        for (Rule r : rules) {
            if (m.putIfAbsent(r.id(), r) != null) {
                throw new IllegalArgumentException("rule listed twice: " + r.id());
            }
            if (m.size() > MAX_RULES) {
                throw new IllegalArgumentException("more than " + MAX_RULES + " rules");
            }
        }
        this.rules = Map.copyOf(m);
    }

    /**
     * Part A's detection rules (dev.dwarpal.siem): they read only the keyed audit chain, so their evidence is
     * verified. The two deny-storm rules and MFA fatigue name the person under attack.
     */
    public static RuleCatalogue reference() {
        return new RuleCatalogue(java.util.List.of(
                verified("honeytoken-touched"), verified("stolen-token-revoked"), verified("break-glass-used"),
                verified("break-glass-refused"), victim("deny-storm-ip"), victim("deny-storm-subject"),
                victim("mfa-fatigue"), verified("impossible-travel-allow"), verified("dlp-block-spike"),
                verified("pam-refused"), verified("audit-chain-break"), verified("audit-anchor-mismatch"),
                verified("alert-flood"), verified("detection-state-full")));
    }

    /** This catalogue plus {@code more} (for example part D's rules); a rule listed in both is refused. */
    public RuleCatalogue with(Iterable<Rule> more) {
        java.util.List<Rule> all = new java.util.ArrayList<>(rules.values());
        more.forEach(all::add);
        return new RuleCatalogue(all);
    }

    public Optional<Rule> rule(String id) {
        return Optional.ofNullable(rules.get(id));
    }

    public Set<String> ids() {
        return rules.keySet();
    }

    private static Rule verified(String id) {
        return new Rule(id, Evidence.VERIFIED, false);
    }

    private static Rule victim(String id) {
        return new Rule(id, Evidence.VERIFIED, true);
    }
}

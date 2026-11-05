package dev.dwarpal.ueba;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;

import dev.dwarpal.domain.Validate;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.RankedAlert;
import dev.dwarpal.soc.Technique;
import dev.dwarpal.soc.Techniques;

/**
 * Which MITRE ATT&CK techniques each rule and detector covers. Alerts do not carry techniques, so ranking and the
 * coverage report look them up here: a fixed table per rule id (part A's rules, part D's correlation rules added by
 * the integration), plus, for UEBA alerts, the techniques of the anomalies behind each alert.
 */
public final class TechniqueMap {

    public static final int MAX_RULES = 10_000;

    private final Map<String, List<Technique>> byRule;
    private final Function<String, List<Technique>> perAlert;

    private TechniqueMap(Map<String, List<Technique>> byRule, Function<String, List<Technique>> perAlert) {
        this.byRule = Map.copyOf(byRule);
        this.perAlert = perAlert;
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Part A's ten rules (ids as in {@code siem.Rules}) and the UEBA detectors, with the techniques they point to.
     */
    public static Builder standard() {
        return builder()
                .rule("break-glass-used", Techniques.VALID_ACCOUNTS, Techniques.ABUSE_ELEVATION)
                .rule("break-glass-refused", Techniques.ABUSE_ELEVATION)
                .rule("honeytoken-touched", Techniques.VALID_ACCOUNTS, Techniques.DATA_FROM_NETWORK_SHARE)
                .rule("stolen-token-revoked", Techniques.STEAL_SESSION_COOKIE)
                .rule("deny-storm-subject", Techniques.BRUTE_FORCE, Techniques.CREDENTIAL_STUFFING)
                .rule("deny-storm-ip", Techniques.PASSWORD_SPRAYING, Techniques.BRUTE_FORCE)
                .rule("mfa-fatigue", Techniques.MFA_REQUEST_GENERATION)
                .rule("impossible-travel-allow", Techniques.VALID_ACCOUNTS, Techniques.MULTI_HOP_PROXY)
                .rule("dlp-block-spike", Techniques.EXFIL_TO_CLOUD_STORAGE)
                .rule("pam-refused", Techniques.ABUSE_ELEVATION, Techniques.ACCOUNT_MANIPULATION)
                .rule(UebaEngine.RULE, Techniques.POWERSHELL, Techniques.OBFUSCATED_FILES,
                        Techniques.APPLICATION_LAYER_PROTOCOL, Techniques.EXFIL_TO_CLOUD_STORAGE,
                        Techniques.EXFIL_OVER_USB, Techniques.DATA_FROM_NETWORK_SHARE,
                        Techniques.ARCHIVE_COLLECTED_DATA, Techniques.VALID_ACCOUNTS);
    }

    /** The techniques of one alert: the per-alert ones if known, else the rule's; at most 8, no duplicates. */
    public List<Technique> of(Alert alert) {
        Objects.requireNonNull(alert, "alert");
        List<Technique> specific = perAlert == null ? List.of() : perAlert.apply(alert.id());
        List<Technique> l = specific == null || specific.isEmpty() ? byRule.getOrDefault(alert.rule(), List.of())
                : specific;
        List<Technique> distinct = List.copyOf(new LinkedHashSet<>(l));
        return distinct.size() > RankedAlert.MAX_TECHNIQUES ? distinct.subList(0, RankedAlert.MAX_TECHNIQUES)
                : distinct;
    }

    /** Every rule and the techniques it can point to. */
    public Map<String, List<Technique>> rules() {
        return byRule;
    }

    public static final class Builder {
        private final Map<String, List<Technique>> byRule = new LinkedHashMap<>();
        private Function<String, List<Technique>> perAlert;

        private Builder() {
        }

        /** Adds (or extends) a rule; every technique must be one {@link Techniques} knows. */
        public Builder rule(String rule, Technique... techniques) {
            Validate.id(rule, "rule");
            if (!byRule.containsKey(rule) && byRule.size() >= MAX_RULES) {
                throw new IllegalArgumentException("at most " + MAX_RULES + " rules");
            }
            Set<Technique> s = new LinkedHashSet<>(byRule.getOrDefault(rule, List.of()));
            for (Technique t : techniques) {
                Objects.requireNonNull(t, "technique");
                if (Techniques.byId(t.id()).filter(t::equals).isEmpty()) {
                    throw new IllegalArgumentException("unknown technique " + t.id());
                }
                s.add(t);
            }
            byRule.put(rule, new ArrayList<>(s));
            return this;
        }

        /** Per-alert techniques, for example {@link UebaEngine#techniques}. */
        public Builder perAlert(Function<String, List<Technique>> lookup) {
            this.perAlert = Objects.requireNonNull(lookup, "lookup");
            return this;
        }

        public TechniqueMap build() {
            Map<String, List<Technique>> m = new LinkedHashMap<>();
            byRule.forEach((k, v) -> m.put(k, List.copyOf(v)));
            return new TechniqueMap(m, perAlert);
        }
    }
}

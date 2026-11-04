package dev.dwarpal.casb;

import dev.dwarpal.domain.DataClassification;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * What to do with sensitive data, per finding type and per classification of the destination.
 *
 * <p>Defaults (stated, configurable):
 * <table>
 *   <caption>Default actions</caption>
 *   <tr><th></th><th>PUBLIC</th><th>INTERNAL</th><th>CONFIDENTIAL</th><th>RESTRICTED</th></tr>
 *   <tr><td>cards, Aadhaar, PAN</td><td>block</td><td>block</td><td>redact</td><td>audit</td></tr>
 *   <tr><td>e-mail, IFSC</td><td>audit</td><td>audit</td><td>audit</td><td>audit</td></tr>
 *   <tr><td>private keys, tokens</td><td>block</td><td>block</td><td>block</td><td>block</td></tr>
 *   <tr><td>content that cannot be inspected</td><td>block</td><td>block</td><td>block</td><td>block</td></tr>
 * </table>
 * Personal identifiers belong only in stores classified for them; secrets belong in none (a key in a
 * SaaS drive is a key leaked); e-mail addresses and bank branch codes are everywhere and only audited;
 * what cannot be read cannot be cleared, so it is refused (fail-closed).
 */
public final class DlpPolicy {

    private final Map<FindingType, Map<DataClassification, DlpAction>> actions;
    private final Map<DataClassification, DlpAction> uninspectable;

    private DlpPolicy(Map<FindingType, Map<DataClassification, DlpAction>> actions,
                      Map<DataClassification, DlpAction> uninspectable) {
        this.actions = actions;
        this.uninspectable = uninspectable;
    }

    public static DlpPolicy defaults() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public DlpAction action(FindingType type, DataClassification classification) {
        return actions.get(Objects.requireNonNull(type, "type")).get(Objects.requireNonNull(classification, "classification"));
    }

    public DlpAction uninspectable(DataClassification classification) {
        return uninspectable.get(Objects.requireNonNull(classification, "classification"));
    }

    public static final class Builder {
        private final Map<FindingType, Map<DataClassification, DlpAction>> actions = new EnumMap<>(FindingType.class);
        private final Map<DataClassification, DlpAction> uninspectable = new EnumMap<>(DataClassification.class);

        private Builder() {
            for (FindingType t : FindingType.values()) {
                Map<DataClassification, DlpAction> m = new EnumMap<>(DataClassification.class);
                for (DataClassification c : DataClassification.values()) {
                    m.put(c, switch (t) {
                        case EMAIL, IFSC -> DlpAction.AUDIT;
                        case PRIVATE_KEY, AWS_ACCESS_KEY, GITHUB_TOKEN, SLACK_TOKEN -> DlpAction.BLOCK;
                        case CARD_NUMBER, AADHAAR, PAN -> switch (c) {
                            case PUBLIC, INTERNAL -> DlpAction.BLOCK;
                            case CONFIDENTIAL -> DlpAction.REDACT;
                            case RESTRICTED -> DlpAction.AUDIT;
                        };
                    });
                }
                actions.put(t, m);
            }
            for (DataClassification c : DataClassification.values()) {
                uninspectable.put(c, DlpAction.BLOCK);
            }
        }

        public Builder action(FindingType type, DataClassification classification, DlpAction action) {
            actions.get(Objects.requireNonNull(type, "type")).put(Objects.requireNonNull(classification, "classification"),
                    Objects.requireNonNull(action, "action"));
            return this;
        }

        public Builder uninspectable(DataClassification classification, DlpAction action) {
            if (action == DlpAction.REDACT) {
                throw new IllegalArgumentException("content that cannot be read cannot be redacted");
            }
            uninspectable.put(Objects.requireNonNull(classification, "classification"), Objects.requireNonNull(action, "action"));
            return this;
        }

        public DlpPolicy build() {
            Map<FindingType, Map<DataClassification, DlpAction>> a = new EnumMap<>(FindingType.class);
            actions.forEach((k, v) -> a.put(k, Map.copyOf(v)));
            return new DlpPolicy(Map.copyOf(a), Map.copyOf(uninspectable));
        }
    }
}

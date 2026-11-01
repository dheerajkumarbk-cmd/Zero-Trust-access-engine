package dev.dwarpal.policy;

import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;

import java.util.Objects;

public record Policy(String id, String description, Condition when, Effect effect) {

    public static final int MAX_DESCRIPTION_LENGTH = 500;

    public Policy {
        Validate.id(id, "policy.id");
        description = Sanitize.text(Objects.requireNonNull(description, "policy.description"), MAX_DESCRIPTION_LENGTH);
        Objects.requireNonNull(when, "policy.when");
        Objects.requireNonNull(effect, "policy.effect");
    }
}

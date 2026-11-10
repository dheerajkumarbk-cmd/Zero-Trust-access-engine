package dev.dwarpal.api;

import java.util.Objects;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;

/**
 * One readiness check behind {@code GET /v1/ready}: a part the engine API needs to give honest answers
 * (policy loaded, audit trail writable, store reachable).
 *
 * <p>Readiness is not liveness: {@code /v1/health} says the process answers; {@code /v1/ready} says its
 * parts work. A check that throws counts as not ready. Only {@link #name()} ever leaves the server, so it
 * is a fixed identifier ({@code [a-z-]{1,32}}), never a message.
 */
public interface Readiness {

    /** Fixed identifier, {@code [a-z-]{1,32}}. */
    String name();

    /** True when this part works. May throw; that is "not ready". */
    boolean ready();

    /** A check from a name and a supplier. */
    static Readiness of(String name, BooleanSupplier check) {
        checkName(name);
        Objects.requireNonNull(check, "check");
        return new Readiness() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean ready() {
                return check.getAsBoolean();
            }
        };
    }

    /** Throws IllegalArgumentException unless the name is {@code [a-z-]{1,32}}. */
    static void checkName(String name) {
        if (name == null || !NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("readiness name must match [a-z-]{1,32}");
        }
    }

    /** Pattern for {@link #checkName}. */
    Pattern NAME = Pattern.compile("[a-z-]{1,32}");
}

package dev.dwarpal.directory;

import java.util.Objects;

/**
 * One thing a person can be given (a mailbox, the finance system, the analyst console). SIMPLE items are approved
 * automatically once the directory shows the person is active; HARD items need the administrator and a lead.
 * {@code consoleRole} is set for the items the console's own roles are made of.
 */
public record AccessItem(String id, String label, String description, Sensitivity sensitivity, String consoleRole) {

    public enum Sensitivity { SIMPLE, HARD }

    public AccessItem {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(description, "description");
        Objects.requireNonNull(sensitivity, "sensitivity");
    }
}

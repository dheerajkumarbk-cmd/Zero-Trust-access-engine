package dev.dwarpal.domain;

import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Who is asking. A subject is either a human or a workload (service account, API client, agent);
 * modelling non-human identities from day one keeps the door open for NHI policies later.
 *
 * <p>Roles and department are canonical lower-case labels (see {@link Validate#label}).
 * In production these attributes come from the identity directory, never from the requester.
 */
public record Subject(String id, SubjectType type, Set<String> roles, String department) {

    public static final int MAX_ROLES = 64;

    public Subject {
        Validate.id(id, "subject.id");
        Objects.requireNonNull(type, "subject.type");
        Objects.requireNonNull(roles, "subject.roles");
        if (roles.size() > MAX_ROLES) {
            throw new IllegalArgumentException("subject has more than " + MAX_ROLES + " roles");
        }
        roles = roles.stream().map(r -> Validate.label(r, "subject.role")).collect(Collectors.toUnmodifiableSet());
        department = Validate.label(department, "subject.department");
    }

    public boolean hasAnyRole(Set<String> wanted) {
        return roles.stream().anyMatch(wanted::contains);
    }
}

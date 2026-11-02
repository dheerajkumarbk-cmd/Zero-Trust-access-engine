package dev.dwarpal.pam;

import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.pip.AttributeDirectory;

import java.time.Clock;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The directory as the engine should see it: the permanent roles from the identity store, plus the
 * roles the subject holds right now through a just-in-time grant. When a grant ends, the role
 * disappears from the very next decision; nothing has to be cleaned up anywhere else.
 */
public final class ElevatedDirectory implements AttributeDirectory {

    private final AttributeDirectory base;
    private final PrivilegedAccessManager pam;
    private final Clock clock;

    public ElevatedDirectory(AttributeDirectory base, PrivilegedAccessManager pam, Clock clock) {
        this.base = Objects.requireNonNull(base, "base");
        this.pam = Objects.requireNonNull(pam, "pam");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public Optional<Subject> subject(String subjectId) {
        return base.subject(subjectId).map(s -> {
            Set<String> elevated = pam.activeRoles(subjectId, clock.instant());
            if (elevated.isEmpty()) {
                return s;
            }
            Set<String> roles = new HashSet<>(s.roles());
            roles.addAll(elevated);
            return new Subject(s.id(), s.type(), roles, s.department());
        });
    }

    @Override
    public Optional<Resource> resource(String resourceId) {
        return base.resource(resourceId);
    }

    @Override
    public boolean isManagedDevice(String deviceId) {
        return base.isManagedDevice(deviceId);
    }
}

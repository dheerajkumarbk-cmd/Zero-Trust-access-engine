package dev.dwarpal.response;

import dev.dwarpal.pam.PrivilegedAccessManager;
import dev.dwarpal.pip.AttributeDirectory;
import dev.dwarpal.session.PolicyAdministrator;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * What playbooks act through, and what they ask before acting: the Policy Administrator (sessions), the
 * privileged access manager (elevation grants) and the directory (who is privileged).
 */
public interface Enforcement {

    int revokeSession(String sessionId, String actor, String reason);

    /** Ends a person's sessions and their elevation grants. */
    int revokeSubject(String subjectId, String actor, String reason);

    int revokeDevice(String deviceId, String actor, String reason);

    /** The person's directory roles plus any roles they hold through elevation now; may throw. */
    Set<String> rolesOf(String subjectId, Instant now);

    static Enforcement of(PolicyAdministrator pa, PrivilegedAccessManager pam, AttributeDirectory directory) {
        Objects.requireNonNull(pa, "pa");
        Objects.requireNonNull(pam, "pam");
        Objects.requireNonNull(directory, "directory");
        return new Enforcement() {
            @Override
            public int revokeSession(String sessionId, String actor, String reason) {
                return pa.revokeSession(sessionId, actor, reason);
            }

            @Override
            public int revokeSubject(String subjectId, String actor, String reason) {
                // Grants first: a person whose sessions end must not keep admin rights for the next login.
                int grants = pam.revokeSubject(subjectId, actor, reason);
                return pa.revokeSubject(subjectId, actor, reason) + grants;
            }

            @Override
            public int revokeDevice(String deviceId, String actor, String reason) {
                return pa.revokeDevice(deviceId, actor, reason);
            }

            @Override
            public Set<String> rolesOf(String subjectId, Instant now) {
                Set<String> roles = new java.util.HashSet<>(pam.activeRoles(subjectId, now));
                directory.subject(subjectId).ifPresent(s -> roles.addAll(s.roles()));
                return Set.copyOf(roles);
            }
        };
    }
}

package dev.dwarpal.pip;

import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.Subject;

import java.util.Optional;

/**
 * Authoritative source of subject, resource and device attributes (a Policy Information Point in
 * NIST SP 800-207 terms): the identity provider for roles and department, the resource catalog
 * for classification, kind and fail mode, the device inventory (MDM) for whether a device is
 * corporate-managed.
 *
 * <p>The engine only trusts the <em>identifiers</em> in a request. Everything that decides
 * access, such as "payroll is RESTRICTED", "alice is in finance" or "this laptop is managed",
 * is looked up here, because a requester who could state their own attributes could grant
 * themselves anything.
 */
public interface AttributeDirectory {

    Optional<Subject> subject(String subjectId);

    Optional<Resource> resource(String resourceId);

    /** True only if the device inventory lists the device as corporate-managed. Unknown devices are not. */
    boolean isManagedDevice(String deviceId);
}

package dev.dwarpal.pip;

import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.Subject;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Immutable directory held in memory; used by the simulator and tests. */
public final class InMemoryDirectory implements AttributeDirectory {

    private final Map<String, Subject> subjects;
    private final Map<String, Resource> resources;
    private final Set<String> managedDevices;

    public InMemoryDirectory(Collection<Subject> subjects, Collection<Resource> resources,
                             Collection<String> managedDevices) {
        // toUnmodifiableMap throws on duplicate ids: two records for one identity is a data error.
        this.subjects = subjects.stream().collect(Collectors.toUnmodifiableMap(Subject::id, Function.identity()));
        this.resources = resources.stream().collect(Collectors.toUnmodifiableMap(Resource::id, Function.identity()));
        this.managedDevices = Set.copyOf(managedDevices);
    }

    public InMemoryDirectory(Collection<Subject> subjects, Collection<Resource> resources) {
        this(subjects, resources, Set.of());
    }

    @Override
    public Optional<Subject> subject(String subjectId) {
        return Optional.ofNullable(subjects.get(subjectId));
    }

    @Override
    public Optional<Resource> resource(String resourceId) {
        return Optional.ofNullable(resources.get(resourceId));
    }

    @Override
    public boolean isManagedDevice(String deviceId) {
        return managedDevices.contains(deviceId);
    }
}

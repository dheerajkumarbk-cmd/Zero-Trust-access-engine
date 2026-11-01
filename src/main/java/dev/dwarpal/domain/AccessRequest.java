package dev.dwarpal.domain;

import java.time.Instant;
import java.util.Objects;

/**
 * One access attempt as seen by a Policy Enforcement Point. {@code pepRegion} names the SASE
 * point of presence that enforced it (e.g. "mumbai"), so one PDP can serve many edges.
 *
 * <p>The timestamp comes from the request, never from the engine's clock: the same request
 * always yields the same decision, which is what makes What-If replay possible (NFR-02).
 * Live deployments pair this with {@code FreshnessGate} so the timestamp cannot be forged.
 *
 * <p>Only identifiers and signed {@link Evidence} are trusted; the engine replaces claimed
 * attributes with authoritative ones before deciding.
 */
public record AccessRequest(String requestId, Instant timestamp, Subject subject, Device device,
                            Resource resource, Action action, NetworkContext network, String pepRegion,
                            Evidence evidence) {

    public AccessRequest {
        Validate.id(requestId, "request.id");
        Objects.requireNonNull(timestamp, "request.timestamp");
        Objects.requireNonNull(subject, "request.subject");
        Objects.requireNonNull(device, "request.device");
        Objects.requireNonNull(resource, "request.resource");
        Objects.requireNonNull(action, "request.action");
        Objects.requireNonNull(network, "request.network");
        pepRegion = Validate.label(pepRegion, "request.pepRegion");
        Objects.requireNonNull(evidence, "request.evidence");
    }

    /** A request carrying no signed evidence. */
    public AccessRequest(String requestId, Instant timestamp, Subject subject, Device device,
                         Resource resource, Action action, NetworkContext network, String pepRegion) {
        this(requestId, timestamp, subject, device, resource, action, network, pepRegion, Evidence.none());
    }

    /** Copy with authoritative subject and resource; every other field is preserved. */
    public AccessRequest withSubjectAndResource(Subject s, Resource r) {
        return new AccessRequest(requestId, timestamp, s, device, r, action, network, pepRegion, evidence);
    }

    /** Copy with a verified device record; every other field is preserved. */
    public AccessRequest withDevice(Device d) {
        return new AccessRequest(requestId, timestamp, subject, d, resource, action, network, pepRegion, evidence);
    }
}

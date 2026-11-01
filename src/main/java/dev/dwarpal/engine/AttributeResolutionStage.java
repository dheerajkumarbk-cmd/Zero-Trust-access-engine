package dev.dwarpal.engine;

import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Device;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.pip.AttributeDirectory;

import java.util.Optional;

/**
 * Stage 2: replace the subject, resource and device-management status the request
 * <em>claims</em> with the authoritative records. Unknown subjects or resources are denied
 * (fail-closed); unknown devices are simply unmanaged (BYOD is allowed, just trusted less).
 * A mismatch between claim and record is kept in the explanation: it is itself a signal worth an
 * analyst's attention (tampering, or a stale PEP cache).
 */
final class AttributeResolutionStage implements DecisionStage {

    private final AttributeDirectory directory;

    AttributeResolutionStage(AttributeDirectory directory) {
        this.directory = directory;
    }

    @Override
    public String name() {
        return "attribute-resolution";
    }

    @Override
    public void apply(DecisionContext ctx) {
        AccessRequest claimed = ctx.request();
        Optional<Subject> subject = directory.subject(claimed.subject().id());
        if (subject.isEmpty()) {
            ctx.terminate(Outcome.DENY, "unknown-subject", "subject not found in directory");
            return;
        }
        Optional<Resource> resource = directory.resource(claimed.resource().id());
        if (resource.isEmpty()) {
            ctx.terminate(Outcome.DENY, "unknown-resource", "resource not found in catalog");
            return;
        }
        if (!subject.get().equals(claimed.subject())) {
            ctx.note("request-supplied subject attributes ignored; directory record used");
        }
        if (!resource.get().equals(claimed.resource())) {
            ctx.note("request-supplied resource attributes ignored; catalog record used ("
                    + resource.get().classification() + ", " + resource.get().kind() + ")");
        }
        Device claimedDevice = claimed.device();
        boolean managed = directory.isManagedDevice(claimedDevice.id());
        if (managed != claimedDevice.managed()) {
            ctx.note("device claimed managed=" + claimedDevice.managed() + "; inventory says " + managed);
        }
        ctx.request(claimed.withSubjectAndResource(subject.get(), resource.get())
                .withDevice(new Device(claimedDevice.id(), managed, claimedDevice.posture())));
    }
}

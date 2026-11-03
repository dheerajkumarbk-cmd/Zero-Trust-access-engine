package dev.dwarpal.edge;

import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Device;
import dev.dwarpal.domain.DevicePosture;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.ResourceKind;
import dev.dwarpal.domain.Subject;
import dev.dwarpal.domain.SubjectType;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.pip.AttributeDirectory;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.session.PolicyAdministrator;
import dev.dwarpal.session.SessionResult;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * {@link SessionAuthority} in the same process as the engine: the Policy Administrator for sessions,
 * a (non-learning) decision point for single decisions.
 *
 * <p>Turning an {@link EdgeRequest} into an engine request, attributes come from the directory only.
 * An unknown subject or resource gets a placeholder that the engine then refuses, so the answer is the
 * same as for any other unknown identifier. Claimed posture is always treated as self-reported; only
 * signed evidence raises it.
 */
public final class LocalSessionAuthority implements SessionAuthority {

    private final PolicyAdministrator administrator;
    private final DecisionPoint singleDecisions;
    private final AttributeDirectory directory;
    private final Supplier<SignalSnapshot> signals;
    private final AuthMethod challenge;
    private final Clock clock;
    private final AtomicLong internalFailures = new AtomicLong();

    /**
     * @param singleDecisions for {@link #decide}: normally {@code DecisionPipeline.continuous(...)} (audited, not learned)
     * @param signals         the current threat signals, from the engine side
     * @param challenge       the authenticator a STEP_UP asks for (the assurance settings' challenge method)
     * @param clock           enforcement is live: requests dated away from this clock are refused
     */
    public LocalSessionAuthority(PolicyAdministrator administrator, DecisionPoint singleDecisions,
                                 AttributeDirectory directory, Supplier<SignalSnapshot> signals, AuthMethod challenge,
                                 Clock clock) {
        this.administrator = Objects.requireNonNull(administrator, "administrator");
        this.singleDecisions = Objects.requireNonNull(singleDecisions, "singleDecisions");
        this.directory = Objects.requireNonNull(directory, "directory");
        this.signals = Objects.requireNonNull(signals, "signals");
        this.challenge = Objects.requireNonNull(challenge, "challenge");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public EdgeResult open(EdgeRequest login, PublicKey sessionKey, Optional<SignatureProof> deviceBinding) {
        Objects.requireNonNull(login, "login");
        Objects.requireNonNull(sessionKey, "sessionKey");
        Objects.requireNonNull(deviceBinding, "deviceBinding");
        try {
            return fromSession(administrator.open(assemble(login), currentSignals(), sessionKey, deviceBinding.orElse(null)),
                    login.requestId());
        } catch (RuntimeException e) {
            return failed(login.requestId());
        }
    }

    @Override
    public EdgeResult use(String token, SignatureProof proof, EdgeRequest request) {
        Objects.requireNonNull(request, "request");
        try {
            return fromSession(administrator.use(token, proof, assemble(request), currentSignals()), request.requestId());
        } catch (RuntimeException e) {
            return failed(request.requestId());
        }
    }

    @Override
    public EdgeResult decide(EdgeRequest request) {
        Objects.requireNonNull(request, "request");
        try {
            // Sessions get this check from the Policy Administrator; single decisions get it here.
            if (Duration.between(clock.instant(), request.timestamp()).abs().compareTo(KeyRing.MAX_CLOCK_SKEW) > 0) {
                return result(EdgeResult.Status.REJECTED, request.requestId(), false, Optional.empty(), false);
            }
            Decision d = singleDecisions.decide(assemble(request), currentSignals());
            EdgeResult.Status status = switch (d.outcome()) {
                case ALLOW -> EdgeResult.Status.GRANTED;
                case ALLOW_LIMITED -> EdgeResult.Status.GRANTED_LIMITED;
                case STEP_UP -> EdgeResult.Status.STEP_UP;
                case DENY -> EdgeResult.Status.DENIED;
            };
            return result(status, request.requestId(), status == EdgeResult.Status.GRANTED_LIMITED, Optional.empty(), false);
        } catch (RuntimeException e) {
            return failed(request.requestId());
        }
    }

    /** Requests answered DENIED because something failed inside (each one is a bug or an outage to look at). */
    public long internalFailures() {
        return internalFailures.get();
    }

    private SignalSnapshot currentSignals() {
        return Objects.requireNonNull(signals.get(), "signal snapshot");
    }

    private AccessRequest assemble(EdgeRequest r) {
        Subject subject = directory.subject(r.subjectId())
                .orElseGet(() -> new Subject(r.subjectId(), SubjectType.HUMAN, Set.of(), "unknown"));
        Resource resource = directory.resource(r.resourceId())
                .orElseGet(() -> new Resource(r.resourceId(), ResourceKind.PRIVATE_APP, DataClassification.RESTRICTED));
        DevicePosture p = r.claimedPosture();
        Device device = new Device(r.deviceId(), directory.isManagedDevice(r.deviceId()),
                new DevicePosture(p.osPatched(), p.diskEncrypted(), p.avHealthy(), AssuranceLevel.SELF_REPORTED));
        return new AccessRequest(r.requestId(), r.timestamp(), subject, device, resource, r.action(), r.network(),
                r.pepRegion(), r.evidence());
    }

    private EdgeResult fromSession(SessionResult s, String reference) {
        EdgeResult.Status status = EdgeResult.Status.valueOf(s.status().name());
        Optional<EdgeGrant> grant = s.grant().map(g -> new EdgeGrant(g.sessionId(), g.token(), g.expiresAt(),
                g.reauthDue(), g.restricted()));
        boolean restricted = status == EdgeResult.Status.GRANTED_LIMITED || grant.map(EdgeGrant::restricted).orElse(false);
        return result(status, reference, restricted, grant, s.sessionEnded());
    }

    private EdgeResult result(EdgeResult.Status status, String reference, boolean restricted,
                              Optional<EdgeGrant> grant, boolean ended) {
        Optional<AuthMethod> c = status == EdgeResult.Status.STEP_UP ? Optional.of(challenge) : Optional.empty();
        return new EdgeResult(status, reference, EdgeResult.genericMessage(status, reference), restricted, c, grant, ended);
    }

    private EdgeResult failed(String reference) {
        internalFailures.incrementAndGet();
        return result(EdgeResult.Status.DENIED, reference, false, Optional.empty(), false);
    }
}

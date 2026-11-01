package dev.dwarpal.engine;

import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.AssuranceLevel;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.domain.Device;
import dev.dwarpal.domain.DevicePosture;

import java.util.Optional;

/**
 * Stage 3: decide how much of the request's signed evidence to believe.
 *
 * <ul>
 *   <li><b>Device posture.</b> Without a valid signature from the agent key bound to <em>this</em>
 *       device, the posture counts as SELF_REPORTED whatever the request claims. A valid agent
 *       signature supports at most AGENT_SIGNED: hardware attestation is not verified here, so it
 *       cannot be claimed.</li>
 *   <li><b>Authentication.</b> The login method and time count only with a valid identity
 *       provider signature bound to this subject <em>and this device</em>. Otherwise it is ignored, and any step-up will
 *       have to happen again.</li>
 * </ul>
 * Verification time is the request timestamp, keeping decisions deterministic; in live mode
 * {@link FreshnessGate} ties that timestamp to the real clock.
 */
final class EvidenceVerificationStage implements DecisionStage {

    private final KeyRing keys;
    private final AssuranceSettings settings;

    EvidenceVerificationStage(KeyRing keys, AssuranceSettings settings) {
        this.keys = keys;
        this.settings = settings;
    }

    @Override
    public String name() {
        return "evidence-verification";
    }

    @Override
    public void apply(DecisionContext ctx) {
        verifyPosture(ctx);
        verifyAuthentication(ctx);
    }

    private void verifyPosture(DecisionContext ctx) {
        AccessRequest req = ctx.request();
        Device device = req.device();
        DevicePosture claimed = device.posture();
        AssuranceLevel effective = AssuranceLevel.SELF_REPORTED;

        Optional<SignatureProof> proof = req.evidence().postureProof();
        if (proof.isPresent()) {
            KeyRing.Result r = keys.verify(KeyPurpose.DEVICE_AGENT, device.id(), proof.get(),
                    SignedMessages.posture(device.id(), claimed, proof.get().signedAt()),
                    req.timestamp(), settings.maxPostureAge());
            if (r.valid()) {
                effective = claimed.assurance().atLeast(AssuranceLevel.AGENT_SIGNED)
                        ? AssuranceLevel.AGENT_SIGNED
                        : claimed.assurance();
            } else {
                ctx.note("device posture signature rejected: " + r.reason());
            }
        }
        if (effective != claimed.assurance()) {
            ctx.note("device posture assurance " + claimed.assurance() + " not supported by evidence; using " + effective);
        }
        ctx.request(req.withDevice(new Device(device.id(), device.managed(), new DevicePosture(
                claimed.osPatched(), claimed.diskEncrypted(), claimed.avHealthy(), effective))));
    }

    private void verifyAuthentication(DecisionContext ctx) {
        AccessRequest req = ctx.request();
        Optional<AuthenticationContext> auth = req.evidence().authentication();
        if (auth.isEmpty()) {
            return;
        }
        Optional<SignatureProof> proof = req.evidence().authenticationProof();
        if (proof.isEmpty()) {
            ctx.note("authentication claim is unsigned; ignored");
            return;
        }
        KeyRing.Result r = keys.verify(KeyPurpose.IDENTITY_PROVIDER, null, proof.get(),
                SignedMessages.authentication(req.subject().id(), req.device().id(), auth.get(), proof.get().signedAt()),
                req.timestamp(), settings.maxAuthenticationAge());
        if (r.valid()) {
            ctx.verifiedAuthentication(auth.get());
        } else {
            ctx.note("authentication signature rejected: " + r.reason());
        }
    }
}

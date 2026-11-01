package dev.dwarpal.admin;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.policy.PolicyLoadException;
import dev.dwarpal.policy.PolicySet;
import dev.dwarpal.policy.SafePolicyLoader;
import dev.dwarpal.risk.SignalSnapshot;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;

/**
 * The only way a policy change reaches the running engine (the Policy Administration Point's
 * write path). Privileged-access controls are enforced here, in code, not by convention:
 *
 * <ul>
 *   <li><b>Four-eyes / two-person rule.</b> A bundle needs approvals from at least
 *       {@code requiredApprovers} <em>distinct administrators</em>. One admin holding two keys
 *       counts once, so no single person, and no single stolen key, can change access policy.</li>
 *   <li><b>Key purpose.</b> Only POLICY_SIGNER keys count; a device or IdP key cannot approve.</li>
 *   <li><b>Integrity.</b> Approvals sign the SHA-256 of the exact text; any edit voids them.</li>
 *   <li><b>Rollback protection.</b> The sequence number must strictly increase.</li>
 *   <li><b>Safe parsing + lint gate.</b> The text goes through {@link SafePolicyLoader}, strict.</li>
 *   <li><b>Accountability.</b> Every attempt, accepted or rejected, is written to the audit chain
 *       <em>before</em> taking effect; if auditing fails, nothing is installed.</li>
 * </ul>
 *
 * Reads ({@link #decide}) are lock-free on an immutable engine; installs are serialised.
 */
public final class PolicyInstaller implements DecisionPoint {

    /** Approvals older than this are stale: an approval is for a change now, not a blank cheque. */
    public static final Duration MAX_APPROVAL_AGE = Duration.ofDays(7);

    private final KeyRing keys;
    private final int requiredApprovers;
    private final AuditLog audit;
    private final Clock clock;
    private final SafePolicyLoader loader = new SafePolicyLoader();

    private volatile PolicyEngine current;
    private long currentSequence;

    public PolicyInstaller(PolicyEngine initial, long initialSequence, KeyRing keys, int requiredApprovers,
                           AuditLog audit, Clock clock) {
        this.current = Objects.requireNonNull(initial, "initial engine");
        if (initialSequence < 0) {
            throw new IllegalArgumentException("initialSequence must be >= 0");
        }
        this.currentSequence = initialSequence;
        this.keys = Objects.requireNonNull(keys, "keys");
        if (requiredApprovers < 1) {
            throw new IllegalArgumentException("at least one approver is required");
        }
        this.requiredApprovers = requiredApprovers;
        this.audit = Objects.requireNonNull(audit, "audit");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public record Result(boolean installed, String reason) {
    }

    @Override
    public Decision decide(AccessRequest request, SignalSnapshot signals) {
        return current.decide(request, signals);
    }

    public PolicyEngine currentEngine() {
        return current;
    }

    public synchronized long currentSequence() {
        return currentSequence;
    }

    public synchronized Result install(PolicyBundle bundle, String requestedBy) {
        Validate.id(requestedBy, "requestedBy");
        Instant now = clock.instant();
        String hash = Digests.sha256Hex(bundle.yaml());

        if (bundle.sequence() <= currentSequence) {
            return reject(bundle, hash, requestedBy, now, "sequence " + bundle.sequence()
                    + " is not newer than installed " + currentSequence + " (rollback refused)");
        }

        TreeSet<String> approvers = new TreeSet<>();
        for (SignatureProof proof : bundle.approvals()) {
            KeyRing.Result r = keys.verify(KeyPurpose.POLICY_SIGNER, null, proof,
                    SignedMessages.policyBundle(bundle.sequence(), bundle.yaml(), proof.signedAt()),
                    now, MAX_APPROVAL_AGE);
            if (r.valid()) {
                approvers.add(r.key().boundTo());
            }
        }
        if (approvers.size() < requiredApprovers) {
            return reject(bundle, hash, requestedBy, now, "only " + approvers.size() + " distinct valid approver(s) "
                    + approvers + ", " + requiredApprovers + " required");
        }

        PolicyEngine next;
        PolicySet set;
        try {
            set = loader.load(bundle.yaml());
            next = current.withPolicySet(set);
        } catch (PolicyLoadException | IllegalArgumentException e) {
            return reject(bundle, hash, requestedBy, now, "policy rejected: " + e.getMessage());
        }

        Map<String, String> f = fields(bundle, hash, requestedBy);
        f.put("policyVersion", set.version());
        f.put("approvers", approvers.toString());
        f.put("replacesSequence", Long.toString(currentSequence));
        // Audit first: if this throws, the new policy is not installed.
        audit.append("POLICY_INSTALLED", requestedBy, now, f);
        current = next;
        currentSequence = bundle.sequence();
        return new Result(true, "installed sequence " + bundle.sequence() + " approved by " + approvers);
    }

    private Result reject(PolicyBundle bundle, String hash, String requestedBy, Instant now, String reason) {
        Map<String, String> f = fields(bundle, hash, requestedBy);
        f.put("reason", reason);
        audit.append("POLICY_REJECTED", requestedBy, now, f);
        return new Result(false, reason);
    }

    private static Map<String, String> fields(PolicyBundle bundle, String hash, String requestedBy) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("sequence", Long.toString(bundle.sequence()));
        f.put("sha256", hash);
        f.put("requestedBy", requestedBy);
        return f;
    }
}

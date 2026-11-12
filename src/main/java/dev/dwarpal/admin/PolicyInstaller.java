package dev.dwarpal.admin;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.engine.PolicyEngine;
import dev.dwarpal.guard.RateLimiter;
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
 *   <li><b>Accountability.</b> Every install is written to the audit chain <em>before</em> taking
 *       effect; if auditing fails, nothing is installed. Rejections are audited too, throttled so a
 *       flood of junk cannot flood the trail (and never blocking a correctly approved bundle).</li>
 * </ul>
 *
 * Reads ({@link #decide}) are lock-free on an immutable engine; installs are serialised.
 */
public final class PolicyInstaller implements DecisionPoint {

    /** Approvals older than this are stale: an approval is for a change now, not a blank cheque. */
    public static final Duration MAX_APPROVAL_AGE = Duration.ofDays(7);
    /** Rejections audited one by one per requester per hour; a real change needs one or two attempts. */
    public static final int AUDITED_REJECTIONS_PER_HOUR = 10;
    /** Rejections audited one by one per hour across all requesters (names are not authenticated). */
    public static final int AUDITED_REJECTIONS_PER_HOUR_TOTAL = 100;
    /** The actor named on the audit record of a restore. */
    public static final String RESTORE_ACTOR = "policy-restore";

    private final RateLimiter rejectionAudits = new RateLimiter(AUDITED_REJECTIONS_PER_HOUR, Duration.ofHours(1), 1_000);
    private final RateLimiter totalRejectionAudits = new RateLimiter(AUDITED_REJECTIONS_PER_HOUR_TOTAL,
            Duration.ofHours(1), 1);
    private final RateLimiter summaryAudits = new RateLimiter(1, Duration.ofHours(1), 1);
    private long suppressedRejections;
    private final KeyRing keys;
    private final int requiredApprovers;
    private final AuditLog audit;
    private final Clock clock;
    private final SafePolicyLoader loader = new SafePolicyLoader();

    private volatile PolicyEngine current;
    private long currentSequence;
    private boolean changed;

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

        Compiled compiled;
        try {
            compiled = compile(bundle.yaml());
        } catch (PolicyLoadException | IllegalArgumentException e) {
            return reject(bundle, hash, requestedBy, now, "policy rejected: " + e.getMessage());
        }
        PolicyEngine next = compiled.next();
        PolicySet set = compiled.set();

        Map<String, String> f = fields(bundle, hash, requestedBy);
        f.put("policyVersion", set.version());
        f.put("approvers", approvers.toString());
        f.put("replacesSequence", Long.toString(currentSequence));
        // Audit first: if this throws, the new policy is not installed.
        audit.append("POLICY_INSTALLED", requestedBy, now, f);
        current = next;
        currentSequence = bundle.sequence();
        changed = true;
        return new Result(true, "installed sequence " + bundle.sequence() + " approved by " + approvers);
    }

    private record Compiled(PolicySet set, PolicyEngine next) {
    }

    /** The one path from text to engine: safe loader, strict lint gate, then the engine rebuilt around the set. */
    private Compiled compile(String yaml) {
        PolicySet set = loader.load(yaml);
        return new Compiled(set, current.withPolicySet(set));
    }

    /**
     * Puts back a bundle that was installed before a restart or lab reset. This is the only unsigned way in, so it is
     * narrow: allowed once, and only while this installer has not installed or restored anything (the start of a lab),
     * for a sequence above the one it was built with. The text goes through exactly the same loader and lint gate as an
     * install. The restore is audited (POLICY_RESTORED) before it takes effect; if the audit refuses, nothing changes.
     * The caller vouches for the text (the lab checks its own seal first).
     */
    public synchronized Result restore(String yaml, long sequence, String note) {
        Objects.requireNonNull(yaml, "yaml");
        if (changed) {
            return new Result(false, "restore refused: this installer already installed or restored a bundle");
        }
        if (sequence <= currentSequence) {
            return new Result(false, "restore refused: sequence " + sequence + " is not newer than " + currentSequence);
        }
        Compiled compiled;
        try {
            compiled = compile(yaml);
        } catch (PolicyLoadException | IllegalArgumentException e) {
            return new Result(false, "restore refused: policy rejected: " + e.getMessage());
        }
        Instant now = clock.instant();
        Map<String, String> f = new LinkedHashMap<>();
        f.put("sequence", Long.toString(sequence));
        f.put("sha256", Digests.sha256Hex(yaml));
        f.put("note", Sanitize.text(note == null ? "" : note, 300));
        f.put("policyVersion", compiled.set().version());
        try {
            audit.append("POLICY_RESTORED", RESTORE_ACTOR, now, f);
        } catch (RuntimeException e) {
            return new Result(false, "restore refused: audit trail unavailable");
        }
        current = compiled.next();
        currentSequence = sequence;
        changed = true;
        return new Result(true, "restored sequence " + sequence);
    }

    /**
     * Rejections are audited, but not without limit: {@code requestedBy} is just a name the caller
     * supplies, so a flood of junk bundles could otherwise flood the audit trail. A requester's
     * first {@value #AUDITED_REJECTIONS_PER_HOUR} rejections per hour (and at most
     * {@value #AUDITED_REJECTIONS_PER_HOUR_TOTAL} overall) are recorded one by one, then a single
     * summary record per hour overall, then only a counter. Rejections never block anyone: a correctly approved bundle
     * installs whoever sends it and however many junk bundles came before.
     */
    private Result reject(PolicyBundle bundle, String hash, String requestedBy, Instant now, String reason) {
        if (rejectionAudits.tryAcquire(requestedBy, now) && totalRejectionAudits.tryAcquire("all", now)) {
            Map<String, String> f = fields(bundle, hash, requestedBy);
            f.put("reason", reason);
            audit.append("POLICY_REJECTED", requestedBy, now, f);
        } else {
            suppressedRejections++;
            if (summaryAudits.tryAcquire("all", now)) {
                Map<String, String> f = new LinkedHashMap<>();
                f.put("requestedBy", requestedBy);
                f.put("auditedPerHour", Integer.toString(AUDITED_REJECTIONS_PER_HOUR));
                audit.append("POLICY_REJECTIONS_THROTTLED", requestedBy, now, f);
            }
        }
        return new Result(false, reason);
    }

    /** Rejections counted but not individually audited (see {@link #reject}). */
    public synchronized long suppressedRejections() {
        return suppressedRejections;
    }

    private static Map<String, String> fields(PolicyBundle bundle, String hash, String requestedBy) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("sequence", Long.toString(bundle.sequence()));
        f.put("sha256", hash);
        f.put("requestedBy", requestedBy);
        return f;
    }
}

package dev.dwarpal.soar;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.guard.RateLimiter;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;
import java.util.function.Consumer;

/**
 * The only way a playbook change reaches the running SOAR: like a policy bundle, a playbook bundle needs the
 * signatures of at least two distinct administrators ({@code POLICY_SIGNER} keys; one person with two keys counts
 * once) over its exact text and sequence number, the sequence must rise (an older, more aggressive file cannot be
 * put back), and the text must pass the strict {@link PlaybookCompiler}. The install is audited before it takes
 * effect; no audit, no install. Rejections are audited too, throttled so junk cannot flood the trail.
 */
public final class PlaybookInstaller {

    public static final String ACTOR = "soc-playbook-installer";
    public static final Duration MAX_APPROVAL_AGE = Duration.ofDays(7);
    /** The two-person rule cannot be configured away. */
    public static final int MIN_APPROVERS = 2;

    public record Result(boolean installed, String reason, List<PlaybookCompiler.Finding> findings) {
        public Result {
            Objects.requireNonNull(reason, "reason");
            findings = List.copyOf(findings);
        }
    }

    /** What an install hands to the SOAR: the compiled set and the bundle's sequence. */
    public record Installed(long sequence, PlaybookSet set) {
        public Installed {
            Objects.requireNonNull(set, "set");
        }
    }

    private final PlaybookCompiler compiler;
    private final KeyRing keys;
    private final int requiredApprovers;
    private final AuditLog audit;
    private final Clock clock;
    private final Consumer<Installed> activate;
    private final RateLimiter rejectionAudits = new RateLimiter(20, Duration.ofHours(1), 1);
    private long sequence;
    private long suppressed;

    /**
     * @param compiler must be strict (warnings block)
     * @param activate receives each installed set (for example {@link Soar#activate})
     */
    public PlaybookInstaller(PlaybookCompiler compiler, KeyRing keys, int requiredApprovers, long initialSequence,
                             AuditLog audit, Clock clock, Consumer<Installed> activate) {
        this.compiler = Objects.requireNonNull(compiler, "compiler");
        this.keys = Objects.requireNonNull(keys, "keys");
        if (requiredApprovers < MIN_APPROVERS) {
            throw new IllegalArgumentException("playbook changes need at least " + MIN_APPROVERS + " approvers");
        }
        if (initialSequence < 0) {
            throw new IllegalArgumentException("initialSequence must be at least 0");
        }
        this.requiredApprovers = requiredApprovers;
        this.sequence = initialSequence;
        this.audit = Objects.requireNonNull(audit, "audit");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.activate = Objects.requireNonNull(activate, "activate");
    }

    public synchronized long sequence() {
        return sequence;
    }

    /** Rejections counted but not audited one by one. */
    public synchronized long suppressedRejections() {
        return suppressed;
    }

    public synchronized Result install(PlaybookBundle bundle, String requestedBy) {
        Objects.requireNonNull(bundle, "bundle");
        Validate.id(requestedBy, "requestedBy");
        Instant now = clock.instant();
        String hash = Digests.sha256Hex(bundle.yaml());
        if (bundle.sequence() <= sequence) {
            return reject(bundle, hash, requestedBy, now, "sequence is not newer than the installed one (rollback refused)",
                    List.of());
        }
        TreeSet<String> approvers = new TreeSet<>();
        for (SignatureProof p : bundle.approvals()) {
            KeyRing.Result r = keys.verify(KeyPurpose.POLICY_SIGNER, null, p,
                    PlaybookBundle.signedMessage(bundle.sequence(), bundle.yaml(), p.signedAt()), now, MAX_APPROVAL_AGE);
            if (r.valid()) {
                approvers.add(r.key().boundTo());
            }
        }
        if (approvers.size() < requiredApprovers) {
            return reject(bundle, hash, requestedBy, now, approvers.size() + " distinct valid approver(s), "
                    + requiredApprovers + " required", List.of());
        }
        PlaybookCompiler.Compilation c;
        try {
            c = compiler.compile(bundle.yaml());
        } catch (PlaybookException e) {
            return reject(bundle, hash, requestedBy, now, "unreadable: " + e.getMessage(), List.of());
        }
        if (!c.accepted()) {
            return reject(bundle, hash, requestedBy, now, "refused by the linter (" + c.findings().size() + " findings)",
                    c.findings());
        }
        PlaybookSet set = c.set().orElseThrow();
        Map<String, String> f = fields(bundle, hash, requestedBy);
        f.put("version", set.version());
        f.put("approvers", approvers.toString());
        f.put("replaces", Long.toString(sequence));
        try {
            audit.append("PLAYBOOKS_INSTALLED", ACTOR, now, f);
        } catch (RuntimeException e) {
            return new Result(false, "audit trail unavailable: nothing installed", List.of());
        }
        activate.accept(new Installed(bundle.sequence(), set));
        sequence = bundle.sequence();
        return new Result(true, "installed sequence " + bundle.sequence() + " approved by " + approvers, c.findings());
    }

    private Result reject(PlaybookBundle b, String hash, String requestedBy, Instant now, String reason,
                          List<PlaybookCompiler.Finding> findings) {
        if (rejectionAudits.tryAcquire("all", now)) {
            Map<String, String> f = fields(b, hash, requestedBy);
            f.put("reason", Sanitize.text(reason, 300));
            try {
                audit.append("PLAYBOOKS_REJECTED", ACTOR, now, f);
            } catch (RuntimeException e) {
                // a rejection changes nothing; failing to record it must not turn into an install
                suppressed++;
            }
        } else {
            suppressed++;
        }
        return new Result(false, reason, findings);
    }

    private static Map<String, String> fields(PlaybookBundle b, String hash, String requestedBy) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("sequence", Long.toString(b.sequence()));
        f.put("sha256", hash);
        f.put("requestedBy", requestedBy);
        return f;
    }
}

package dev.dwarpal.console.admin;

import dev.dwarpal.admin.PolicyBundle;
import dev.dwarpal.admin.PolicyInstaller;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.policy.PolicyLoadException;
import dev.dwarpal.policy.PolicySet;
import dev.dwarpal.policy.SafePolicyLoader;
import dev.dwarpal.soar.PlaybookBundle;
import dev.dwarpal.soar.PlaybookCompiler;
import dev.dwarpal.soar.PlaybookException;
import dev.dwarpal.soar.PlaybookInstaller;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Proposals for a policy or a playbook change and the signatures collected for them, until the change is installed or
 * lapses. This class never decides anything: the signing is done with the approving administrator's own key, the
 * installers ({@link PolicyInstaller}, {@link PlaybookInstaller}) check the approvals, the distinct signers, the
 * sequence number and the linter, and write the audit record before the change takes effect. What is kept here is
 * only the open paperwork, bounded and short-lived.
 */
final class Changes {

    enum Kind { POLICY, PLAYBOOK }

    static final int MAX_OPEN = 10;
    static final int MAX_YAML = 64 * 1024;
    static final Duration TTL = Duration.ofHours(1);
    static final int REQUIRED = 2;

    /** A change under review (the signatures stay inside; the view shows who signed). */
    static final class Candidate {
        final String id;
        final Kind kind;
        final long sequence;
        final String yaml;
        final String sha256;
        final String proposedBy;
        final Instant at;
        final Map<String, SignatureProof> approvals = new LinkedHashMap<>();
        final List<String> findings;

        Candidate(String id, Kind kind, long sequence, String yaml, String proposedBy, Instant at,
                  List<String> findings) {
            this.id = id;
            this.kind = kind;
            this.sequence = sequence;
            this.yaml = yaml;
            this.sha256 = Digests.sha256Hex(yaml);
            this.proposedBy = proposedBy;
            this.at = at;
            this.findings = List.copyOf(findings);
        }
    }

    /** What the screen shows of a candidate. */
    record View(String id, String kind, long sequence, String sha256, String proposedBy, Instant proposedAt,
                Instant lapsesAt, List<String> approvedBy, int required, boolean linted, List<String> findings,
                String yaml) {
    }

    /** Why a proposal, signature or install was not done, in words fit for the screen. */
    static final class Refused extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final int status;

        Refused(int status, String message) {
            super(message);
            this.status = status;
        }

        int status() {
            return status;
        }
    }

    private final AdminServices services;
    private final Map<String, Candidate> open = new LinkedHashMap<>();

    Changes(AdminServices services) {
        this.services = services;
    }

    synchronized View propose(Kind kind, String yaml, String by) {
        expire();
        if (yaml == null || yaml.isBlank()) {
            throw new Refused(400, "nothing was submitted");
        }
        if (yaml.length() > MAX_YAML || yaml.getBytes(StandardCharsets.UTF_8).length > MAX_YAML) {
            throw new Refused(400, "the file is larger than " + MAX_YAML + " bytes");
        }
        if (open.size() >= MAX_OPEN) {
            throw new Refused(429, "too many open proposals; wait for one to lapse or be installed");
        }
        List<String> findings = new ArrayList<>();
        boolean ok = lint(kind, yaml, findings);
        long sequence = (kind == Kind.POLICY ? services.policies().currentSequence() : services.playbooks().sequence()) + 1;
        Candidate c = new Candidate(UUID.randomUUID().toString().substring(0, 8), kind, sequence, yaml, by,
                services.clock().instant(), findings);
        if (!ok) {
            // a refused file is shown with its findings but is not kept: it can never be approved or installed
            return view(c, false);
        }
        open.put(c.id, c);
        return view(c, true);
    }

    private boolean lint(Kind kind, String yaml, List<String> findings) {
        try {
            if (kind == Kind.POLICY) {
                PolicySet set = new SafePolicyLoader().load(yaml);
                services.policies().currentEngine().withPolicySet(set);     // the installer's own lint gate
                findings.add("The policy set " + set.version() + " loads: " + set.policies().size() + " policies.");
                return true;
            }
            PlaybookCompiler.Compilation c = services.playbookCompiler().compile(yaml);
            c.findings().forEach(f -> findings.add(f.toString()));
            return c.accepted();
        } catch (PolicyLoadException | PlaybookException | IllegalArgumentException e) {
            // the loaders' messages name places in the file, never its content
            findings.add("ERROR: " + e.getMessage());
            return false;
        }
    }

    synchronized Optional<View> view(String id) {
        expire();
        Candidate c = open.get(id);
        return c == null ? Optional.empty() : Optional.of(view(c, true));
    }

    synchronized List<View> all() {
        expire();
        return open.values().stream().map(c -> view(c, true)).toList();
    }

    synchronized Optional<Candidate> candidate(String id) {
        expire();
        return Optional.ofNullable(open.get(id));
    }

    /** The approving administrator signs the exact text and sequence with their own key. */
    synchronized View approve(String id, String adminId) {
        expire();
        Candidate c = open.get(id);
        if (c == null) {
            throw new Refused(404, "no such proposal");
        }
        KeyPair key = services.signingKey(adminId)
                .orElseThrow(() -> new Refused(403, "you hold no signing key in this lab"));
        Instant now = services.clock().instant();
        KeyPurpose purpose = KeyPurpose.POLICY_SIGNER;
        byte[] message = c.kind == Kind.POLICY
                ? SignedMessages.policyBundle(c.sequence, c.yaml, now)
                : SignedMessages.playbookBundle(c.sequence, c.sha256, now);
        SignatureProof proof = new SignatureProof(services.keyId(adminId, purpose), now,
                Ed25519.sign(key.getPrivate(), message));
        c.approvals.put(adminId, proof);
        return view(c, true);
    }

    /** Hands the signed bundle to the installer; on success the proposal is closed. */
    synchronized InstallResult install(String id, String by) {
        expire();
        Candidate c = open.get(id);
        if (c == null) {
            throw new Refused(404, "no such proposal");
        }
        List<SignatureProof> proofs = new ArrayList<>(c.approvals.values());
        boolean installed;
        String reason;
        if (c.kind == Kind.POLICY) {
            PolicyInstaller.Result r = services.policies().install(new PolicyBundle(c.sequence, c.yaml, proofs), by);
            installed = r.installed();
            reason = r.reason();
        } else {
            PlaybookInstaller.Result r = services.playbooks().install(new PlaybookBundle(c.sequence, c.yaml, proofs), by);
            installed = r.installed();
            reason = r.reason();
            if (installed) {
                services.playbookInstalled(c.yaml);
            }
        }
        List<String> approvedBy = c.approvals.keySet().stream().sorted().toList();
        if (installed) {
            open.remove(id);
            boolean kept = services.bundleInstalled(c.kind == Kind.POLICY ? "policy" : "playbook", c.sequence, c.yaml,
                    approvedBy);
            if (!kept) {
                reason = reason + " (installed, but not kept for a restart)";
            }
        }
        return new InstallResult(installed, reason, approvedBy);
    }

    /** The installers' answer, and who signed. */
    record InstallResult(boolean installed, String reason, List<String> approvedBy) {
    }

    synchronized boolean withdraw(String id) {
        return open.remove(id) != null;
    }

    private void expire() {
        Instant now = services.clock().instant();
        open.values().removeIf(c -> !now.isBefore(c.at.plus(TTL)));
    }

    private View view(Candidate c, boolean linted) {
        return new View(c.id, c.kind.name().toLowerCase(java.util.Locale.ROOT), c.sequence, c.sha256, c.proposedBy, c.at,
                c.at.plus(TTL), c.approvals.keySet().stream().sorted().toList(), REQUIRED, linted, c.findings,
                linted ? c.yaml : "");
    }
}

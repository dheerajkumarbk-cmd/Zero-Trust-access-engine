package dev.dwarpal.soar;

import dev.dwarpal.crypto.Canonical;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.SignatureProof;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * A playbook file packaged for deployment, like a policy bundle: the exact text, a strictly increasing sequence
 * number (rollback guard) and the approvals of at least two administrators, each a signature over
 * {@link #signedMessage}.
 */
public record PlaybookBundle(long sequence, String yaml, List<SignatureProof> approvals) {

    public static final int MAX_APPROVALS = 16;
    /** Domain of what approvers sign; kept apart from policy bundles so one approval cannot serve as the other. */
    public static final String DOMAIN = "dwarpal/playbook-bundle/v1";

    public PlaybookBundle {
        if (sequence < 1) {
            throw new IllegalArgumentException("bundle sequence starts at 1");
        }
        Objects.requireNonNull(yaml, "yaml");
        approvals = List.copyOf(approvals);
        if (approvals.size() > MAX_APPROVALS) {
            throw new IllegalArgumentException("too many approvals");
        }
    }

    /** What an approver signs: this sequence, the SHA-256 of this exact text, and when. */
    public static byte[] signedMessage(long sequence, String yaml, Instant signedAt) {
        return Canonical.encode(DOMAIN, Long.toString(sequence), Digests.sha256Hex(yaml), signedAt.toString());
    }
}

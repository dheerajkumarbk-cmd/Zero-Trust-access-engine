package dev.dwarpal.admin;

import dev.dwarpal.crypto.SignatureProof;

import java.util.List;
import java.util.Objects;

/**
 * A policy file packaged for deployment: the exact YAML text, a strictly increasing sequence
 * number, and the administrators' approvals (signatures over sequence + SHA-256 of the text).
 *
 * <p>The sequence number is the rollback guard: an attacker who captures an old, more permissive
 * bundle with valid signatures still cannot re-install it.
 */
public record PolicyBundle(long sequence, String yaml, List<SignatureProof> approvals) {

    public static final int MAX_APPROVALS = 16;

    public PolicyBundle {
        if (sequence < 1) {
            throw new IllegalArgumentException("bundle sequence starts at 1");
        }
        Objects.requireNonNull(yaml, "yaml");
        approvals = List.copyOf(approvals);
        if (approvals.size() > MAX_APPROVALS) {
            throw new IllegalArgumentException("too many approvals");
        }
    }
}

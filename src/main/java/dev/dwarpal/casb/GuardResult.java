package dev.dwarpal.casb;

import dev.dwarpal.edge.EdgeResult;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The CASB's answer to one SaaS data request.
 *
 * <ul>
 *   <li>{@code ALLOWED}: go ahead (an upload goes through unchanged).</li>
 *   <li>{@code REDACTED}: an upload goes through, but only as {@link #content()}.</li>
 *   <li>{@code STEP_UP}: the user must authenticate again ({@link #result()} carries the challenge).</li>
 *   <li>{@code REFUSED}: not allowed; {@link #userMessage()} is safe to show.</li>
 * </ul>
 * The findings are types and positions only. {@link #toString()} never prints content.
 */
public final class GuardResult {

    public enum Verdict {
        ALLOWED,
        REDACTED,
        STEP_UP,
        REFUSED
    }

    /** Why a request was refused or changed; for counters and the audit trail, not for the user. */
    public enum Reason {
        NONE,
        ENGINE,
        READ_ONLY,
        WRONG_ACTION,
        SENSITIVE_DATA,
        UNINSPECTABLE,
        UNKNOWN_RESOURCE,
        AUDIT_UNAVAILABLE
    }

    private final Verdict verdict;
    private final Reason reason;
    private final EdgeResult result;
    private final List<Finding> findings;
    private final byte[] content;

    GuardResult(Verdict verdict, Reason reason, EdgeResult result, List<Finding> findings, byte[] content) {
        this.verdict = Objects.requireNonNull(verdict, "verdict");
        this.reason = Objects.requireNonNull(reason, "reason");
        this.result = Objects.requireNonNull(result, "result");
        this.findings = List.copyOf(findings);
        this.content = content == null ? null : content.clone();
        if ((verdict == Verdict.REDACTED) != (content != null)) {
            throw new IllegalArgumentException("redacted content comes with REDACTED and only with REDACTED");
        }
    }

    public Verdict verdict() {
        return verdict;
    }

    public boolean allowed() {
        return verdict == Verdict.ALLOWED || verdict == Verdict.REDACTED;
    }

    public Reason reason() {
        return reason;
    }

    /** The engine's answer (status, reference, generic message, challenge). */
    public EdgeResult result() {
        return result;
    }

    public List<Finding> findings() {
        return findings;
    }

    /** The redacted upload, present only with REDACTED. */
    public Optional<byte[]> content() {
        return content == null ? Optional.empty() : Optional.of(content.clone());
    }

    /**
     * The bytes to pass on to the SaaS service: the redacted copy for REDACTED, {@code original} for
     * ALLOWED, nothing otherwise. Use this instead of choosing between {@link #content()} and the
     * original yourself: forwarding the original after a redaction would undo it.
     */
    public Optional<byte[]> forward(byte[] original) {
        Objects.requireNonNull(original, "original");
        return switch (verdict) {
            case ALLOWED -> Optional.of(original.clone());
            case REDACTED -> content();
            case STEP_UP, REFUSED -> Optional.empty();
        };
    }

    public String reference() {
        return result.reference();
    }

    public String userMessage() {
        return switch (verdict) {
            case ALLOWED, REDACTED, STEP_UP -> result.userMessage();
            case REFUSED -> EdgeResult.genericMessage(EdgeResult.Status.DENIED, result.reference());
        };
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof GuardResult g && verdict == g.verdict && reason == g.reason && result.equals(g.result)
                && findings.equals(g.findings) && Arrays.equals(content, g.content);
    }

    @Override
    public int hashCode() {
        return Objects.hash(verdict, reason, result, findings, Arrays.hashCode(content));
    }

    @Override
    public String toString() {
        return "GuardResult[" + verdict + ", reason=" + reason + ", reference=" + result.reference() + ", findings="
                + findings + (content != null ? ", content=<redacted, " + content.length + " bytes>" : "") + "]";
    }
}

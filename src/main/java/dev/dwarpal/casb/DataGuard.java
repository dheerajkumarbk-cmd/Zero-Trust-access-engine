package dev.dwarpal.casb;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.casb.GuardResult.Reason;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.SessionAuthority;
import dev.dwarpal.guard.RateLimiter;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * The CASB data guard: decides SaaS data actions in a session and inspects what is uploaded.
 *
 * <ol>
 *   <li>The session use goes to the engine through {@link SessionAuthority#use} (token, proof of
 *       possession, continuous evaluation). Anything but GRANTED or GRANTED_LIMITED stops here.</li>
 *   <li>Read-only is enforced here as well as in the engine: a session that was ever granted read-only
 *       may only READ, whatever a later answer says.</li>
 *   <li>An upload is inspected; the {@link DlpPolicy} for the destination's classification (from the
 *       directory, never from the client) decides: block, redact, or allow with audit.</li>
 *   <li>Every finding that lets data through is written to the audit trail (types and positions, never
 *       values) before the answer is given; if the trail cannot be written, the upload is refused.
 *       Refused uploads are audited with throttling.</li>
 * </ol>
 */
public final class DataGuard {

    public static final String AUDIT_TYPE = "casb.dlp";
    /** Read-only sessions remembered; the engine enforces read-only too, this is the second line. */
    public static final int MAX_TRACKED_SESSIONS = 100_000;
    private static final int MAX_AUDITED_FINDINGS = 50;

    private final SessionAuthority authority;
    private final Function<String, Optional<DataClassification>> classification;
    private final DlpPolicy policy;
    private final AuditLog audit;
    private final Clock clock;
    private final RateLimiter refusalAudits = new RateLimiter(20, Duration.ofMinutes(1), 10_000);
    private final Set<String> readOnlySessions = Collections.newSetFromMap(new LinkedHashMap<>(16, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
            return size() > MAX_TRACKED_SESSIONS;
        }
    });

    /**
     * @param classification the classification of a SaaS resource, from the directory (empty if unknown)
     */
    public DataGuard(SessionAuthority authority, Function<String, Optional<DataClassification>> classification,
                     DlpPolicy policy, AuditLog audit, Clock clock) {
        this.authority = Objects.requireNonNull(authority, "authority");
        this.classification = Objects.requireNonNull(classification, "classification");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** A READ (view) or DOWNLOAD in a session. */
    public GuardResult access(String token, SignatureProof proof, EdgeRequest request) {
        Objects.requireNonNull(request, "request");
        if (request.action() != Action.READ && request.action() != Action.DOWNLOAD) {
            return refused(Reason.WRONG_ACTION, request.requestId());
        }
        Gate g = session(token, proof, request);
        return g.stop() != null ? g.stop() : allowed(g.granted());
    }

    /** An upload (WRITE) in a session, with its content. */
    public GuardResult upload(String token, SignatureProof proof, EdgeRequest request, byte[] content) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(content, "content");
        if (request.action() != Action.WRITE) {
            return refused(Reason.WRONG_ACTION, request.requestId());
        }
        Gate g = session(token, proof, request);
        if (g.stop() != null) {
            return g.stop();
        }
        EdgeResult granted = g.granted();
        Optional<DataClassification> c = classification.apply(request.resourceId());
        if (c == null || c.isEmpty()) {
            return refusedAudited(Reason.UNKNOWN_RESOURCE, request, List.of(), "unknown");
        }
        Inspection inspection = Inspection.of(content);
        if (!inspection.inspectable()) {
            DlpAction a = policy.uninspectable(c.get());
            return a == DlpAction.BLOCK ? refusedAudited(Reason.UNINSPECTABLE, request, List.of(), c.get().name())
                    : pass(request, granted, inspection, a, c.get(), null);
        }
        if (inspection.findings().isEmpty()) {
            return allowed(granted);
        }
        DlpAction verdict = DlpAction.AUDIT;
        for (Finding f : inspection.findings()) {
            verdict = verdict.stricter(policy.action(f.type(), c.get()));
        }
        if (verdict == DlpAction.REDACT && inspection.truncated()) {
            // the report is full, so redacting what it lists would leave the rest behind
            verdict = DlpAction.BLOCK;
        }
        return switch (verdict) {
            case BLOCK -> refusedAudited(Reason.SENSITIVE_DATA, request, inspection.findings(), c.get().name());
            case REDACT -> pass(request, granted, inspection, verdict, c.get(), inspection.redactedBytes().orElseThrow());
            case AUDIT -> pass(request, granted, inspection, verdict, c.get(), null);
        };
    }

    /** Either a final answer ({@code stop}) or the engine's grant to carry on with. */
    private record Gate(GuardResult stop, EdgeResult granted) {
    }

    /** Runs the session use and the read-only rule. */
    private Gate session(String token, SignatureProof proof, EdgeRequest request) {
        EdgeResult r;
        try {
            r = authority.use(token, proof, request);
        } catch (RuntimeException e) {
            r = null;
        }
        if (r == null) {
            return new Gate(refused(Reason.ENGINE, request.requestId()), null);
        }
        String sessionId = proof == null ? null : proof.keyId();
        boolean restricted = r.restricted() || r.status() == EdgeResult.Status.GRANTED_LIMITED;
        synchronized (readOnlySessions) {
            if (sessionId != null && restricted && r.status().allowed()) {
                readOnlySessions.add(sessionId);
            }
            restricted |= sessionId != null && readOnlySessions.contains(sessionId);
        }
        return switch (r.status()) {
            case GRANTED, GRANTED_LIMITED -> restricted && request.action() != Action.READ
                    ? new Gate(new GuardResult(GuardResult.Verdict.REFUSED, Reason.READ_ONLY, r, List.of(), null), null)
                    : new Gate(null, r);
            case STEP_UP -> new Gate(new GuardResult(GuardResult.Verdict.STEP_UP, Reason.ENGINE, r, List.of(), null), null);
            case OPENED, DENIED, REJECTED -> new Gate(new GuardResult(GuardResult.Verdict.REFUSED, Reason.ENGINE,
                    r, List.of(), null), null);
        };
    }

    private static GuardResult allowed(EdgeResult granted) {
        return new GuardResult(GuardResult.Verdict.ALLOWED, Reason.NONE, granted, List.of(), null);
    }

    /** Data goes through (as is, or redacted): the audit record must be written first. */
    private GuardResult pass(EdgeRequest request, EdgeResult granted, Inspection inspection, DlpAction action, DataClassification c,
                             byte[] redacted) {
        try {
            record(request, action.name(), inspection.findings(), c.name(), inspection.inspectable());
        } catch (RuntimeException e) {
            return refused(Reason.AUDIT_UNAVAILABLE, request.requestId());
        }
        Reason reason = inspection.inspectable() ? Reason.SENSITIVE_DATA : Reason.UNINSPECTABLE;
        return redacted != null
                ? new GuardResult(GuardResult.Verdict.REDACTED, reason, granted, inspection.findings(), redacted)
                : new GuardResult(GuardResult.Verdict.ALLOWED, reason, granted, inspection.findings(), null);
    }

    private GuardResult refusedAudited(Reason reason, EdgeRequest request, List<Finding> findings, String classificationName) {
        if (refusalAudits.tryAcquire(request.subjectId(), clock.instant())) {
            try {
                record(request, "BLOCK", findings, classificationName, reason != Reason.UNINSPECTABLE);
            } catch (RuntimeException e) {
                // refusing needs no record to be safe; the refusal stands
            }
        }
        GuardResult r = refused(reason, request.requestId());
        return new GuardResult(r.verdict(), r.reason(), r.result(), findings, null);
    }

    private void record(EdgeRequest request, String action, List<Finding> findings, String classificationName,
                        boolean inspectable) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("reference", request.requestId());
        fields.put("resource", request.resourceId());
        fields.put("classification", classificationName);
        fields.put("action", action);
        fields.put("inspectable", Boolean.toString(inspectable));
        fields.put("count", Integer.toString(findings.size()));
        Set<String> types = new LinkedHashSet<>();
        StringBuilder positions = new StringBuilder();
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            types.add(f.type().name());
            if (i < MAX_AUDITED_FINDINGS) {
                positions.append(i == 0 ? "" : ",").append(f.type()).append('@').append(f.start()).append('-').append(f.end());
            }
        }
        fields.put("types", String.join(",", types));
        fields.put("findings", positions.toString());
        Instant now = clock.instant();
        audit.append(AUDIT_TYPE, request.subjectId(), now, fields);
    }

    private GuardResult refused(Reason reason, String reference) {
        GuardResult.Reason r = Reason.valueOf(reason.name());
        return new GuardResult(GuardResult.Verdict.REFUSED, r, result(EdgeResult.Status.DENIED, reference), List.of(), null);
    }

    private static EdgeResult result(EdgeResult.Status status, String reference) {
        return new EdgeResult(status, reference, EdgeResult.genericMessage(status, reference), false, Optional.empty(),
                Optional.empty(), false);
    }
}

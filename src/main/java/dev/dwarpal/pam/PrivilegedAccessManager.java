package dev.dwarpal.pam;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.guard.NonceCache;
import dev.dwarpal.guard.RateLimiter;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Privileged Access Management: nobody holds administrative roles permanently.
 *
 * <ul>
 *   <li><b>Just-in-time elevation.</b> A subject who is <em>eligible</em> for a role asks for it for a
 *       limited time (1 h by default) with a written justification, proving fresh, phishing-resistant
 *       MFA that can be used once. A <em>different</em> person approves by signing exactly that request
 *       (person, role, duration) with an approver key. The role then exists only inside the window; the
 *       engine sees it through {@link ElevatedDirectory} and loses it on the first decision after.</li>
 *   <li><b>Break-glass.</b> For emergencies when no approver is reachable: a designated account opens
 *       its sealed credential, gets the role for 30 minutes, and the SOC is alerted at once. Every use
 *       must be reviewed afterwards by someone else, who signs a verdict; "misuse" ends the grant.</li>
 *   <li><b>Rate limits</b> on requests, approvals and break-glass, and bounded stores.</li>
 * </ul>
 *
 * <p>Everything is audited, and nothing is granted unless its audit record was written.
 */
public final class PrivilegedAccessManager {

    public static final String ACTOR = "pam";
    public static final int MAX_JUSTIFICATION_LENGTH = 500;
    public static final int MIN_JUSTIFICATION_LENGTH = 10;

    /** An open request, waiting for an approver. */
    public record ElevationRequest(String requestId, String subjectId, String role, Duration duration,
                                   String justification, Instant requestedAt, Instant lapsesAt) {
    }

    /** The answer to a PAM operation; {@code id} is the request or grant concerned, when there is one. */
    public record Result(boolean ok, Optional<String> id, String reason) {
        static Result ok(String id, String reason) {
            return new Result(true, Optional.of(id), reason);
        }

        static Result refused(String reason) {
            return new Result(false, Optional.empty(), reason);
        }
    }

    private final KeyRing keys;
    private final Map<String, Set<String>> eligible;
    private final Map<String, Set<String>> breakGlassAccounts;
    private final PamSettings settings;
    private final AuditLog audit;
    private final Clock clock;
    private final Consumer<String> criticalAlerts;
    private final SecureRandom random = new SecureRandom();

    private final Map<String, ElevationRequest> pending = new LinkedHashMap<>();
    /** Read on every decision, so lock-free: each value is an immutable list replaced under the lock. */
    private final ConcurrentHashMap<String, List<ElevationGrant>> grants = new ConcurrentHashMap<>();
    private final Map<String, ElevationGrant> awaitingReview = new LinkedHashMap<>();
    private final RateLimiter requestLimit;
    private final RateLimiter approvalLimit;
    private final RateLimiter breakGlassLimit;
    private final RateLimiter refusalAudits = new RateLimiter(20, Duration.ofMinutes(1), 10_000);
    private final RateLimiter alertLimit = new RateLimiter(5, Duration.ofHours(1), 10_000);
    private final NonceCache usedProofs;

    /**
     * @param eligible           subject id to the roles they may request (eligible, not active)
     * @param breakGlassAccounts break-glass account id to the roles its sealed credential opens
     * @param criticalAlerts     where break-glass alerts go (the SOC pager); its failures never block
     */
    public PrivilegedAccessManager(KeyRing keys, Map<String, Set<String>> eligible,
                                   Map<String, Set<String>> breakGlassAccounts, PamSettings settings,
                                   AuditLog audit, Clock clock, Consumer<String> criticalAlerts) {
        this.keys = Objects.requireNonNull(keys, "keys");
        this.eligible = copyRoles(eligible);
        this.breakGlassAccounts = copyRoles(breakGlassAccounts);
        this.settings = Objects.requireNonNull(settings, "settings");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.criticalAlerts = Objects.requireNonNull(criticalAlerts, "criticalAlerts");
        this.requestLimit = new RateLimiter(settings.requestsPerHour(), Duration.ofHours(1), 100_000);
        this.approvalLimit = new RateLimiter(settings.approvalsPerHour(), Duration.ofHours(1), 10_000);
        this.breakGlassLimit = new RateLimiter(settings.breakGlassPerDay(), Duration.ofDays(1), 10_000);
        Duration proofWindow = settings.mfaMaxAge().compareTo(settings.approvalMaxAge()) > 0
                ? settings.mfaMaxAge() : settings.approvalMaxAge();
        this.usedProofs = new NonceCache(proofWindow.plus(KeyRing.MAX_CLOCK_SKEW), 100_000);
    }

    /**
     * A subject asks for a role for a while.
     *
     * @param auth      the requester's MFA, signed by the identity provider for this subject and device
     */
    public synchronized Result request(String subjectId, String deviceId, String role, Duration duration,
                                       String justification, AuthenticationContext auth, SignatureProof authProof) {
        Validate.id(subjectId, "subjectId");
        Validate.id(deviceId, "deviceId");
        String r = Validate.label(role, "role");
        Objects.requireNonNull(duration, "duration");
        Instant now = clock.instant();
        if (!eligible.getOrDefault(subjectId, Set.of()).contains(r)) {
            return refuse("ELEVATION_REFUSED", subjectId, r, "not eligible for role " + r, now);
        }
        if (duration.isNegative() || duration.isZero() || duration.compareTo(settings.maxElevation()) > 0) {
            return refuse("ELEVATION_REFUSED", subjectId, r,
                    "duration must be positive and at most " + settings.maxElevation().toMinutes() + " min", now);
        }
        Optional<String> why = checkJustification(justification);
        if (why.isPresent()) {
            return refuse("ELEVATION_REFUSED", subjectId, r, why.get(), now);
        }
        Optional<String> mfa = verifyRequesterMfa(subjectId, deviceId, auth, authProof, now);
        if (mfa.isPresent()) {
            return refuse("ELEVATION_REFUSED", subjectId, r, mfa.get(), now);
        }
        // Counted only once the requester has proved who they are: junk sent in someone's name cannot
        // use up their quota and lock them out of elevation during an incident.
        if (!requestLimit.tryAcquire(subjectId, now)) {
            return refuse("ELEVATION_REFUSED", subjectId, r, "too many elevation requests this hour", now);
        }
        pending.values().removeIf(p -> !now.isBefore(p.lapsesAt()));
        if (pending.size() >= settings.maxPending()) {
            return refuse("ELEVATION_REFUSED", subjectId, r, "too many open requests; refusing (fail-closed)", now);
        }
        String text = Sanitize.text(justification.strip(), MAX_JUSTIFICATION_LENGTH);
        ElevationRequest req = new ElevationRequest(newId("e-"), subjectId, r, duration, text, now,
                now.plus(settings.requestTtl()));
        Map<String, String> f = new LinkedHashMap<>();
        f.put("requestId", req.requestId());
        f.put("subjectId", subjectId);
        f.put("deviceId", deviceId);
        f.put("role", r);
        f.put("minutes", Long.toString(duration.toMinutes()));
        f.put("mfa", auth.method().name());
        f.put("justification", text);
        if (!tryAudit("ELEVATION_REQUESTED", subjectId, now, f)) {
            return Result.refused("audit trail unavailable: no audit, no request");
        }
        pending.put(req.requestId(), req);
        return Result.ok(req.requestId(), "request " + req.requestId() + " waits for an approver");
    }

    /** A different person approves one open request by signing exactly what it asks for. */
    public synchronized Result approve(String requestId, String approverId, SignatureProof approval) {
        Validate.id(requestId, "requestId");
        Validate.id(approverId, "approverId");
        Objects.requireNonNull(approval, "approval");
        Instant now = clock.instant();
        ElevationRequest req = pending.get(requestId);
        if (req == null || !now.isBefore(req.lapsesAt())) {
            pending.remove(requestId);
            return refuse("ELEVATION_APPROVAL_REFUSED", approverId, "-", "no open request " + requestId, now);
        }
        if (approverId.equals(req.subjectId())) {
            return refuse("ELEVATION_APPROVAL_REFUSED", approverId, req.role(), "nobody approves their own elevation", now);
        }
        KeyRing.Result v = keys.verify(KeyPurpose.ELEVATION_APPROVER, approverId, approval,
                SignedMessages.elevationApproval(requestId, req.subjectId(), req.role(), req.duration().toSeconds(),
                        approval.signedAt()),
                now, settings.approvalMaxAge());
        if (!v.valid()) {
            return refuse("ELEVATION_APPROVAL_REFUSED", approverId, req.role(), "approval rejected: " + v.reason(), now);
        }
        // Limits genuine approvals (a stolen approver key cannot hand out elevation in bulk); forged
        // ones were refused above and never touch the approver's quota.
        if (!approvalLimit.tryAcquire(approverId, now)) {
            return refuse("ELEVATION_APPROVAL_REFUSED", approverId, req.role(), "too many approvals this hour", now);
        }
        if (countGrants() >= settings.maxGrants()) {
            return refuse("ELEVATION_APPROVAL_REFUSED", approverId, req.role(), "too many active grants (fail-closed)", now);
        }
        ElevationGrant g = new ElevationGrant(requestId, req.subjectId(), req.role(), now, now.plus(req.duration()),
                Optional.of(approverId), false, req.justification());
        Map<String, String> f = grantFields(g);
        f.put("approvedBy", approverId);
        if (!tryAudit("ELEVATION_GRANTED", approverId, now, f)) {
            return Result.refused("audit trail unavailable: no audit, no elevation");
        }
        pending.remove(requestId);
        addGrant(g);
        return Result.ok(g.grantId(), req.subjectId() + " holds " + req.role() + " until " + g.until());
    }

    /**
     * Emergency access without an approver: the account's sealed credential signs the role and the
     * justification. The SOC is alerted immediately and the use must be reviewed.
     */
    public synchronized Result breakGlass(String accountId, String role, String justification, SignatureProof sealed) {
        Validate.id(accountId, "accountId");
        String r = Validate.label(role, "role");
        Objects.requireNonNull(sealed, "sealed");
        Instant now = clock.instant();
        if (!breakGlassAccounts.getOrDefault(accountId, Set.of()).contains(r)) {
            failedAttemptAlert(accountId, "break-glass attempt by " + accountId + " for role " + r
                    + ", which it does not hold", now);
            return refuse("BREAK_GLASS_REFUSED", accountId, r, "not a break-glass account for role " + r, now);
        }
        Optional<String> why = checkJustification(justification);
        if (why.isPresent()) {
            return refuse("BREAK_GLASS_REFUSED", accountId, r, why.get(), now);
        }
        KeyRing.Result v = keys.verify(KeyPurpose.BREAK_GLASS, accountId, sealed,
                SignedMessages.breakGlass(accountId, r, justification, sealed.signedAt()), now, settings.approvalMaxAge());
        if (!v.valid()) {
            failedAttemptAlert(accountId, "failed break-glass attempt for " + accountId + ": " + v.reason(), now);
            return refuse("BREAK_GLASS_REFUSED", accountId, r, "sealed credential rejected: " + v.reason(), now);
        }
        if (!usedProofs.firstUse("bg|" + sealed.signature(), now)) {
            failedAttemptAlert(accountId, "replayed break-glass signature for " + accountId, now);
            return refuse("BREAK_GLASS_REFUSED", accountId, r, "this break-glass signature was already used", now);
        }
        // Counted only for genuine uses of the sealed credential, so junk cannot use up the emergency quota.
        if (!breakGlassLimit.tryAcquire(accountId, now)) {
            alert("break-glass limit reached for " + accountId + ": a genuine credential was refused");
            return refuse("BREAK_GLASS_REFUSED", accountId, r, "break-glass limit for today reached", now);
        }
        if (countGrants() >= settings.maxGrants()) {
            return refuse("BREAK_GLASS_REFUSED", accountId, r, "too many active grants (fail-closed)", now);
        }
        String text = Sanitize.text(justification.strip(), MAX_JUSTIFICATION_LENGTH);
        ElevationGrant g = new ElevationGrant(newId("bg-"), accountId, r, now, now.plus(settings.breakGlassDuration()),
                Optional.empty(), true, text);
        Map<String, String> f = grantFields(g);
        f.put("severity", "CRITICAL");
        if (!tryAudit("BREAK_GLASS_USED", accountId, now, f)) {
            return Result.refused("audit trail unavailable: no audit, no break-glass");
        }
        addGrant(g);
        awaitingReview.put(g.grantId(), g);
        alert("break-glass: " + accountId + " holds " + r + " until " + g.until() + " (" + text + ")");
        return Result.ok(g.grantId(), "emergency access until " + g.until() + "; the SOC has been alerted");
    }

    /**
     * Someone other than the account reviews a break-glass use and signs a verdict: {@code justified}
     * or {@code misuse}. Misuse ends the grant at once.
     */
    public synchronized Result review(String grantId, String reviewerId, String verdict, SignatureProof signed) {
        Validate.id(grantId, "grantId");
        Validate.id(reviewerId, "reviewerId");
        Objects.requireNonNull(signed, "signed");
        Instant now = clock.instant();
        if (!"justified".equals(verdict) && !"misuse".equals(verdict)) {
            return Result.refused("verdict must be 'justified' or 'misuse'");
        }
        ElevationGrant g = awaitingReview.get(grantId);
        if (g == null) {
            return Result.refused("no break-glass use " + grantId + " awaits review");
        }
        if (reviewerId.equals(g.subjectId())) {
            return refuse("BREAK_GLASS_REVIEW_REFUSED", reviewerId, g.role(), "nobody reviews their own break-glass use", now);
        }
        KeyRing.Result v = keys.verify(KeyPurpose.ELEVATION_APPROVER, reviewerId, signed,
                SignedMessages.breakGlassReview(grantId, verdict, signed.signedAt()), now, settings.approvalMaxAge());
        if (!v.valid()) {
            return refuse("BREAK_GLASS_REVIEW_REFUSED", reviewerId, g.role(), "review rejected: " + v.reason(), now);
        }
        Map<String, String> f = grantFields(g);
        f.put("reviewer", reviewerId);
        f.put("verdict", verdict);
        if (!tryAudit("BREAK_GLASS_REVIEWED", reviewerId, now, f)) {
            return Result.refused("audit trail unavailable: review not recorded");
        }
        awaitingReview.remove(grantId);
        if ("misuse".equals(verdict)) {
            endGrants(x -> x.grantId().equals(grantId), "ELEVATION_REVOKED", reviewerId, "break-glass misuse", now);
            alert("break-glass " + grantId + " by " + g.subjectId() + " judged misuse by " + reviewerId);
        }
        return Result.ok(grantId, "reviewed: " + verdict);
    }

    /** Ends all of a subject's grants now (incident response, offboarding). */
    public synchronized int revokeSubject(String subjectId, String actor, String reason) {
        Validate.id(subjectId, "subjectId");
        Validate.id(actor, "actor");
        return endGrants(g -> g.subjectId().equals(subjectId), "ELEVATION_REVOKED", actor,
                Sanitize.text(Objects.requireNonNull(reason, "reason"), MAX_JUSTIFICATION_LENGTH), clock.instant());
    }

    /** Ends one grant now. */
    public synchronized int revokeGrant(String grantId, String actor, String reason) {
        Validate.id(grantId, "grantId");
        Validate.id(actor, "actor");
        return endGrants(g -> g.grantId().equals(grantId), "ELEVATION_REVOKED", actor,
                Sanitize.text(Objects.requireNonNull(reason, "reason"), MAX_JUSTIFICATION_LENGTH), clock.instant());
    }

    /** Removes grants whose window is over, auditing each; run it on a schedule. */
    public synchronized int purgeExpired() {
        Instant now = clock.instant();
        pending.values().removeIf(p -> !now.isBefore(p.lapsesAt()));
        return endGrants(g -> !g.activeAt(now) && !now.isBefore(g.until()), "ELEVATION_EXPIRED", ACTOR,
                "time window over", now);
    }

    /** The roles a subject holds through grants at time {@code at}. Lock-free: called on every decision. */
    public Set<String> activeRoles(String subjectId, Instant at) {
        List<ElevationGrant> mine = grants.get(subjectId);
        if (mine == null) {
            return Set.of();
        }
        return mine.stream().filter(g -> g.activeAt(at)).map(ElevationGrant::role).collect(Collectors.toUnmodifiableSet());
    }

    public synchronized List<ElevationRequest> pendingRequests() {
        return List.copyOf(pending.values());
    }

    public List<ElevationGrant> grants() {
        List<ElevationGrant> all = new ArrayList<>();
        grants.values().forEach(all::addAll);
        return List.copyOf(all);
    }

    /** Break-glass uses nobody has reviewed yet, including ones whose window is over. */
    public synchronized List<ElevationGrant> pendingReviews() {
        return List.copyOf(awaitingReview.values());
    }

    private Optional<String> verifyRequesterMfa(String subjectId, String deviceId, AuthenticationContext auth,
                                                SignatureProof proof, Instant now) {
        if (auth == null || proof == null) {
            return Optional.of("privileged access needs fresh MFA");
        }
        if (!settings.requestMethods().contains(auth.method())) {
            return Optional.of(auth.method() + " is not accepted for privileged access; use " + settings.requestMethods());
        }
        if (auth.authenticatedAt().isAfter(now.plus(KeyRing.MAX_CLOCK_SKEW))
                || Duration.between(auth.authenticatedAt(), now).compareTo(settings.mfaMaxAge()) > 0) {
            return Optional.of("MFA is not fresh (at most " + settings.mfaMaxAge().toMinutes() + " min)");
        }
        KeyRing.Result v = keys.verify(KeyPurpose.IDENTITY_PROVIDER, null, proof,
                SignedMessages.authentication(subjectId, deviceId, auth, proof.signedAt()), now, settings.mfaMaxAge());
        if (!v.valid()) {
            return Optional.of("MFA proof rejected: " + v.reason());
        }
        // One MFA ceremony, one request: a captured proof cannot be replayed to ask again.
        if (!usedProofs.firstUse("mfa|" + proof.signature(), now)) {
            return Optional.of("this MFA proof was already used");
        }
        return Optional.empty();
    }

    private static Optional<String> checkJustification(String justification) {
        if (justification == null || justification.strip().length() < MIN_JUSTIFICATION_LENGTH) {
            return Optional.of("a justification of at least " + MIN_JUSTIFICATION_LENGTH + " characters is required");
        }
        if (justification.length() > MAX_JUSTIFICATION_LENGTH) {
            return Optional.of("justification longer than " + MAX_JUSTIFICATION_LENGTH + " characters");
        }
        return Optional.empty();
    }

    private void addGrant(ElevationGrant g) {
        grants.compute(g.subjectId(), (k, old) -> {
            List<ElevationGrant> next = old == null ? new ArrayList<>() : new ArrayList<>(old);
            next.add(g);
            return List.copyOf(next);
        });
    }

    private int countGrants() {
        int n = 0;
        for (List<ElevationGrant> l : grants.values()) {
            n += l.size();
        }
        return n;
    }

    /** Removes matching grants first, then audits them; a failing audit never keeps a grant alive. */
    private int endGrants(Predicate<ElevationGrant> which, String type, String actor, String reason, Instant now) {
        List<ElevationGrant> ended = new ArrayList<>();
        for (String subject : List.copyOf(grants.keySet())) {
            grants.computeIfPresent(subject, (k, old) -> {
                List<ElevationGrant> keep = new ArrayList<>();
                for (ElevationGrant g : old) {
                    if (which.test(g)) {
                        ended.add(g);
                    } else {
                        keep.add(g);
                    }
                }
                return keep.isEmpty() ? null : List.copyOf(keep);
            });
        }
        for (ElevationGrant g : ended) {
            Map<String, String> f = grantFields(g);
            f.put("reason", reason);
            tryAudit(type, actor, now, f);
        }
        return ended.size();
    }

    private Result refuse(String type, String who, String role, String reason, Instant now) {
        if (refusalAudits.tryAcquire(type + "|" + who, now)) {
            Map<String, String> f = new LinkedHashMap<>();
            f.put("who", who);
            f.put("role", role);
            f.put("reason", reason);
            tryAudit(type, ACTOR, now, f);
        }
        return Result.refused(reason);
    }

    private boolean tryAudit(String type, String actor, Instant now, Map<String, String> fields) {
        try {
            audit.append(type, actor, now, fields);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Failed attempts page the SOC, at most 5 times per account per hour: junk must not cause alert fatigue. */
    private void failedAttemptAlert(String accountId, String message, Instant now) {
        if (alertLimit.tryAcquire(accountId, now)) {
            alert(message);
        }
    }

    private void alert(String message) {
        try {
            criticalAlerts.accept(Sanitize.text(message, MAX_JUSTIFICATION_LENGTH));
        } catch (RuntimeException e) {
            // the pager being down must not change the decision; the audit trail has the record
        }
    }

    private static Map<String, String> grantFields(ElevationGrant g) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("grantId", g.grantId());
        f.put("subjectId", g.subjectId());
        f.put("role", g.role());
        f.put("from", g.from().toString());
        f.put("until", g.until().toString());
        f.put("breakGlass", Boolean.toString(g.breakGlass()));
        f.put("justification", g.justification());
        return f;
    }

    private String newId(String prefix) {
        byte[] b = new byte[16];
        random.nextBytes(b);
        return prefix + HexFormat.of().formatHex(b);
    }

    private static Map<String, Set<String>> copyRoles(Map<String, Set<String>> in) {
        Map<String, Set<String>> out = new HashMap<>();
        Objects.requireNonNull(in, "roles").forEach((who, roles) -> out.put(Validate.id(who, "subject"),
                roles.stream().map(r -> Validate.label(r, "role")).collect(Collectors.toUnmodifiableSet())));
        return Map.copyOf(out);
    }
}

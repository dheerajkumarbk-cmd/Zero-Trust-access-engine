package dev.dwarpal.session;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.domain.DataClassification;
import dev.dwarpal.domain.Resource;
import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.engine.AssuranceSettings;
import dev.dwarpal.engine.DecisionPoint;
import dev.dwarpal.guard.NonceCache;
import dev.dwarpal.guard.RateLimiter;
import dev.dwarpal.pip.AttributeDirectory;
import dev.dwarpal.risk.SignalSnapshot;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;

/**
 * The Policy Administrator (NIST SP 800-207): turns the engine's decisions into sessions, and keeps
 * judging those sessions for as long as they live.
 *
 * <ul>
 *   <li><b>Open.</b> A login the engine allows gets a session: a random 256-bit bearer token
 *       (only its hash is stored) bound to the subject, the device, the resource and a session
 *       public key the client generated. A read-only decision gives a read-only session.</li>
 *   <li><b>Use.</b> Every request on a session must present the token <em>and</em> a fresh
 *       signature with the session key over this exact request (proof of possession, as in DPoP).
 *       A stolen token alone is useless; a captured request cannot be replayed (single-use request
 *       ids). Then the engine decides the request again: continuous evaluation, so a deny-list
 *       entry, a honeytoken hit or rising risk takes effect on the very next request.</li>
 *   <li><b>Limits.</b> Idle timeout, absolute lifetime, and re-authentication at an interval set
 *       by the data's classification. Re-authentication means a fresh, verified MFA proof bound to
 *       the session's subject and device: whoever sits at an unlocked laptop cannot pass it without
 *       the user's authenticator.</li>
 *   <li><b>Revoke.</b> By session, subject or device (account disabled, password changed, device
 *       lost): the SOC's kill switch, effective immediately because every use is checked here.</li>
 * </ul>
 *
 * <p>Every session opening and ending is audited. No audit, no session.
 */
public final class PolicyAdministrator {

    public static final String ACTOR = "policy-administrator";
    private static final int MAX_REASON_LENGTH = 256;
    private static final int TOKEN_BYTES = 32;
    private static final int TOKEN_CHARS = 43;

    private final DecisionPoint opening;
    private final DecisionPoint continuous;
    private final AttributeDirectory directory;
    private final KeyRing keys;
    private final AssuranceSettings assurance;
    private final SessionLimits limits;
    private final AuditLog audit;
    private final Clock clock;
    private final SecureRandom random;
    private final SessionStore store = new SessionStore();
    private final NonceCache nonces;
    /** Login MFA proofs already spent: each opens at most one session (finding B7, at the PA). */
    private final NonceCache loginProofs;
    private final boolean requireMfaAtOpen;
    private final Object openLock = new Object();
    private final AtomicLong malformedTokens = new AtomicLong();
    private final AtomicLong unknownTokens = new AtomicLong();
    /** Refusals are audited, but at most 20 per event type and subject per minute: a flood cannot flood the trail. */
    private final RateLimiter auditThrottle = new RateLimiter(20, Duration.ofMinutes(1), 10_000);

    private PolicyAdministrator(Builder b) {
        this.opening = Objects.requireNonNull(b.opening, "opening decision point");
        this.continuous = Objects.requireNonNull(b.continuous, "continuous decision point");
        this.directory = Objects.requireNonNull(b.directory, "directory");
        this.keys = Objects.requireNonNull(b.keys, "keyRing");
        this.assurance = Objects.requireNonNull(b.assurance, "assurance");
        this.limits = Objects.requireNonNull(b.limits, "limits");
        this.audit = Objects.requireNonNull(b.audit, "audit (no audit, no session)");
        this.clock = Objects.requireNonNull(b.clock, "clock");
        this.random = new SecureRandom();
        // A request id is remembered for as long as a proof carrying it could still verify.
        this.nonces = new NonceCache(limits.maxProofAge().plus(KeyRing.MAX_CLOCK_SKEW), b.nonceCapacity);
        // An MFA proof is remembered for as long as it could still count as fresh.
        this.loginProofs = new NonceCache(assurance.maxAuthenticationAge().plus(KeyRing.MAX_CLOCK_SKEW), b.nonceCapacity);
        this.requireMfaAtOpen = b.requireMfaAtOpen;
    }

    /** The audit trail is not optional: no audit, no session. */
    public static Builder builder(AuditLog audit) {
        return new Builder(audit);
    }

    /** Opens a session for a device without an endpoint agent (no signed posture in the request). */
    public SessionResult open(AccessRequest request, SignalSnapshot signals, PublicKey proofKey) {
        return open(request, signals, proofKey, null);
    }

    /**
     * Decides a login and, if the engine allows it, opens a session.
     *
     * @param proofKey      the session public key the client generated for this session; every later use
     *                      must be signed with the matching private key
     * @param deviceBinding required when the request carries a signed device posture: the device agent's
     *                      signature over (device, request id, session key thumbprint), at most
     *                      {@link SessionLimits#maxProofAge()} old and usable once. Without it a posture
     *                      report captured earlier could be replayed to open a session for another key.
     */
    public SessionResult open(AccessRequest request, SignalSnapshot signals, PublicKey proofKey,
                              SignatureProof deviceBinding) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(signals, "signals");
        Objects.requireNonNull(proofKey, "proofKey");
        if (!Ed25519.isEd25519(proofKey)) {
            return SessionResult.rejected("session proof key must be Ed25519", false);
        }
        Instant now = clock.instant();
        Optional<String> skew = clockSkew(request, now);
        if (skew.isPresent()) {
            return SessionResult.rejected(skew.get(), false);
        }
        String thumbprint = Digests.thumbprint(proofKey);
        // Checked before the engine runs, so a replayed login is neither decided nor learned from.
        if (request.evidence().postureProof().isPresent()) {
            Optional<String> binding = verifyDeviceBinding(request, proofKey, deviceBinding, now);
            if (binding.isPresent()) {
                auditRefusal("SESSION_BINDING_FAILED", request, null, binding.get(), now);
                return SessionResult.rejected("the device did not bind the session key: " + binding.get(), false);
            }
        }
        if (mfaNotBoundTo(request, thumbprint)) {
            auditRefusal("SESSION_MFA_NOT_BOUND", request, null, "MFA proof not bound to the session key", now);
            return SessionResult.rejected("the MFA proof is not bound to this session's key", false);
        }
        // Finding B1 at the PA: a session opens only on verified MFA, whichever enforcement point asks.
        // Finding B7: a login MFA proof opens at most one session, so a captured login cannot be replayed.
        Optional<Instant> verifiedMfa = verifiedAuthentication(request, now, thumbprint);
        if (verifiedMfa.isEmpty() && requireMfaAtOpen) {
            auditRefusal("SESSION_MFA_REQUIRED", request, null, "no fresh, verified, key-bound MFA proof", now);
            return SessionResult.of(SessionResult.Status.STEP_UP, null,
                    "verified MFA required before a session opens; challenge with " + assurance.challengeMethod(), false);
        }
        if (verifiedMfa.isPresent()
                && !loginProofs.firstUse(request.evidence().authenticationProof().orElseThrow().signature(), now)) {
            auditRefusal("SESSION_LOGIN_REPLAY", request, null, "login MFA proof already used", now);
            return SessionResult.rejected("this MFA proof has already opened a session: replay refused", false);
        }
        Decision d = opening.decide(request, signals);
        if (d.outcome() == Outcome.STEP_UP) {
            return SessionResult.of(SessionResult.Status.STEP_UP, d,
                    "step-up required before a session opens; challenge with " + assurance.challengeMethod(), false);
        }
        if (d.outcome() == Outcome.DENY) {
            return SessionResult.of(SessionResult.Status.DENIED, d, "the engine denied the login", false);
        }
        Optional<Resource> resource = directory.resource(request.resource().id());
        if (resource.isEmpty()) {
            return SessionResult.of(SessionResult.Status.DENIED, d, "resource unknown to the directory", false);
        }

        String token = newToken();
        Duration reauth = limits.reauthFor(resource.get().classification());
        Instant lastAuth = verifiedMfa.orElse(now);
        boolean restricted = d.restricted() || d.outcome() == Outcome.ALLOW_LIMITED;
        Session session = new Session(newSessionId(), Digests.sha256Hex(token), request.subject().id(),
                request.device().id(), request.resource().id(), restricted, proofKey, now, now, lastAuth,
                now.plus(limits.absoluteLifetime()), reauth);

        List<Session> evicted;
        List<Session> expired = new ArrayList<>();
        synchronized (openLock) {
            if (store.size() >= limits.maxSessions()) {
                expired.addAll(store.purgeExpired(now, limits.idleTimeout()));
                if (store.size() >= limits.maxSessions()) {
                    auditEndedQuietly(expired, now);
                    return SessionResult.of(SessionResult.Status.DENIED, d,
                            "session capacity reached; refusing new sessions (fail-closed)", false);
                }
            }
            // The subject's dead sessions do not count towards their limit; they are closed as expired.
            for (Session old : store.ofSubject(session.subjectId())) {
                if (SessionStore.ended(old, now, limits.idleTimeout()).isPresent()) {
                    store.remove(old.tokenHash()).ifPresent(expired::add);
                }
            }
            List<Session> mine = store.ofSubject(session.subjectId());
            int excess = mine.size() - limits.maxSessionsPerSubject() + 1;
            evicted = excess > 0 ? mine.subList(0, excess) : List.of();
            for (Session old : evicted) {
                store.remove(old.tokenHash());
            }
            store.add(session);
        }

        auditEndedQuietly(expired, now);
        try {
            for (Session old : evicted) {
                auditEnd("SESSION_REVOKED", old, ACTOR, "per-subject session limit: oldest session closed", now);
            }
            Map<String, String> f = fields(session);
            f.put("restricted", Boolean.toString(restricted));
            f.put("expiresAt", session.expiresAt().toString());
            f.put("reauthDue", session.reauthDue().toString());
            f.put("decisionRequestId", d.requestId());
            audit.append("SESSION_OPENED", ACTOR, now, f);
        } catch (RuntimeException e) {
            store.remove(session.tokenHash());
            return SessionResult.of(SessionResult.Status.DENIED, d,
                    "audit trail unavailable: no audit, no session", false);
        }
        SessionGrant grant = new SessionGrant(session.sessionId(), token, session.expiresAt(), session.reauthDue(),
                restricted);
        return SessionResult.opened(grant, d, "session " + session.sessionId() + " opened"
                + (restricted ? " read-only" : ""));
    }

    /**
     * Checks one request made on a session, then has the engine decide it again.
     *
     * @param token the bearer token from {@link SessionGrant#token()}
     * @param proof the client's signature over this request with the session key; its key id is the
     *              session id
     */
    public SessionResult use(String token, SignatureProof proof, AccessRequest request, SignalSnapshot signals) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(signals, "signals");
        Instant now = clock.instant();
        Optional<String> skew = clockSkew(request, now);
        if (skew.isPresent()) {
            return SessionResult.rejected(skew.get(), false);
        }
        if (!wellFormed(token)) {
            malformedTokens.incrementAndGet();
            return SessionResult.rejected("malformed session token", false);
        }
        String hash = Digests.sha256Hex(token);
        Optional<Session> found = store.get(hash);
        if (found.isEmpty()) {
            unknownTokens.incrementAndGet();
            return SessionResult.rejected("unknown, expired or revoked session", false);
        }
        Session s = found.get();

        Optional<String> over = SessionStore.ended(s, now, limits.idleTimeout());
        if (over.isPresent()) {
            return endAndReject(s, "SESSION_EXPIRED", over.get(), now);
        }
        if (!request.subject().id().equals(s.subjectId()) || !request.device().id().equals(s.deviceId())) {
            return endAndReject(s, "SESSION_REVOKED",
                    "token presented for another subject or device: possible token theft", now);
        }
        if (!request.resource().id().equals(s.resourceId())) {
            return SessionResult.rejected("token was issued for another resource", false);
        }
        Optional<String> possession = verifyPossession(s, proof, request, now);
        if (possession.isPresent()) {
            auditRefusal("SESSION_PROOF_FAILED", request, s, possession.get(), now);
            return SessionResult.rejected("proof of possession failed: " + possession.get(), false);
        }
        // After the proof: only the key holder can spend a request id, so nobody can burn the victim's ids.
        // '|' cannot occur in an identifier, so keys from different sessions can never collide.
        if (!nonces.firstUse(s.sessionId() + "|" + request.requestId(), now)) {
            auditRefusal("SESSION_REPLAY_REFUSED", request, s, "request id already used", now);
            return SessionResult.rejected("request id already used in this session: replay refused", false);
        }
        String thumbprint = Digests.thumbprint(s.proofKey());
        if (mfaNotBoundTo(request, thumbprint)) {
            auditRefusal("SESSION_MFA_NOT_BOUND", request, s, "MFA proof not bound to the session key", now);
            return SessionResult.rejected("the MFA proof is not bound to this session's key", false);
        }
        if (s.restricted() && request.action() != Action.READ) {
            return SessionResult.of(SessionResult.Status.DENIED, null,
                    "session is read-only; " + request.action() + " refused", false);
        }

        Optional<Instant> freshAuth = verifiedAuthentication(request, now, thumbprint)
                .filter(at -> at.isAfter(s.lastAuthenticatedAt()));
        Instant reauthDue = s.lastAuthenticatedAt().plus(effectiveReauthInterval(s));
        if (!now.isBefore(reauthDue) && freshAuth.isEmpty()) {
            return SessionResult.of(SessionResult.Status.STEP_UP, null,
                    "re-authentication due since " + reauthDue + "; challenge with "
                            + assurance.challengeMethod(), false);
        }

        Decision d = continuous.decide(request, signals);
        switch (d.outcome()) {
            case ALLOW, ALLOW_LIMITED -> {
                boolean limited = d.restricted() || d.outcome() == Outcome.ALLOW_LIMITED;
                Optional<Session> updated = store.update(hash, cur -> {
                    Session u = cur.lastUsedAt().isBefore(now) ? cur.used(now) : cur;
                    if (freshAuth.isPresent() && freshAuth.get().isAfter(u.lastAuthenticatedAt())) {
                        u = u.reauthenticated(freshAuth.get());
                    }
                    return limited ? u.downgraded() : u;
                });
                if (updated.isEmpty()) {
                    return SessionResult.of(SessionResult.Status.REJECTED, d, "session ended during evaluation", true);
                }
                boolean readOnly = updated.get().restricted();
                return SessionResult.of(readOnly ? SessionResult.Status.GRANTED_LIMITED : SessionResult.Status.GRANTED,
                        d, readOnly ? "granted read-only" : "granted", false);
            }
            case STEP_UP -> {
                return SessionResult.of(SessionResult.Status.STEP_UP, d,
                        "the engine requires step-up for this request; challenge with " + assurance.challengeMethod(),
                        false);
            }
            case DENY -> {
                boolean end = request.action() == Action.READ
                        || d.matchedPolicyId().startsWith("hard-gate:")
                        || "fail-closed".equals(d.matchedPolicyId())
                        || d.risk().posteriorAttack() >= limits.revokeAboveRisk();
                if (!end) {
                    return SessionResult.of(SessionResult.Status.DENIED, d,
                            "this action was denied; the session continues", false);
                }
                store.remove(hash);
                boolean audited = tryAuditEnd("SESSION_REVOKED", s, ACTOR,
                        "continuous evaluation denied request " + request.requestId(), now);
                return SessionResult.of(SessionResult.Status.DENIED, d,
                        "continuous evaluation denied the request; session revoked"
                                + (audited ? "" : " (audit trail unavailable)"), true);
            }
            default -> throw new IllegalStateException("unexpected outcome " + d.outcome());
        }
    }

    /** Ends one session. Returns the number of sessions ended (0 or 1). */
    public int revokeSession(String sessionId, String actor, String reason) {
        Validate.id(sessionId, "sessionId");
        return revoke(s -> s.sessionId().equals(sessionId), actor, reason);
    }

    /** Ends every session of a subject: account disabled, password reset, suspected compromise. */
    public int revokeSubject(String subjectId, String actor, String reason) {
        Validate.id(subjectId, "subjectId");
        return revoke(s -> s.subjectId().equals(subjectId), actor, reason);
    }

    /** Ends every session on a device: lost, stolen or compromised. */
    public int revokeDevice(String deviceId, String actor, String reason) {
        Validate.id(deviceId, "deviceId");
        return revoke(s -> s.deviceId().equals(deviceId), actor, reason);
    }

    /** Sessions in the store, including ones whose time ran out but were not yet cleaned up. */
    public int activeSessions() {
        return store.size();
    }

    /**
     * Closes every session whose time ran out, auditing each as expired. Run it on a schedule (every
     * minute, say): sessions are also cleaned up when used, when their subject logs in again, and when
     * the store is full, but an abandoned session would otherwise sit in memory until then.
     */
    public int purgeExpired() {
        Instant now = clock.instant();
        List<Session> expired = store.purgeExpired(now, limits.idleTimeout());
        auditEndedQuietly(expired, now);
        return expired.size();
    }

    /** Refusal events not written to the audit trail because their type and subject were over the limit. */
    public long suppressedAuditEvents() {
        return auditThrottle.refused();
    }

    /** Requests with a token that is not even well-formed (probing, client bugs). */
    public long malformedTokens() {
        return malformedTokens.get();
    }

    /** Requests with a well-formed token that matches no live session (guessing, stale clients). */
    public long unknownTokens() {
        return unknownTokens.get();
    }

    /**
     * Revokes first, then audits. If the audit fails the sessions stay revoked (fail-closed) and the
     * failure is reported to the caller.
     */
    private int revoke(Predicate<Session> which, String actor, String rawReason) {
        Validate.id(actor, "actor");
        String reason = Sanitize.text(Objects.requireNonNull(rawReason, "reason"), MAX_REASON_LENGTH);
        Instant now = clock.instant();
        List<Session> removed = store.removeIf(which);
        RuntimeException firstFailure = null;
        for (Session s : removed) {
            try {
                auditEnd("SESSION_REVOKED", s, actor, reason, now);
            } catch (RuntimeException e) {
                if (firstFailure == null) {
                    firstFailure = e;
                }
            }
        }
        if (firstFailure != null) {
            throw new IllegalStateException("sessions revoked, but the audit trail failed", firstFailure);
        }
        return removed.size();
    }

    private SessionResult endAndReject(Session s, String type, String reason, Instant now) {
        store.remove(s.tokenHash());
        boolean audited = tryAuditEnd(type, s, ACTOR, reason, now);
        return SessionResult.rejected(reason + (audited ? "" : " (audit trail unavailable)"), true);
    }

    private Optional<String> verifyDeviceBinding(AccessRequest request, PublicKey proofKey, SignatureProof binding,
                                                 Instant now) {
        if (binding == null) {
            return Optional.of("no device binding supplied");
        }
        String deviceId = request.device().id();
        KeyRing.Result r = keys.verify(KeyPurpose.DEVICE_AGENT, deviceId, binding,
                SignedMessages.sessionBinding(deviceId, request.requestId(), Digests.thumbprint(proofKey),
                        binding.signedAt()),
                now, limits.maxProofAge());
        if (!r.valid()) {
            return Optional.of(r.reason());
        }
        if (!nonces.firstUse("open|" + deviceId + "|" + request.requestId(), now)) {
            return Optional.of("device binding already used");
        }
        return Optional.empty();
    }

    private Optional<String> verifyPossession(Session s, SignatureProof proof, AccessRequest request, Instant now) {
        if (proof == null) {
            return Optional.of("no proof supplied");
        }
        if (!proof.keyId().equals(s.sessionId())) {
            return Optional.of("proof names another session");
        }
        if (proof.signedAt().isAfter(now.plus(KeyRing.MAX_CLOCK_SKEW))) {
            return Optional.of("proof is dated in the future");
        }
        if (Duration.between(proof.signedAt(), now).compareTo(limits.maxProofAge()) > 0) {
            return Optional.of("proof is older than " + limits.maxProofAge().toSeconds() + " s");
        }
        byte[] message = SignedMessages.sessionUse(s.sessionId(), request.requestId(), request.subject().id(),
                request.device().id(), request.resource().id(), request.action().name(), proof.signedAt());
        if (!Ed25519.verify(s.proofKey(), message, proof.signature())) {
            return Optional.of("signature does not verify with the session key");
        }
        return Optional.empty();
    }

    /** Sessions are live: a request whose time is off from the administrator's clock is refused. */
    private static Optional<String> clockSkew(AccessRequest request, Instant now) {
        Duration skew = Duration.between(now, request.timestamp()).abs();
        if (skew.compareTo(KeyRing.MAX_CLOCK_SKEW) > 0) {
            return Optional.of("request time is " + skew.toSeconds() + " s from the administrator's clock");
        }
        return Optional.empty();
    }

    /** Any MFA claim reaching a session must be bound to that session's key; otherwise it is refused outright. */
    private static boolean mfaNotBoundTo(AccessRequest request, String thumbprint) {
        Optional<AuthenticationContext> auth = request.evidence().authentication();
        return auth.isPresent() && !auth.get().boundTo(thumbprint);
    }

    /**
     * The shorter of the interval fixed at opening and the one for the resource's classification now,
     * so a resource reclassified upwards shortens its open sessions too. An unknown resource gets the
     * shortest interval (the engine will refuse it anyway).
     */
    private Duration effectiveReauthInterval(Session s) {
        Duration current = directory.resource(s.resourceId())
                .map(r -> limits.reauthFor(r.classification()))
                .orElse(limits.reauthFor(DataClassification.RESTRICTED));
        return current.compareTo(s.reauthInterval()) < 0 ? current : s.reauthInterval();
    }

    /**
     * When the request proves a fresh, step-up-grade authentication (signed by the identity provider,
     * bound to this subject, device and session key), the time it happened; never later than now.
     */
    private Optional<Instant> verifiedAuthentication(AccessRequest request, Instant now, String thumbprint) {
        Optional<AuthenticationContext> auth = request.evidence().authentication();
        Optional<SignatureProof> proof = request.evidence().authenticationProof();
        if (auth.isEmpty() || proof.isEmpty() || !auth.get().boundTo(thumbprint)) {
            return Optional.empty();
        }
        AuthenticationContext a = auth.get();
        if (!a.method().satisfiesStepUp() || a.authenticatedAt().isAfter(now.plus(KeyRing.MAX_CLOCK_SKEW))
                || Duration.between(a.authenticatedAt(), now).compareTo(assurance.maxAuthenticationAge()) > 0) {
            return Optional.empty();
        }
        KeyRing.Result r = keys.verify(KeyPurpose.IDENTITY_PROVIDER, null, proof.get(),
                SignedMessages.authentication(request.subject().id(), request.device().id(), a, proof.get().signedAt()),
                now, assurance.maxAuthenticationAge());
        if (!r.valid()) {
            return Optional.empty();
        }
        return Optional.of(a.authenticatedAt().isAfter(now) ? now : a.authenticatedAt());
    }

    private void auditEnd(String type, Session s, String actor, String reason, Instant now) {
        Map<String, String> f = fields(s);
        f.put("reason", reason);
        audit.append(type, actor, now, f);
    }

    /** Sessions cleaned up because their time ran out; they were already unusable. */
    private void auditEndedQuietly(List<Session> expired, Instant now) {
        for (Session s : expired) {
            tryAuditEnd("SESSION_EXPIRED", s, ACTOR,
                    SessionStore.ended(s, now, limits.idleTimeout()).orElse("session time ran out"), now);
        }
    }

    private boolean tryAuditEnd(String type, Session s, String actor, String reason, Instant now) {
        try {
            auditEnd(type, s, actor, reason, now);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * A refused attempt that changes no state: audited best effort (the answer is a refusal either way),
     * and throttled per event type and subject so a flood of refusals cannot flood the audit trail.
     */
    private void auditRefusal(String type, AccessRequest request, Session s, String reason, Instant now) {
        if (!auditThrottle.tryAcquire(type + "|" + request.subject().id(), now)) {
            return;
        }
        Map<String, String> f = s != null ? fields(s) : new LinkedHashMap<>();
        if (s == null) {
            f.put("subjectId", request.subject().id());
            f.put("deviceId", request.device().id());
        }
        f.put("requestId", request.requestId());
        f.put("sourceIp", request.network().ip());
        f.put("reason", reason);
        try {
            audit.append(type, ACTOR, now, f);
        } catch (RuntimeException e) {
            // the request is refused either way
        }
    }

    private static Map<String, String> fields(Session s) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("sessionId", s.sessionId());
        f.put("subjectId", s.subjectId());
        f.put("deviceId", s.deviceId());
        f.put("resourceId", s.resourceId());
        return f;
    }

    private String newToken() {
        byte[] b = new byte[TOKEN_BYTES];
        random.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private String newSessionId() {
        byte[] b = new byte[16];
        random.nextBytes(b);
        return "s-" + HexFormat.of().formatHex(b);
    }

    /** Exactly 43 base64url characters: anything else is refused before any lookup. */
    static boolean wellFormed(String token) {
        if (token == null || token.length() != TOKEN_CHARS) {
            return false;
        }
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    public static final class Builder {
        private DecisionPoint opening;
        private DecisionPoint continuous;
        private AttributeDirectory directory;
        private KeyRing keys;
        private AssuranceSettings assurance = AssuranceSettings.defaults();
        private SessionLimits limits = SessionLimits.defaults();
        private final AuditLog audit;
        private Clock clock = Clock.systemUTC();
        private int nonceCapacity = 200_000;
        private boolean requireMfaAtOpen = true;

        private Builder(AuditLog audit) {
            this.audit = audit;
        }

        /** Decides logins; normally the full pipeline (learning, audit, engine). */
        public Builder opening(DecisionPoint v) {
            opening = v;
            return this;
        }

        /** Decides each use of a session; normally audit + engine without learning. */
        public Builder continuous(DecisionPoint v) {
            continuous = v;
            return this;
        }

        public Builder directory(AttributeDirectory v) {
            directory = v;
            return this;
        }

        public Builder keyRing(KeyRing v) {
            keys = v;
            return this;
        }

        public Builder assurance(AssuranceSettings v) {
            assurance = v;
            return this;
        }

        public Builder limits(SessionLimits v) {
            limits = v;
            return this;
        }

        public Builder clock(Clock v) {
            clock = v;
            return this;
        }

        public Builder nonceCapacity(int v) {
            nonceCapacity = v;
            return this;
        }

        /**
         * Lets a login without verified MFA reach the engine, which then treats authentication as risk
         * evidence only. For tests of the engine path; never for a deployment.
         */
        public Builder allowLoginWithoutMfa() {
            requireMfaAtOpen = false;
            return this;
        }

        public PolicyAdministrator build() {
            return new PolicyAdministrator(this);
        }
    }
}

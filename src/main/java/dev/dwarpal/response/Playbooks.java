package dev.dwarpal.response;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.guard.RateLimiter;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Verdict;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Turns analysts' verdicts into action. A verdict counts only if the {@link VerdictGate} admits it
 * (signed by the analyst's key, recent, used once), it is about an alert in the {@link CaseBook}, and
 * the analyst is not one of the people the case is about.
 *
 * <ul>
 *   <li><b>True positive</b>: the play for the alert's rule runs on the entities the alert names:
 *       revoke (sessions and elevation grants), deny until a time (never more than
 *       {@link ResponseSettings#maxDeny()}), watch with a decaying weight. Every action is audited with
 *       the case and the analyst before it is taken.</li>
 *   <li><b>Two-person rule</b>: when the alert names a privileged or protected person, or the target is a
 *       shared address, destructive steps wait for a second true-positive verdict on the same alert from
 *       another analyst within {@link ResponseSettings#secondAnalystWindow()}. Watches apply at once.</li>
 *   <li><b>Rate limits</b>: destructive actions are limited per hour overall and per analyst, so a flood
 *       of alerts (or one stolen analyst key) cannot lock out the company. Only verified verdicts count.</li>
 *   <li><b>False positive</b>: lifts the case's denies and watches (and only the case's: see
 *       {@link SignalLedger}). Lifting what two analysts confirmed needs two analysts again. Ended
 *       sessions stay ended; the person logs in again.</li>
 *   <li><b>Benign</b>: closes the case without action.</li>
 * </ul>
 */
public final class Playbooks {

    public static final String ACTOR = "soc-playbooks";

    public enum Status {
        /** The play ran in full and the case is closed. */
        APPLIED,
        /** Some steps wait for a second analyst. */
        AWAITING_SECOND_ANALYST,
        /** Closed without action (benign, or a false positive with nothing to lift). */
        CLOSED,
        /** A false positive lifted the case's actions. */
        UNDONE,
        /** Some steps were held back (rate limit) or failed (audit or enforcement down); the case stays triaged. */
        PARTIAL,
        /** The verdict did not count, or contradicted a waiting one (which is then cancelled). */
        REFUSED
    }

    /** The answer to one verdict. */
    public record Result(Status status, Optional<String> caseId, String message, int actions) {
        public Result {
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(caseId, "caseId");
            Objects.requireNonNull(message, "message");
        }
    }

    /** A first verdict waiting for a second analyst. */
    public record Pending(String caseId, String alertId, String analystId, Verdict.Outcome outcome, Instant at) {
    }

    private record Applied(Play.Step step, Entity target, boolean twoPerson) {
    }

    private static final class CaseState {
        Pending pending;
        final LinkedHashMap<String, Applied> applied = new LinkedHashMap<>();

        boolean twoPerson() {
            return applied.values().stream().anyMatch(Applied::twoPerson);
        }
    }

    private final ResponseSettings settings;
    private final CaseBook book;
    private final VerdictGate gate;
    private final SignalLedger ledger;
    private final Enforcement enforcement;
    private final AuditLog audit;
    private final Clock clock;
    private final Map<String, Play> plays;
    private final Play defaultPlay;
    private final Map<String, CaseState> states = new HashMap<>();
    private final RateLimiter overall;
    private final RateLimiter perAnalyst;
    private final RateLimiter refusalAudits = new RateLimiter(20, Duration.ofMinutes(1), 10_000);
    private long refusedVerdicts;
    private long heldBack;

    private Playbooks(Builder b) {
        this.settings = Objects.requireNonNull(b.settings, "settings");
        this.book = Objects.requireNonNull(b.book, "cases");
        this.gate = Objects.requireNonNull(b.gate, "verdicts");
        this.ledger = Objects.requireNonNull(b.ledger, "ledger");
        this.enforcement = Objects.requireNonNull(b.enforcement, "enforcement");
        this.audit = Objects.requireNonNull(b.audit, "audit");
        this.clock = Objects.requireNonNull(b.clock, "clock");
        this.plays = Map.copyOf(b.plays);
        this.defaultPlay = Objects.requireNonNull(b.defaultPlay, "defaultPlay");
        List<Play> all = new ArrayList<>(plays.values());
        all.add(defaultPlay);
        for (Play p : all) {
            for (Play.Step s : p.steps()) {
                if (s instanceof Play.Deny d && d.duration().compareTo(settings.maxDeny()) > 0) {
                    throw new IllegalArgumentException("a play denies for longer than the settings allow");
                }
            }
        }
        this.overall = new RateLimiter(settings.destructivePerHour(), Duration.ofHours(1), 1);
        this.perAnalyst = new RateLimiter(settings.destructivePerAnalyst(), Duration.ofHours(1), 10_000);
    }

    /**
     * The audit trail is not optional (no audit, no action), and neither is the ledger the playbooks share
     * with every other writer to the signal feed.
     */
    public static Builder builder(AuditLog audit, SignalLedger ledger) {
        return new Builder(audit, ledger);
    }

    /**
     * The reference plays, keyed by the rule ids of part A's detection engine. Rules not listed get
     * {@link #cautiousPlay()}.
     */
    public static Map<String, Play> referencePlays() {
        Duration day = Duration.ofDays(1);
        // Keys are part A's rule ids (dev.dwarpal.siem); an integration test checks that every rule has a play.
        // The two deny-storm rules and mfa-fatigue name the person being attacked, whom anyone can name by
        // sending requests: they deny addresses only and watch the person, never deny them.
        Play storm = Play.of(new Play.Deny(Entity.Kind.IP, Duration.ofHours(4)),
                new Play.Watch(Entity.Kind.SUBJECT, Math.log(10), day));
        return Map.ofEntries(
                Map.entry("honeytoken-touched", Play.of(new Play.Revoke(Entity.Kind.SUBJECT),
                        new Play.Revoke(Entity.Kind.DEVICE), new Play.Deny(Entity.Kind.SUBJECT, day),
                        new Play.Deny(Entity.Kind.DEVICE, day), new Play.Deny(Entity.Kind.IP, day))),
                Map.entry("stolen-token-revoked", Play.of(new Play.Revoke(Entity.Kind.SESSION),
                        new Play.Revoke(Entity.Kind.SUBJECT), new Play.Watch(Entity.Kind.SUBJECT, Math.log(100), day))),
                Map.entry("break-glass-used", Play.of(new Play.Revoke(Entity.Kind.SUBJECT),
                        new Play.Deny(Entity.Kind.SUBJECT, day))),
                Map.entry("break-glass-refused", Play.of(new Play.Watch(Entity.Kind.SUBJECT, Math.log(10), day))),
                Map.entry("deny-storm-ip", storm),
                Map.entry("deny-storm-subject", storm),
                Map.entry("mfa-fatigue", Play.of(new Play.Revoke(Entity.Kind.SUBJECT),
                        new Play.Watch(Entity.Kind.SUBJECT, Math.log(100), Duration.ofDays(2)))),
                Map.entry("impossible-travel-allow", Play.of(new Play.Revoke(Entity.Kind.SUBJECT),
                        new Play.Watch(Entity.Kind.SUBJECT, Math.log(100), day))),
                Map.entry("dlp-block-spike", Play.of(new Play.Watch(Entity.Kind.SUBJECT, Math.log(100),
                        Duration.ofDays(7)))),
                Map.entry("pam-refused", Play.of(new Play.Watch(Entity.Kind.SUBJECT, Math.log(10), day))),
                Map.entry("audit-chain-break", Play.of()),
                Map.entry("audit-anchor-mismatch", Play.of()),
                // Detection's own health alerts: for people, not for automatic action.
                Map.entry("alert-flood", Play.of()),
                Map.entry("detection-state-full", Play.of()));
    }

    /** For a rule without a play: watch the people it names (x10, half-life one day), nothing destructive. */
    public static Play cautiousPlay() {
        return Play.of(new Play.Watch(Entity.Kind.SUBJECT, Math.log(10), Duration.ofDays(1)));
    }

    /** Acts on one verdict. Never throws for a well-formed verdict. */
    public synchronized Result handle(Verdict v) {
        Objects.requireNonNull(v, "verdict");
        Optional<String> bad = gate.admit(v);
        if (bad.isPresent()) {
            return refuse(v, Optional.empty(), bad.get());
        }
        Optional<Alert> alert = book.alert(v.alertId());
        Optional<Case> found = book.caseOf(v.alertId());
        if (alert.isEmpty() || found.isEmpty()) {
            return refuse(v, Optional.empty(), "no case holds this alert");
        }
        Case c = found.get();
        if (c.concerns(v.analystId())) {
            return refuse(v, Optional.of(c.id()), "an analyst cannot decide a case about themselves");
        }
        Instant now = clock.instant();
        lapse(c.id(), now);
        Map<String, String> f = fields(c.id(), v.alertId());
        f.put("outcome", v.outcome().name());
        if (!audited("VERDICT_ACCEPTED", v.analystId(), now, f)) {
            return refuse(v, Optional.of(c.id()), "audit trail unavailable");
        }
        return switch (v.outcome()) {
            case TRUE_POSITIVE -> truePositive(c, alert.get(), v, now);
            case FALSE_POSITIVE -> falsePositive(c, v, now);
            case BENIGN -> benign(c, v);
        };
    }

    /** First verdicts waiting for a second analyst. */
    public synchronized List<Pending> pending() {
        Instant now = clock.instant();
        return states.values().stream().map(s -> s.pending).filter(Objects::nonNull)
                .filter(p -> !expired(p, now)).toList();
    }

    /** Verdicts refused (not verified, replayed, unknown alert, own case, audit down). */
    public synchronized long refusedVerdicts() {
        return refusedVerdicts;
    }

    /** Destructive steps held back by the rate limits. */
    public synchronized long heldBack() {
        return heldBack;
    }

    // ---- outcomes ------------------------------------------------------------------------------------

    private Result truePositive(Case c, Alert alert, Verdict v, Instant now) {
        CaseState st = states.computeIfAbsent(c.id(), k -> new CaseState());
        boolean confirmed = false;
        if (st.pending != null) {
            Pending p = st.pending;
            if (p.outcome() != Verdict.Outcome.TRUE_POSITIVE) {
                return disagree(c, st, v, now);
            }
            if (p.analystId().equals(v.analystId())) {
                return refuse(v, Optional.of(c.id()), "the second verdict must come from another analyst");
            }
            if (!p.alertId().equals(v.alertId())) {
                return refuse(v, Optional.of(c.id()), "the second analyst must confirm the same alert");
            }
            confirmed = true;
            st.pending = null;
        } else if (c.state() == Case.State.CLOSED) {
            forgetIfEmpty(c.id(), st);
            return refuse(v, Optional.of(c.id()), "case already decided");
        }
        Play play = plays.getOrDefault(alert.rule(), defaultPlay);
        boolean protectedAlert = alert.entities().stream()
                .anyMatch(e -> e.kind() == Entity.Kind.SUBJECT && protectedSubject(e.id(), now));
        int done = 0;
        boolean needSecond = false;
        boolean limited = false;
        boolean failed = false;
        for (int i = 0; i < play.steps().size() && !failed; i++) {
            Play.Step step = play.steps().get(i);
            for (Entity target : alert.entities()) {
                if (target.kind() != step.target()) {
                    continue;
                }
                String key = i + "|" + target.kind() + "|" + target.id();
                if (st.applied.containsKey(key)) {
                    continue;
                }
                boolean twoPerson = step.destructive() && (protectedAlert
                        || (target.kind() == Entity.Kind.IP && settings.sharedAddresses().contains(target.id())));
                if (twoPerson && !confirmed) {
                    needSecond = true;
                    continue;
                }
                if (step.destructive() && !permit(v.analystId(), now)) {
                    limited = true;
                    continue;
                }
                if (!audited("RESPONSE_ACTION", v.analystId(), now, action(c.id(), alert.id(), step, target, confirmed))
                        || !execute(c.id(), alert, step, target, v.analystId())) {
                    failed = true;
                    break;
                }
                st.applied.put(key, new Applied(step, target, twoPerson));
                done++;
            }
        }
        boolean holds = !st.applied.isEmpty();
        if (needSecond) {
            st.pending = new Pending(c.id(), alert.id(), v.analystId(), Verdict.Outcome.TRUE_POSITIVE, now);
            Map<String, String> f = fields(c.id(), alert.id());
            f.put("waitingFor", "second analyst");
            audited("RESPONSE_PENDING", v.analystId(), now, f);
            book.triage(c.id(), v.analystId(), "true positive; protected target needs a second analyst");
            return new Result(Status.AWAITING_SECOND_ANALYST, Optional.of(c.id()),
                    "destructive steps wait for a second analyst", done);
        }
        if (limited || failed) {
            book.triage(c.id(), v.analystId(), limited ? "rate limited" : "an action failed");
            return new Result(Status.PARTIAL, Optional.of(c.id()), limited
                    ? "rate limit reached: some steps held back; send a new verdict later"
                    : "an action failed (audit or enforcement unavailable); send a new verdict to retry", done);
        }
        book.close(c.id(), v.analystId(), "true positive", holds);
        forgetIfEmpty(c.id(), st);
        return new Result(Status.APPLIED, Optional.of(c.id()), "play applied", done);
    }

    private Result falsePositive(Case c, Verdict v, Instant now) {
        CaseState st = states.get(c.id());
        if (st == null || st.applied.isEmpty()) {
            states.remove(c.id());
            if (c.state() == Case.State.CLOSED) {
                return refuse(v, Optional.of(c.id()), "case already decided, nothing to lift");
            }
            book.close(c.id(), v.analystId(), "false positive", false);
            return new Result(Status.CLOSED, Optional.of(c.id()), "closed as false positive", 0);
        }
        if (st.twoPerson()) {
            Pending p = st.pending;
            if (p == null || p.outcome() != Verdict.Outcome.FALSE_POSITIVE) {
                st.pending = new Pending(c.id(), v.alertId(), v.analystId(), Verdict.Outcome.FALSE_POSITIVE, now);
                Map<String, String> f = fields(c.id(), v.alertId());
                f.put("waitingFor", "second analyst to lift");
                audited("RESPONSE_PENDING", v.analystId(), now, f);
                return new Result(Status.AWAITING_SECOND_ANALYST, Optional.of(c.id()),
                        "two analysts confirmed these actions; lifting them needs two as well", 0);
            }
            if (p.analystId().equals(v.analystId())) {
                return refuse(v, Optional.of(c.id()), "the second verdict must come from another analyst");
            }
        }
        st.pending = null;
        int lifted = 0;
        boolean ok = true;
        java.util.Set<Entity> done = new java.util.HashSet<>();
        for (Applied a : List.copyOf(st.applied.values())) {
            if (a.step() instanceof Play.Revoke || !done.add(a.target())) {
                continue;
            }
            Map<String, String> f = fields(c.id(), v.alertId());
            f.put("kind", a.target().kind().name());
            f.put("target", a.target().id());
            if (!audited("RESPONSE_UNDONE", v.analystId(), now, f)) {
                ok = false;
                break;
            }
            if (ledger.lift(c.id(), Play.feedKind(a.target().kind()), a.target().id(), v.analystId(),
                    "false positive on " + c.id())) {
                lifted++;
            } else {
                ok = false;
            }
        }
        if (!ok) {
            return new Result(Status.PARTIAL, Optional.of(c.id()),
                    "some actions could not be lifted (audit or signal feed unavailable); send a new verdict to retry",
                    lifted);
        }
        st.applied.clear();
        states.remove(c.id());
        if (c.state() == Case.State.CLOSED) {
            book.release(c.id(), v.analystId(), "false positive: actions lifted");
        } else {
            book.close(c.id(), v.analystId(), "false positive: actions lifted", false);
        }
        return new Result(Status.UNDONE, Optional.of(c.id()),
                "denies and watches lifted; ended sessions stay ended (the person logs in again)", lifted);
    }

    private Result benign(Case c, Verdict v) {
        CaseState st = states.get(c.id());
        if (c.state() == Case.State.CLOSED) {
            return refuse(v, Optional.of(c.id()), "case already decided");
        }
        if (st != null && !st.applied.isEmpty()) {
            return refuse(v, Optional.of(c.id()), "actions are in force: a false-positive verdict lifts them");
        }
        states.remove(c.id());
        book.close(c.id(), v.analystId(), "benign", false);
        return new Result(Status.CLOSED, Optional.of(c.id()), "closed as benign", 0);
    }

    /** Two analysts disagree: the waiting verdict is cancelled and nothing more happens. */
    private Result disagree(Case c, CaseState st, Verdict v, Instant now) {
        Map<String, String> f = fields(c.id(), v.alertId());
        f.put("cancelled", st.pending.outcome().name());
        f.put("firstAnalyst", st.pending.analystId());
        audited("RESPONSE_PENDING_CANCELLED", v.analystId(), now, f);
        st.pending = null;
        forgetIfEmpty(c.id(), st);
        refusedVerdicts++;
        return new Result(Status.REFUSED, Optional.of(c.id()), "analysts disagree: the waiting verdict is cancelled", 0);
    }

    // ---- actions -------------------------------------------------------------------------------------

    private boolean execute(String caseId, Alert alert, Play.Step step, Entity target, String analyst) {
        String reason = caseId + " alert " + alert.id() + " rule " + alert.rule();
        try {
            return switch (step) {
                case Play.Revoke r -> {
                    switch (r.target()) {
                        case SUBJECT -> enforcement.revokeSubject(target.id(), analyst, reason);
                        case DEVICE -> enforcement.revokeDevice(target.id(), analyst, reason);
                        default -> enforcement.revokeSession(target.id(), analyst, reason);
                    }
                    yield true;
                }
                case Play.Deny d -> ledger.deny(caseId, Play.feedKind(target.kind()), target.id(), d.duration(), analyst,
                        reason);
                case Play.Watch w -> ledger.watch(caseId, Play.feedKind(target.kind()), target.id(), w.logLr(),
                        w.halfLife(), analyst, reason);
            };
        } catch (RuntimeException e) {
            // Enforcement down, or revoked but its audit failed: report it; the verdict can be sent again.
            return false;
        }
    }

    private boolean protectedSubject(String subjectId, Instant now) {
        if (settings.protectedSubjects().contains(subjectId)) {
            return true;
        }
        try {
            Set<String> roles = enforcement.rolesOf(subjectId, now);
            return roles.stream().anyMatch(settings.privilegedRoles()::contains);
        } catch (RuntimeException e) {
            return true;    // cannot tell: treat as privileged (two analysts), never as ordinary
        }
    }

    private boolean permit(String analyst, Instant now) {
        if (perAnalyst.tryAcquire(analyst, now) && overall.tryAcquire("all", now)) {
            return true;
        }
        heldBack++;
        return false;
    }

    private void lapse(String caseId, Instant now) {
        CaseState st = states.get(caseId);
        if (st != null && st.pending != null && expired(st.pending, now)) {
            Map<String, String> f = fields(caseId, st.pending.alertId());
            f.put("firstAnalyst", st.pending.analystId());
            audited("RESPONSE_PENDING_LAPSED", ACTOR, now, f);
            st.pending = null;
            forgetIfEmpty(caseId, st);
        }
    }

    private boolean expired(Pending p, Instant now) {
        return !now.isBefore(p.at().plus(settings.secondAnalystWindow()));
    }

    private void forgetIfEmpty(String caseId, CaseState st) {
        if (st.pending == null && st.applied.isEmpty()) {
            states.remove(caseId);
        }
    }

    private Result refuse(Verdict v, Optional<String> caseId, String why) {
        refusedVerdicts++;
        Instant now = clock.instant();
        if (refusalAudits.tryAcquire(v.analystId(), now)) {
            Map<String, String> f = new LinkedHashMap<>();
            f.put("alert", v.alertId());
            f.put("claimedAnalyst", v.analystId());
            f.put("outcome", v.outcome().name());
            f.put("reason", why);
            audited("VERDICT_REFUSED", ACTOR, now, f);
        }
        return new Result(Status.REFUSED, caseId, why, 0);
    }

    private boolean audited(String type, String actor, Instant now, Map<String, String> fields) {
        try {
            audit.append(type, Validate.id(actor, "actor"), now, fields);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static Map<String, String> fields(String caseId, String alertId) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("case", caseId);
        f.put("alert", alertId);
        return f;
    }

    private static Map<String, String> action(String caseId, String alertId, Play.Step step, Entity target,
                                              boolean secondAnalyst) {
        Map<String, String> f = fields(caseId, alertId);
        f.put("step", step.getClass().getSimpleName().toLowerCase(java.util.Locale.ROOT));
        f.put("kind", target.kind().name());
        f.put("target", target.id());
        f.put("twoAnalysts", Boolean.toString(secondAnalyst));
        switch (step) {
            case Play.Deny d -> f.put("duration", d.duration().toString());
            case Play.Watch w -> {
                f.put("logLr", Double.toString(w.logLr()));
                f.put("halfLife", w.halfLife().toString());
            }
            case Play.Revoke r -> f.put("scope", r.target().name());
        }
        return f;
    }

    public static final class Builder {
        private final AuditLog audit;
        private ResponseSettings settings = ResponseSettings.defaults();
        private CaseBook book;
        private VerdictGate gate;
        private final SignalLedger ledger;
        private Enforcement enforcement;
        private Clock clock = Clock.systemUTC();
        private final Map<String, Play> plays = new HashMap<>(referencePlays());
        private Play defaultPlay = cautiousPlay();

        private Builder(AuditLog audit, SignalLedger ledger) {
            this.audit = audit;
            this.ledger = ledger;
        }

        public Builder settings(ResponseSettings v) {
            settings = v;
            return this;
        }

        public Builder cases(CaseBook v) {
            book = v;
            return this;
        }

        public Builder verdicts(VerdictGate v) {
            gate = v;
            return this;
        }

        public Builder enforcement(Enforcement v) {
            enforcement = v;
            return this;
        }

        public Builder clock(Clock v) {
            clock = v;
            return this;
        }

        /** Replaces the play for one rule. */
        public Builder play(String rule, Play play) {
            plays.put(Validate.id(rule, "rule"), Objects.requireNonNull(play, "play"));
            return this;
        }

        public Builder defaultPlay(Play v) {
            defaultPlay = v;
            return this;
        }

        public Playbooks build() {
            return new Playbooks(this);
        }
    }
}

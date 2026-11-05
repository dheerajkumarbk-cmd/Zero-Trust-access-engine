package dev.dwarpal.response;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertSink;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Severity;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The SOC's case book: alerts become cases, grouped by the entity they are about, and move from OPEN
 * to TRIAGED to CLOSED. It is an {@link AlertSink}, so detection writes straight into it.
 *
 * <ul>
 *   <li><b>Grouped.</b> An alert joins the case that is not yet closed for its key entity (the first
 *       person it names, otherwise its first entity); otherwise it opens a new case. An alert id is
 *       accepted once.</li>
 *   <li><b>Bounded.</b> At most {@link ResponseSettings#maxCases()} cases and
 *       {@link ResponseSettings#maxAlertsPerCase()} alerts per case. When full, the oldest closed case
 *       that no longer holds actions is forgotten; failing that, the oldest untouched open case of
 *       lower severity than the new alert is dropped (audited); if there is none, the new alert is
 *       refused and counted, never silently lost.</li>
 *   <li><b>Audited first.</b> Every change is written to the audit trail before it happens: no audit,
 *       no change.</li>
 * </ul>
 */
public final class CaseBook implements AlertSink {

    public static final String ACTOR = "soc-casebook";
    public static final int MAX_REASON = 256;

    private static final class Entry {
        final String id;
        final Entity key;
        final Instant openedAt;
        final List<Alert> alerts = new ArrayList<>();
        Case.State state = Case.State.OPEN;
        Severity severity;
        boolean holdsActions;

        Entry(String id, Entity key, Instant openedAt, Severity severity) {
            this.id = id;
            this.key = key;
            this.openedAt = openedAt;
            this.severity = severity;
        }

        Case view() {
            return new Case(id, key, state, severity, openedAt, alerts, holdsActions);
        }
    }

    private final ResponseSettings settings;
    private final AuditLog audit;
    private final Clock clock;
    private final LinkedHashMap<String, Entry> cases = new LinkedHashMap<>();
    /** The case not yet closed for each key entity. */
    private final Map<Entity, String> live = new HashMap<>();
    private final Map<String, String> caseOfAlert = new HashMap<>();
    private long nextId = 1;
    private long refused;
    private long dropped;

    public CaseBook(ResponseSettings settings, AuditLog audit, Clock clock) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public synchronized boolean raise(Alert alert) {
        Objects.requireNonNull(alert, "alert");
        if (caseOfAlert.containsKey(alert.id())) {
            return false;
        }
        Entity key = keyOf(alert);
        Instant now = clock.instant();
        String liveId = live.get(key);
        if (liveId != null) {
            Entry e = cases.get(liveId);
            if (e.alerts.size() >= settings.maxAlertsPerCase()) {
                refused++;
                return false;
            }
            if (!audited("CASE_ALERT", ACTOR, now, fields(e.id, alert))) {
                return false;
            }
            e.alerts.add(alert);
            e.severity = alert.severity().atLeast(e.severity) ? alert.severity() : e.severity;
            caseOfAlert.put(alert.id(), e.id);
            return true;
        }
        if (cases.size() >= settings.maxCases() && !forgetOneClosed() && !dropOneLessSevere(alert, now)) {
            refused++;
            return false;
        }
        String id = "case-" + nextId;
        Map<String, String> f = fields(id, alert);
        f.put("entityKind", key.kind().name());
        f.put("entity", key.id());
        if (!audited("CASE_OPENED", ACTOR, now, f)) {
            return false;
        }
        nextId++;
        Entry e = new Entry(id, key, now, alert.severity());
        e.alerts.add(alert);
        cases.put(id, e);
        live.put(key, id);
        caseOfAlert.put(alert.id(), id);
        return true;
    }

    public synchronized Optional<Case> get(String caseId) {
        Entry e = cases.get(caseId);
        return e == null ? Optional.empty() : Optional.of(e.view());
    }

    /** The case an alert belongs to. */
    public synchronized Optional<Case> caseOf(String alertId) {
        String id = caseOfAlert.get(alertId);
        return id == null ? Optional.empty() : get(id);
    }

    /** The alert with this id, if a case holds it. */
    public synchronized Optional<Alert> alert(String alertId) {
        String id = caseOfAlert.get(alertId);
        if (id == null) {
            return Optional.empty();
        }
        return cases.get(id).alerts.stream().filter(a -> a.id().equals(alertId)).findFirst();
    }

    /** Cases not yet closed, oldest first. */
    public synchronized List<Case> unresolved() {
        return cases.values().stream().filter(e -> e.state != Case.State.CLOSED).map(Entry::view).toList();
    }

    /** OPEN to TRIAGED. */
    synchronized boolean triage(String caseId, String actor, String reason) {
        Entry e = cases.get(caseId);
        if (e == null || e.state != Case.State.OPEN) {
            return false;
        }
        return move(e, Case.State.TRIAGED, actor, reason, e.holdsActions);
    }

    /** OPEN or TRIAGED to CLOSED, recording whether the case's actions are still in force. */
    synchronized boolean close(String caseId, String actor, String reason, boolean holdsActions) {
        Entry e = cases.get(caseId);
        if (e == null || e.state == Case.State.CLOSED) {
            return false;
        }
        return move(e, Case.State.CLOSED, actor, reason, holdsActions);
    }

    /** A closed case's actions were lifted (or ended): it may now be forgotten when space is needed. */
    synchronized boolean release(String caseId, String actor, String reason) {
        Entry e = cases.get(caseId);
        if (e == null || e.state != Case.State.CLOSED || !e.holdsActions) {
            return false;
        }
        Map<String, String> f = new LinkedHashMap<>();
        f.put("case", e.id);
        f.put("reason", Sanitize.text(reason, MAX_REASON));
        if (!audited("CASE_RELEASED", actor, clock.instant(), f)) {
            return false;
        }
        e.holdsActions = false;
        return true;
    }

    public synchronized int size() {
        return cases.size();
    }

    /** Alerts refused because the book or their case was full. */
    public synchronized long refused() {
        return refused;
    }

    private boolean move(Entry e, Case.State to, String actor, String reason, boolean holdsActions) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("case", e.id);
        f.put("from", e.state.name());
        f.put("to", to.name());
        f.put("reason", Sanitize.text(Objects.requireNonNull(reason, "reason"), MAX_REASON));
        if (!audited("CASE_STATE", actor, clock.instant(), f)) {
            return false;
        }
        e.state = to;
        e.holdsActions = holdsActions;
        if (to == Case.State.CLOSED) {
            live.remove(e.key, e.id);
        }
        return true;
    }

    private boolean forgetOneClosed() {
        Iterator<Entry> it = cases.values().iterator();
        while (it.hasNext()) {
            Entry e = it.next();
            if (e.state == Case.State.CLOSED && !e.holdsActions) {
                it.remove();
                e.alerts.forEach(a -> caseOfAlert.remove(a.id()));
                return true;
            }
        }
        return false;
    }

    /**
     * Full of live cases: the oldest untouched (OPEN) case of lower severity than the new alert makes way,
     * audited, so a flood of low alerts cannot shut out a critical one.
     */
    private boolean dropOneLessSevere(Alert alert, Instant now) {
        for (Entry e : cases.values()) {
            if (e.state == Case.State.OPEN && !e.holdsActions && !e.severity.atLeast(alert.severity())) {
                Map<String, String> f = new LinkedHashMap<>();
                f.put("case", e.id);
                f.put("severity", e.severity.name());
                f.put("forAlert", alert.id());
                f.put("forSeverity", alert.severity().name());
                if (!audited("CASE_DROPPED", ACTOR, now, f)) {
                    return false;
                }
                cases.remove(e.id);
                live.remove(e.key, e.id);
                e.alerts.forEach(a -> caseOfAlert.remove(a.id()));
                dropped++;
                return true;
            }
        }
        return false;
    }

    /** Open cases dropped to make way for a more severe alert. */
    public synchronized long dropped() {
        return dropped;
    }

    private boolean audited(String type, String actor, Instant now, Map<String, String> fields) {
        try {
            audit.append(type, Validate.id(actor, "actor"), now, fields);
            return true;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private static Map<String, String> fields(String caseId, Alert a) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("case", caseId);
        f.put("alert", a.id());
        f.put("rule", a.rule());
        f.put("severity", a.severity().name());
        return f;
    }

    private static Entity keyOf(Alert a) {
        return a.entities().stream().filter(x -> x.kind() == Entity.Kind.SUBJECT).findFirst()
                .orElse(a.entities().getFirst());
    }
}

package dev.dwarpal.soar;

import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.domain.Sanitize;
import dev.dwarpal.domain.Validate;
import dev.dwarpal.response.Case;
import dev.dwarpal.response.CaseBook;
import dev.dwarpal.soc.Alert;
import dev.dwarpal.soc.AlertRanker;
import dev.dwarpal.soc.AlertSink;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.RankedAlert;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Case management on top of part B's {@link CaseBook}: who works a case, notes, a service-level deadline by
 * priority, a timeline and links between cases about the same entities. It is the {@link AlertSink} detection
 * writes to: each alert goes into the case book first, then is ranked ({@link AlertRanker}) and recorded here.
 *
 * <p>Rules, enforced here so no caller can skip them:
 * <ul>
 *   <li><b>Nobody works their own case.</b> An analyst named in a case cannot be assigned it, take it, or write
 *       notes on it; cases about any analyst are seen only by leads who are not named in them.</li>
 *   <li><b>Assignment.</b> An analyst may take an unassigned case for themselves; only a lead assigns to others or
 *       takes a case from someone.</li>
 *   <li><b>Bounded.</b> Notes per case, characters per note (longer is refused, not cut), timeline entries (the
 *       oldest after the first are dropped and counted) and links are all limited; entries follow the case book's
 *       own bound and are forgotten with its cases.</li>
 *   <li><b>Audited first.</b> Assignments and notes are written to the audit trail before they change anything
 *       (notes as their SHA-256 and length: the text stays here). Ranking is shown even when its audit record
 *       cannot be written, because hiding an alert's priority is the less safe failure; such failures are counted.</li>
 *   <li><b>Ranking fails safe.</b> If the ranker fails, the alert is shown as P2 and not actionable (no destructive
 *       play can run on it), never as low priority.</li>
 * </ul>
 */
public final class CaseManager implements AlertSink {

    public static final String ACTOR = "soc-cases";

    /** The answer to a change request; the API maps these to fixed, generic replies. */
    public enum Outcome { OK, NOT_FOUND, FORBIDDEN, CONFLICT, INVALID, UNAVAILABLE }

    private static final class Entry {
        final String id;
        final Map<String, RankedAlert> alerts = new LinkedHashMap<>();
        final List<CaseView.Note> notes = new ArrayList<>();
        final List<CaseView.TimelineEntry> timeline = new ArrayList<>();
        final Set<String> links = new LinkedHashSet<>();
        Priority priority;
        double score;
        Instant deadline;
        Instant acknowledgedAt;
        boolean lateResponse;
        String assignee;
        boolean awaitingSecond;
        long dropped;
        int noteCount;

        Entry(String id, Priority priority, Instant deadline) {
            this.id = id;
            this.priority = priority;
            this.deadline = deadline;
        }
    }

    private final CaseBook book;
    private final AlertRanker ranker;
    private final AuditLog audit;
    private final Clock clock;
    private final CaseSettings settings;
    private final Map<String, Analyst> analysts;
    private final LinkedHashMap<String, Entry> entries = new LinkedHashMap<>();
    private final Map<String, RankedAlert> rankedById = new HashMap<>();
    private long auditFailures;
    private long rankerFailures;

    public CaseManager(CaseBook book, AlertRanker ranker, AuditLog audit, Clock clock, CaseSettings settings,
                       Collection<Analyst> analysts) {
        this.book = Objects.requireNonNull(book, "book");
        this.ranker = Objects.requireNonNull(ranker, "ranker");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.settings = Objects.requireNonNull(settings, "settings");
        Map<String, Analyst> m = new LinkedHashMap<>();
        for (Analyst a : analysts) {
            if (m.putIfAbsent(a.id(), a) != null) {
                throw new IllegalArgumentException("analyst listed twice: " + a.id());
            }
        }
        this.analysts = Map.copyOf(m);
    }

    // ---- alerts ---------------------------------------------------------------------------------------------

    @Override
    public synchronized boolean raise(Alert alert) {
        Objects.requireNonNull(alert, "alert");
        if (!book.raise(alert)) {
            return false;
        }
        Optional<Case> c = book.caseOf(alert.id());
        if (c.isEmpty()) {
            return true;    // accepted and already forgotten (the book made room): nothing to manage
        }
        Instant now = clock.instant();
        RankedAlert r = rank(alert, now);
        prune();
        Entry e = entries.get(c.get().id());
        boolean opened = e == null;
        if (opened) {
            e = new Entry(c.get().id(), r.priority(), now.plus(settings.sla(r.priority())));
            entries.put(e.id, e);
            add(e, now, CaseView.TimelineEntry.Kind.OPENED, ACTOR, "opened by " + alert.id());
        }
        e.alerts.put(alert.id(), r);
        rankedById.put(alert.id(), r);
        e.score = Math.max(e.score, r.score());
        add(e, now, CaseView.TimelineEntry.Kind.ALERT, ACTOR, alert.id() + " " + alert.rule() + " "
                + alert.severity() + " ranked " + r.priority() + (r.actionable() ? "" : " (collected evidence only)"));
        if (opened || r.priority().atLeast(e.priority) && r.priority() != e.priority) {
            Priority before = e.priority;
            e.priority = r.priority();
            Instant due = now.plus(settings.sla(e.priority));
            if (due.isBefore(e.deadline)) {
                e.deadline = due;
            }
            Map<String, String> f = new LinkedHashMap<>();
            f.put("case", e.id);
            f.put("priority", e.priority.name());
            f.put("deadline", e.deadline.toString());
            f.put("alert", alert.id());
            audited("CASE_PRIORITY", ACTOR, now, f);
            if (!opened) {
                add(e, now, CaseView.TimelineEntry.Kind.PRIORITY, ACTOR, before + " to " + e.priority);
            }
        }
        if (opened) {
            link(e, c.get(), now);
        }
        return true;
    }

    private RankedAlert rank(Alert alert, Instant now) {
        try {
            RankedAlert r = ranker.rank(alert, now);
            if (r == null || !r.alert().id().equals(alert.id())) {
                throw new IllegalStateException("ranker answered about another alert");
            }
            return r;
        } catch (RuntimeException e) {
            rankerFailures++;
            return new RankedAlert(alert, Priority.P2, 50, List.of(), false,
                    List.of("ranking unavailable: shown as P2, not actionable"));
        }
    }

    /** Links a new case with the cases still tracked that name any of the same entities. */
    private void link(Entry e, Case c, Instant now) {
        Set<Entity> mine = c.entities();
        for (Entry other : entries.values()) {
            if (other == e || e.links.size() >= settings.maxLinks()) {
                continue;
            }
            Optional<Case> oc = book.get(other.id);
            if (oc.isEmpty() || oc.get().entities().stream().noneMatch(mine::contains)) {
                continue;
            }
            Map<String, String> f = new LinkedHashMap<>();
            f.put("case", e.id);
            f.put("linked", other.id);
            audited("CASE_LINKED", ACTOR, now, f);
            e.links.add(other.id);
            add(e, now, CaseView.TimelineEntry.Kind.LINKED, ACTOR, "shares entities with " + other.id);
            if (other.links.size() < settings.maxLinks() && other.links.add(e.id)) {
                add(other, now, CaseView.TimelineEntry.Kind.LINKED, ACTOR, "shares entities with " + e.id);
            }
        }
    }

    // ---- changes by analysts --------------------------------------------------------------------------------

    /** Assigns a case. See the class rules. */
    public synchronized Outcome assign(String caseId, Analyst actor, String assigneeId) {
        Objects.requireNonNull(actor, "actor");
        Optional<Entry> found = live(caseId);
        if (found.isEmpty() || !canSee(actor, caseId)) {
            return Outcome.NOT_FOUND;
        }
        Analyst assignee = analysts.get(assigneeId);
        if (assignee == null) {
            return Outcome.INVALID;
        }
        Entry e = found.get();
        Case c = book.get(caseId).orElseThrow();
        if (c.state() == Case.State.CLOSED) {
            return Outcome.CONFLICT;
        }
        if (c.concerns(assignee.id())) {
            return Outcome.FORBIDDEN;
        }
        if (!actor.lead() && (!assignee.id().equals(actor.id()) || e.assignee != null && !e.assignee.equals(actor.id()))) {
            return Outcome.FORBIDDEN;
        }
        if (assignee.id().equals(e.assignee)) {
            return Outcome.OK;
        }
        Instant now = clock.instant();
        Map<String, String> f = new LinkedHashMap<>();
        f.put("case", caseId);
        f.put("assignee", assignee.id());
        f.put("previous", e.assignee == null ? "none" : e.assignee);
        if (!audited("CASE_ASSIGNED", actor.id(), now, f)) {
            return Outcome.UNAVAILABLE;
        }
        e.assignee = assignee.id();
        acknowledge(e, now);
        add(e, now, CaseView.TimelineEntry.Kind.ASSIGNED, actor.id(), "assigned to " + assignee.id());
        return Outcome.OK;
    }

    /** Adds a note. The text is sanitised (no line breaks, controls or bidi) and refused when too long or blank. */
    public synchronized Outcome note(String caseId, Analyst actor, String text) {
        Objects.requireNonNull(actor, "actor");
        Objects.requireNonNull(text, "text");
        Optional<Entry> found = live(caseId);
        if (found.isEmpty() || !canSee(actor, caseId)) {
            return Outcome.NOT_FOUND;
        }
        if (text.isBlank() || text.length() > settings.maxNoteChars()) {
            return Outcome.INVALID;
        }
        Entry e = found.get();
        if (e.notes.size() >= settings.maxNotes()) {
            return Outcome.CONFLICT;
        }
        String clean = Sanitize.text(text, settings.maxNoteChars());
        Instant now = clock.instant();
        String noteId = "n-" + caseId + "-" + (e.noteCount + 1);
        Map<String, String> f = new LinkedHashMap<>();
        f.put("case", caseId);
        f.put("note", noteId);
        f.put("sha256", Digests.sha256Hex(clean));
        f.put("chars", Integer.toString(clean.length()));
        if (!audited("CASE_NOTE", actor.id(), now, f)) {
            return Outcome.UNAVAILABLE;
        }
        e.noteCount++;
        e.notes.add(new CaseView.Note(noteId, actor.id(), now, clean));
        acknowledge(e, now);
        add(e, now, CaseView.TimelineEntry.Kind.NOTE, actor.id(), noteId);
        return Outcome.OK;
    }

    // ---- changes by the SOAR (already audited where they happen) --------------------------------------------

    /** Records something that happened to a case (a verdict, an action, an isolation, a notification). */
    synchronized void record(String caseId, CaseView.TimelineEntry.Kind kind, String actor, String detail) {
        Entry e = entries.get(caseId);
        if (e == null) {
            return;
        }
        Instant now = clock.instant();
        if (kind == CaseView.TimelineEntry.Kind.VERDICT) {
            acknowledge(e, now);
        }
        add(e, now, kind, actor, detail);
    }

    synchronized void awaitingSecond(String caseId, boolean waiting) {
        Entry e = entries.get(caseId);
        if (e != null) {
            e.awaitingSecond = waiting;
        }
    }

    // ---- reading --------------------------------------------------------------------------------------------

    /** The ranked alert, if a tracked case holds it. */
    public synchronized Optional<RankedAlert> ranked(String alertId) {
        return Optional.ofNullable(rankedById.get(alertId)).filter(r -> book.alert(alertId).isPresent());
    }

    /** The id of the tracked case that holds an alert. */
    public synchronized Optional<String> caseOfAlert(String alertId) {
        return book.caseOf(alertId).map(Case::id).filter(entries::containsKey);
    }

    public synchronized Optional<CaseView> view(String caseId) {
        prune();
        Entry e = entries.get(caseId);
        if (e == null) {
            return Optional.empty();
        }
        return book.get(caseId).map(c -> view(e, c, clock.instant()));
    }

    /** Every tracked case, most urgent first (priority, then breached, then deadline). */
    public synchronized List<CaseView> all() {
        prune();
        Instant now = clock.instant();
        List<CaseView> out = new ArrayList<>();
        for (Entry e : entries.values()) {
            book.get(e.id).ifPresent(c -> out.add(view(e, c, now)));
        }
        out.sort(Comparator.comparing(CaseView::priority).thenComparing(v -> !v.breached())
                .thenComparing(CaseView::deadline).thenComparing(v -> -v.score()));
        return out;
    }

    /** Whether an analyst may see a case (see the class rules). */
    public synchronized boolean canSee(Analyst who, String caseId) {
        Entry e = entries.get(caseId);
        Optional<Case> c = book.get(caseId);
        if (e == null || c.isEmpty() || analysts.get(who.id()) == null || !analysts.get(who.id()).equals(who)) {
            return false;
        }
        Case k = c.get();
        if (k.concerns(who.id())) {
            return false;
        }
        boolean aboutAnalyst = analysts.keySet().stream().anyMatch(k::concerns);
        if (who.lead()) {
            return true;
        }
        if (aboutAnalyst) {
            return false;
        }
        return e.assignee == null || e.assignee.equals(who.id()) || e.awaitingSecond;
    }

    /** Whether an entity names an analyst (so only leads, and not that analyst, may read about it). */
    public boolean aboutAnalyst(Entity e) {
        return e.kind() == Entity.Kind.SUBJECT && analysts.containsKey(e.id());
    }

    public Optional<Analyst> analyst(String id) {
        return Optional.ofNullable(analysts.get(id));
    }

    /** Counters for the metrics endpoint. */
    public record Metrics(int tracked, Map<Priority, Integer> openByPriority, int breached, int unassigned,
                          long auditFailures, long rankerFailures, long refusedByBook) {
        public Metrics {
            openByPriority = Map.copyOf(openByPriority);
        }
    }

    public synchronized Metrics metrics() {
        Map<Priority, Integer> open = new java.util.EnumMap<>(Priority.class);
        for (Priority p : Priority.values()) {
            open.put(p, 0);
        }
        int breached = 0;
        int unassigned = 0;
        for (CaseView v : all()) {
            if (v.state() != Case.State.CLOSED) {
                open.merge(v.priority(), 1, Integer::sum);
                if (v.assignee().isEmpty()) {
                    unassigned++;
                }
            }
            if (v.breached()) {
                breached++;
            }
        }
        return new Metrics(entries.size(), open, breached, unassigned, auditFailures, rankerFailures, book.refused());
    }

    // ---- internals ------------------------------------------------------------------------------------------

    private CaseView view(Entry e, Case c, Instant now) {
        boolean breached = e.lateResponse || e.acknowledgedAt == null && now.isAfter(e.deadline)
                && c.state() != Case.State.CLOSED;
        return new CaseView(e.id, c.key(), c.state(), e.priority, e.score, c.openedAt(), e.deadline,
                Optional.ofNullable(e.acknowledgedAt), breached, Optional.ofNullable(e.assignee), c.holdsActions(),
                e.awaitingSecond, List.copyOf(e.alerts.values()), c.entities(), e.notes, e.timeline,
                List.copyOf(e.links), e.dropped);
    }

    private Optional<Entry> live(String caseId) {
        if (caseId == null) {
            return Optional.empty();
        }
        prune();
        return Optional.ofNullable(entries.get(caseId));
    }

    private void acknowledge(Entry e, Instant now) {
        if (e.acknowledgedAt == null) {
            e.acknowledgedAt = now;
            e.lateResponse = now.isAfter(e.deadline);
        }
    }

    private void add(Entry e, Instant now, CaseView.TimelineEntry.Kind kind, String actor, String detail) {
        if (e.timeline.size() >= settings.maxTimeline()) {
            e.timeline.remove(1);   // keep how the case opened
            e.dropped++;
        }
        e.timeline.add(new CaseView.TimelineEntry(now, kind, Validate.id(actor, "actor"), Sanitize.text(detail, 300)));
    }

    /** Forgets entries whose case the book has forgotten (it bounds the number of cases). */
    private void prune() {
        // The book bounds its cases; when it has forgotten one, this holds more entries than it has cases.
        if (entries.size() > book.size()) {
            entries.values().removeIf(e -> book.get(e.id).isEmpty() && forget(e));
        }
    }

    private boolean forget(Entry e) {
        e.alerts.keySet().forEach(rankedById::remove);
        return true;
    }

    private boolean audited(String type, String actor, Instant now, Map<String, String> fields) {
        try {
            audit.append(type, Validate.id(actor, "actor"), now, fields);
            return true;
        } catch (RuntimeException ex) {
            auditFailures++;
            return false;
        }
    }
}

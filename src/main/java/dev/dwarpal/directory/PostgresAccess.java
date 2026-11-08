package dev.dwarpal.directory;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The access process in PostgreSQL. Standard SQL only; every statement is a constant with {@code ?} for each value. The
 * rules are enforced here, against the directory's own rows, and every change that touches more than one table is one
 * transaction: a joiner is created with all their grants or not at all, a leaver loses everything or nothing.
 *
 * <p>Decisions are taken one at a time inside this process (a lock), so two approvers deciding the same grant at the
 * same moment cannot both see "the other one has not decided yet" and leave an approved grant waiting for ever.
 */
public final class PostgresAccess implements Access {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int MAX_ITEMS = 12;
    private static final int RECENT = 50;

    private static final String ITEMS = "SELECT item_id, label, description, sensitivity, console_role FROM access_item ORDER BY item_id";
    private static final String TEMPLATES = "SELECT business_role, item_id FROM access_role_template ORDER BY business_role, item_id";

    private static final String REQUEST_COLUMNS = "SELECT request_id, kind, status, subject_id, requested_by, reason, display_name,"
            + " department, business_role, decided_by, decision_reason, created_at, updated_at FROM access_request";
    private static final String FIND_REQUEST = REQUEST_COLUMNS + " WHERE request_id = ?";
    private static final String REQUESTS_OF = REQUEST_COLUMNS + " WHERE requested_by = ? OR subject_id = ? ORDER BY created_at DESC";
    private static final String REQUESTS_RECENT = REQUEST_COLUMNS + " ORDER BY created_at DESC";
    private static final String REQUESTS_OPEN_JOINERS = REQUEST_COLUMNS
            + " WHERE kind = 'JOINER' AND status = 'PENDING' ORDER BY created_at";
    private static final String OPEN_JOINER_FOR = "SELECT 1 FROM access_request WHERE subject_id = ? AND kind = 'JOINER' AND status = 'PENDING'";
    private static final String REQUEST_ITEMS = "SELECT item_id FROM access_request_item WHERE request_id = ? ORDER BY item_id";
    private static final String INSERT_REQUEST = "INSERT INTO access_request (request_id, kind, status, subject_id, requested_by,"
            + " reason, display_name, department, business_role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    private static final String INSERT_REQUEST_ITEM = "INSERT INTO access_request_item (request_id, item_id) VALUES (?, ?)";
    private static final String SET_REQUEST_STATUS = "UPDATE access_request SET status = ?, decided_by = ?, decision_reason = ?,"
            + " updated_at = ? WHERE request_id = ? AND status = ?";
    private static final String CANCEL_OPEN_REQUESTS = "UPDATE access_request SET status = 'CANCELLED', decision_reason = ?,"
            + " updated_at = ? WHERE subject_id = ? AND status IN ('PENDING', 'APPROVED')";

    private static final String GRANT_COLUMNS = "SELECT grant_id, request_id, person_id, item_id, state, created_at, granted_at,"
            + " removed_at, removed_reason FROM access_grant";
    private static final String FIND_GRANT = GRANT_COLUMNS + " WHERE grant_id = ?";
    private static final String GRANTS_OF = GRANT_COLUMNS + " WHERE person_id = ? ORDER BY created_at DESC, grant_id";
    private static final String GRANTS_LIVE_OF = GRANT_COLUMNS + " WHERE person_id = ? AND state IN ('ACTIVE', 'PENDING') ORDER BY item_id";
    private static final String GRANTS_OF_REQUEST = GRANT_COLUMNS + " WHERE request_id = ? ORDER BY item_id";
    private static final String GRANT_IDS_AWAITING = "SELECT g.grant_id FROM access_grant g JOIN access_approval a ON a.grant_id = g.grant_id"
            + " WHERE g.state = 'PENDING' AND a.approver_role = ? AND a.decision = 'PENDING' ORDER BY g.created_at, g.grant_id";
    private static final String APPROVALS_OF_GRANT = "SELECT grant_id, approver_role, approver_id, decision, reason, decided_at"
            + " FROM access_approval WHERE grant_id = ? ORDER BY approver_role";
    private static final String HELD_ITEM = "SELECT 1 FROM access_grant WHERE person_id = ? AND item_id = ? AND state IN ('ACTIVE', 'PENDING')";
    private static final String INSERT_GRANT = "INSERT INTO access_grant (grant_id, request_id, person_id, item_id, state, created_at,"
            + " granted_at) VALUES (?, ?, ?, ?, ?, ?, ?)";
    private static final String INSERT_APPROVAL = "INSERT INTO access_approval (grant_id, approver_role, approver_id, decision,"
            + " reason, decided_at) VALUES (?, ?, ?, ?, ?, ?)";
    private static final String DECIDE_APPROVAL = "UPDATE access_approval SET approver_id = ?, decision = ?, reason = ?, decided_at = ?"
            + " WHERE grant_id = ? AND approver_role = ? AND decision = 'PENDING'";
    private static final String ACTIVATE_GRANT = "UPDATE access_grant SET state = 'ACTIVE', granted_at = ? WHERE grant_id = ?"
            + " AND state = 'PENDING' AND NOT EXISTS (SELECT 1 FROM access_approval a WHERE a.grant_id = access_grant.grant_id"
            + " AND a.decision <> 'APPROVED')";
    private static final String REJECT_GRANT = "UPDATE access_grant SET state = 'REJECTED' WHERE grant_id = ? AND state = 'PENDING'";
    private static final String REMOVE_GRANT = "UPDATE access_grant SET state = 'REMOVED', removed_at = ?, removed_reason = ?"
            + " WHERE grant_id = ? AND state IN ('ACTIVE', 'PENDING')";
    private static final String PENDING_IN_REQUEST = "SELECT COUNT(*) FROM access_grant WHERE request_id = ? AND state = 'PENDING'";

    private static final String PERSON_STATUS = "SELECT status FROM directory_person WHERE person_id = ?";
    private static final String HAS_ROLE = "SELECT 1 FROM directory_person_role WHERE person_id = ? AND console_role = ?";
    private static final String PERSON_ROLES = "SELECT console_role FROM directory_person_role WHERE person_id = ? ORDER BY console_role";
    private static final String INSERT_PERSON = "INSERT INTO directory_person (person_id, display_name, department, business_role,"
            + " status, source, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    private static final String INSERT_ROLE = "INSERT INTO directory_person_role (person_id, console_role) VALUES (?, ?)";
    private static final String DELETE_ROLES = "DELETE FROM directory_person_role WHERE person_id = ?";
    private static final String DISABLE_PERSON = "UPDATE directory_person SET status = 'DISABLED', updated_at = ?"
            + " WHERE person_id = ? AND status = 'ACTIVE'";

    private final Database db;
    private final Clock clock;
    private final ReentrantLock writes = new ReentrantLock();

    public PostgresAccess(Database db) {
        this(db, Clock.systemUTC());
    }

    PostgresAccess(Database db, Clock clock) {
        this.db = Objects.requireNonNull(db, "db");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    // ---- what can be given ---------------------------------------------------------------------------------------

    @Override
    public List<AccessItem> catalog() {
        return db.read(c -> List.copyOf(items(c).values()));
    }

    @Override
    public Map<String, List<String>> templates() {
        return db.read(c -> {
            Map<String, List<String>> out = new TreeMap<>();
            try (PreparedStatement s = c.prepareStatement(TEMPLATES); ResultSet r = s.executeQuery()) {
                while (r.next()) {
                    out.computeIfAbsent(r.getString(1), k -> new ArrayList<>()).add(r.getString(2));
                }
            }
            return Map.copyOf(out);
        });
    }

    // ---- joiner ----------------------------------------------------------------------------------------------------

    @Override
    public AccessResult submitJoiner(String hrId, String personId, String displayName, String department, String businessRole,
                                     String reason) {
        String name = plain(displayName, "name", DirectoryPerson.NAME_MAX);
        String dept = plain(department, "department", DirectoryPerson.LABEL_MAX);
        String job = plain(businessRole, "business role", DirectoryPerson.LABEL_MAX);
        String why = plain(reason, "reason", 300);
        if (!DirectoryPerson.validId(personId)) {
            throw new Refused(Refused.Code.INVALID, "a person id is 2 to 32 lower-case letters, digits, . _ -");
        }
        return locked(() -> db.write(c -> {
            requireActive(c, hrId, "HR");
            if (personStatus(c, personId) != null || openJoinerFor(c, personId)) {
                throw new Refused(Refused.Code.CONFLICT, "that person exists already or has a request waiting");
            }
            Instant now = clock.instant();
            String id = newId("req-");
            insertRequest(c, id, AccessRequest.Kind.JOINER, AccessRequest.Status.PENDING, personId, hrId, why, name, dept, job, now);
            List<AccessEvent> events = List.of(event("ACCESS_REQUESTED", hrId, "kind", "JOINER", "request", id, "subject", personId,
                    "businessRole", job));
            return new AccessResult(loadRequest(c, id), List.of(), events);
        }));
    }

    @Override
    public AccessResult saveJoiner(String adminId, String requestId, Set<String> ticked) {
        Objects.requireNonNull(ticked, "ticked");
        return locked(() -> db.write(c -> {
            requireActive(c, adminId, "ADMIN");
            AccessRequest req = requirePending(c, requestId, AccessRequest.Kind.JOINER);
            if (req.requestedBy().equals(adminId)) {
                throw new Refused(Refused.Code.FORBIDDEN, "nobody approves their own request");
            }
            Map<String, AccessItem> catalog = items(c);
            Set<String> chosen = new TreeSet<>(ticked);
            if (chosen.size() > MAX_ITEMS || !catalog.keySet().containsAll(chosen)) {
                throw new Refused(Refused.Code.INVALID, "tick items from the list only");
            }
            if (personStatus(c, req.subjectId()) != null) {
                throw new Refused(Refused.Code.CONFLICT, "that person exists already");
            }
            Instant now = clock.instant();
            insertPerson(c, req, now);
            List<AccessEvent> events = new ArrayList<>();
            events.add(event("ACCESS_PERSON_ADDED", adminId, "request", req.id(), "person", req.subjectId(), "businessRole",
                    req.businessRole(), "source", "HR"));
            for (String item : chosen) {
                insertRequestItem(c, req.id(), item);
                AccessItem it = catalog.get(item);
                String grantId = newId("grt-");
                if (it.sensitivity() == AccessItem.Sensitivity.SIMPLE) {
                    insertGrant(c, grantId, req.id(), req.subjectId(), item, AccessGrant.State.ACTIVE, now, now);
                    grantRole(c, req.subjectId(), it);
                    events.add(event("ACCESS_GRANTED", adminId, "request", req.id(), "grant", grantId, "person", req.subjectId(),
                            "item", item, "how", "ticked by the administrator, simple item"));
                } else {
                    insertGrant(c, grantId, req.id(), req.subjectId(), item, AccessGrant.State.PENDING, now, null);
                    insertApproval(c, grantId, "ADMIN", adminId, AccessGrant.Decision.APPROVED, "ticked and saved", now);
                    insertApproval(c, grantId, "LEAD", null, AccessGrant.Decision.PENDING, null, null);
                    events.add(event("ACCESS_APPROVED", adminId, "request", req.id(), "grant", grantId, "person", req.subjectId(),
                            "item", item, "role", "ADMIN"));
                    events.add(event("ACCESS_PENDING", adminId, "request", req.id(), "grant", grantId, "person", req.subjectId(),
                            "item", item, "waiting", "LEAD"));
                }
            }
            AccessRequest.Status next = pendingCount(c, req.id()) == 0 ? AccessRequest.Status.DONE : AccessRequest.Status.APPROVED;
            setStatus(c, req.id(), AccessRequest.Status.PENDING, next, adminId, "saved with " + chosen.size() + " items ticked", now);
            return new AccessResult(loadRequest(c, req.id()), requestGrants(c, req.id()), events);
        }));
    }

    @Override
    public AccessResult rejectJoiner(String adminId, String requestId, String reason) {
        String why = plain(reason, "reason", 300);
        return locked(() -> db.write(c -> {
            requireActive(c, adminId, "ADMIN");
            AccessRequest req = requirePending(c, requestId, AccessRequest.Kind.JOINER);
            if (req.requestedBy().equals(adminId)) {
                throw new Refused(Refused.Code.FORBIDDEN, "nobody approves their own request");
            }
            setStatus(c, req.id(), AccessRequest.Status.PENDING, AccessRequest.Status.REJECTED, adminId, why, clock.instant());
            List<AccessEvent> events = List.of(event("ACCESS_REJECTED", adminId, "request", req.id(), "kind", "JOINER", "subject",
                    req.subjectId(), "reason", why));
            return new AccessResult(loadRequest(c, req.id()), List.of(), events);
        }));
    }

    // ---- more access -------------------------------------------------------------------------------------------------

    @Override
    public AccessResult requestAccess(String personId, Set<String> wanted, String reason) {
        Objects.requireNonNull(wanted, "items");
        String why = plain(reason, "reason", 300);
        return locked(() -> db.write(c -> {
            // "HR shows the person is active": the directory's own status, read now
            if (!DirectoryPerson.validId(personId) || !"ACTIVE".equals(personStatus(c, personId))) {
                throw new Refused(Refused.Code.FORBIDDEN, "only an active person can ask for access");
            }
            Map<String, AccessItem> catalog = items(c);
            Set<String> chosen = new TreeSet<>(wanted);
            if (chosen.isEmpty() || chosen.size() > MAX_ITEMS || !catalog.keySet().containsAll(chosen)) {
                throw new Refused(Refused.Code.INVALID, "choose one or more items from the list");
            }
            for (String item : chosen) {
                AccessItem it = catalog.get(item);
                if (holds(c, personId, item) || it.consoleRole() != null && hasRole(c, personId, it.consoleRole())) {
                    throw new Refused(Refused.Code.CONFLICT, "you have " + it.label() + " already, or it is waiting for approval");
                }
            }
            Instant now = clock.instant();
            String id = newId("req-");
            insertRequest(c, id, AccessRequest.Kind.ACCESS, AccessRequest.Status.PENDING, personId, personId, why, null, null, null, now);
            List<AccessEvent> events = new ArrayList<>();
            events.add(event("ACCESS_REQUESTED", personId, "kind", "ACCESS", "request", id, "subject", personId, "items",
                    String.join(",", chosen)));
            for (String item : chosen) {
                insertRequestItem(c, id, item);
                AccessItem it = catalog.get(item);
                String grantId = newId("grt-");
                if (it.sensitivity() == AccessItem.Sensitivity.SIMPLE) {
                    insertGrant(c, grantId, id, personId, item, AccessGrant.State.ACTIVE, now, now);
                    grantRole(c, personId, it);
                    events.add(event("ACCESS_GRANTED", personId, "request", id, "grant", grantId, "person", personId, "item", item,
                            "how", "automatic: the directory shows the person is active"));
                } else {
                    insertGrant(c, grantId, id, personId, item, AccessGrant.State.PENDING, now, null);
                    insertApproval(c, grantId, "ADMIN", null, AccessGrant.Decision.PENDING, null, null);
                    insertApproval(c, grantId, "LEAD", null, AccessGrant.Decision.PENDING, null, null);
                    events.add(event("ACCESS_PENDING", personId, "request", id, "grant", grantId, "person", personId, "item", item,
                            "waiting", "ADMIN,LEAD"));
                }
            }
            AccessRequest.Status next = pendingCount(c, id) == 0 ? AccessRequest.Status.DONE : AccessRequest.Status.PENDING;
            if (next != AccessRequest.Status.PENDING) {
                setStatus(c, id, AccessRequest.Status.PENDING, next, null, "all items were simple: granted automatically", now);
            }
            return new AccessResult(loadRequest(c, id), requestGrants(c, id), events);
        }));
    }

    @Override
    public AccessResult decide(String approverId, String approverRole, String grantId, boolean approve, String reason) {
        if (!"ADMIN".equals(approverRole) && !"LEAD".equals(approverRole)) {
            throw new Refused(Refused.Code.INVALID, "only an administrator or a lead decides");
        }
        String why = approve ? optional(reason, 300) : plain(reason, "reason", 300);
        return locked(() -> db.write(c -> {
            requireActive(c, approverId, approverRole);
            AccessGrant g = loadGrant(c, grantId).orElseThrow(() -> new Refused(Refused.Code.NOT_FOUND, "not found"));
            AccessRequest req = loadRequest(c, g.requestId());
            if (g.state() != AccessGrant.State.PENDING) {
                throw new Refused(Refused.Code.CONFLICT, "that grant is not waiting for a decision");
            }
            if (req.requestedBy().equals(approverId) || g.personId().equals(approverId)) {
                throw new Refused(Refused.Code.FORBIDDEN, "nobody approves their own request");
            }
            Instant now = clock.instant();
            int changed;
            try (PreparedStatement s = c.prepareStatement(DECIDE_APPROVAL)) {
                s.setString(1, approverId);
                s.setString(2, approve ? "APPROVED" : "REJECTED");
                s.setString(3, why);
                s.setObject(4, at(now));
                s.setString(5, grantId);
                s.setString(6, approverRole);
                changed = s.executeUpdate();
            }
            if (changed != 1) {
                throw new Refused(Refused.Code.CONFLICT, "that approval was decided already, or is not needed");
            }
            List<AccessEvent> events = new ArrayList<>();
            events.add(event(approve ? "ACCESS_APPROVED" : "ACCESS_REJECTED", approverId, "request", req.id(), "grant", grantId,
                    "person", g.personId(), "item", g.itemId(), "role", approverRole, "reason", why == null ? "" : why));
            if (approve) {
                if (activate(c, grantId, now) == 1) {
                    AccessItem it = items(c).get(g.itemId());
                    if (it != null) {
                        grantRole(c, g.personId(), it);
                    }
                    events.add(event("ACCESS_GRANTED", approverId, "request", req.id(), "grant", grantId, "person", g.personId(),
                            "item", g.itemId(), "how", "approved by every approver the item needs"));
                }
            } else {
                reject(c, grantId);
            }
            if ((req.status() == AccessRequest.Status.PENDING || req.status() == AccessRequest.Status.APPROVED)
                    && pendingCount(c, req.id()) == 0) {
                setStatus(c, req.id(), req.status(), AccessRequest.Status.DONE, approverId, "every grant is decided", now);
            }
            return new AccessResult(loadRequest(c, req.id()), requestGrants(c, req.id()), events);
        }));
    }

    // ---- leaver ---------------------------------------------------------------------------------------------------------

    @Override
    public AccessResult leaver(String hrId, String personId, String reason) {
        String why = plain(reason, "reason", 300);
        if (!DirectoryPerson.validId(personId)) {
            throw new Refused(Refused.Code.NOT_FOUND, "not found");
        }
        return locked(() -> db.write(c -> {
            requireActive(c, hrId, "HR");
            if (hrId.equals(personId)) {
                throw new Refused(Refused.Code.FORBIDDEN, "nobody removes themselves");
            }
            String status = personStatus(c, personId);
            if (status == null) {
                throw new Refused(Refused.Code.NOT_FOUND, "not found");
            }
            if (!"ACTIVE".equals(status)) {
                throw new Refused(Refused.Code.CONFLICT, "that person has left already");
            }
            if (hasRole(c, personId, "ADMIN")) {
                throw new Refused(Refused.Code.FORBIDDEN, "the administrator's own account is not removed by a request");
            }
            Instant now = clock.instant();
            String id = newId("req-");
            insertRequest(c, id, AccessRequest.Kind.LEAVER, AccessRequest.Status.DONE, personId, hrId, why, null, null, null, now);
            List<AccessEvent> events = new ArrayList<>();
            events.add(event("ACCESS_REQUESTED", hrId, "kind", "LEAVER", "request", id, "subject", personId, "reason", why));
            // every grant the records show, not a re-calculation from the role, so one-off extras go as well
            for (AccessGrant g : liveGrants(c, personId)) {
                try (PreparedStatement s = c.prepareStatement(REMOVE_GRANT)) {
                    s.setObject(1, at(now));
                    s.setString(2, "leaver");
                    s.setString(3, g.id());
                    s.executeUpdate();
                }
                events.add(event("ACCESS_REMOVED", hrId, "request", id, "grant", g.id(), "person", personId, "item", g.itemId(),
                        "was", g.state().name(), "why", "leaver"));
            }
            List<String> roles = new ArrayList<>();
            try (PreparedStatement s = c.prepareStatement(PERSON_ROLES)) {
                s.setString(1, personId);
                try (ResultSet r = s.executeQuery()) {
                    while (r.next()) {
                        roles.add(r.getString(1));
                    }
                }
            }
            deleteRoles(c, personId);
            events.add(event("ACCESS_ROLES_REMOVED", hrId, "request", id, "person", personId, "roles", String.join(",", roles)));
            try (PreparedStatement s = c.prepareStatement(CANCEL_OPEN_REQUESTS)) {
                s.setString(1, "the person left");
                s.setObject(2, at(now));
                s.setString(3, personId);
                s.executeUpdate();
            }
            disable(c, personId, now);
            events.add(event("ACCESS_PERSON_DISABLED", hrId, "request", id, "person", personId));
            return new AccessResult(loadRequest(c, id), personGrants(c, personId), events);
        }));
    }

    // ---- reads -----------------------------------------------------------------------------------------------------------

    @Override
    public Optional<AccessRequest> request(String id) {
        if (id == null || id.length() > 40) {
            return Optional.empty();
        }
        return db.read(c -> findRequest(c, id));
    }

    @Override
    public List<AccessRequest> openJoiners() {
        return db.read(c -> {
            try (PreparedStatement s = c.prepareStatement(REQUESTS_OPEN_JOINERS)) {
                return readRequests(c, s, Integer.MAX_VALUE);
            }
        });
    }

    @Override
    public List<AccessRequest> recent() {
        return db.read(c -> {
            try (PreparedStatement s = c.prepareStatement(REQUESTS_RECENT)) {
                return readRequests(c, s, RECENT);
            }
        });
    }

    @Override
    public List<AccessRequest> requestsOf(String personId) {
        if (!DirectoryPerson.validId(personId)) {
            return List.of();
        }
        return db.read(c -> {
            try (PreparedStatement s = c.prepareStatement(REQUESTS_OF)) {
                s.setString(1, personId);
                s.setString(2, personId);
                return readRequests(c, s, RECENT);
            }
        });
    }

    @Override
    public List<AccessGrant> grantsOf(String personId) {
        if (!DirectoryPerson.validId(personId)) {
            return List.of();
        }
        return db.read(c -> personGrants(c, personId));
    }

    @Override
    public List<AccessGrant> grantsOfRequest(String requestId) {
        if (requestId == null || requestId.length() > 40) {
            return List.of();
        }
        return db.read(c -> requestGrants(c, requestId));
    }

    @Override
    public List<Awaiting> awaiting(String approverRole) {
        if (!"ADMIN".equals(approverRole) && !"LEAD".equals(approverRole)) {
            return List.of();
        }
        return db.read(c -> {
            List<String> ids = new ArrayList<>();
            try (PreparedStatement s = c.prepareStatement(GRANT_IDS_AWAITING)) {
                s.setString(1, approverRole);
                try (ResultSet r = s.executeQuery()) {
                    while (r.next()) {
                        ids.add(r.getString(1));
                    }
                }
            }
            List<Awaiting> out = new ArrayList<>();
            for (String id : ids) {
                Optional<AccessGrant> g = loadGrant(c, id);
                if (g.isPresent()) {
                    out.add(new Awaiting(g.get(), loadRequest(c, g.get().requestId())));
                }
            }
            return List.copyOf(out);
        });
    }

    // ---- helpers: rules ---------------------------------------------------------------------------------------------------

    private <T> T locked(java.util.function.Supplier<T> work) {
        writes.lock();
        try {
            return work.get();
        } finally {
            writes.unlock();
        }
    }

    /** The person exists, is ACTIVE and holds the console role: anything else is "not allowed", whoever is asking. */
    private static void requireActive(Connection c, String id, String role) throws SQLException {
        if (!DirectoryPerson.validId(id) || !"ACTIVE".equals(personStatus(c, id)) || !hasRole(c, id, role)) {
            throw new Refused(Refused.Code.FORBIDDEN, "that is not allowed");
        }
    }

    private static AccessRequest requirePending(Connection c, String requestId, AccessRequest.Kind kind) throws SQLException {
        AccessRequest req = requestId == null || requestId.length() > 40 ? null : findRequest(c, requestId).orElse(null);
        if (req == null || req.kind() != kind) {
            throw new Refused(Refused.Code.NOT_FOUND, "not found");
        }
        if (req.status() != AccessRequest.Status.PENDING) {
            throw new Refused(Refused.Code.CONFLICT, "that request has been dealt with already");
        }
        return req;
    }

    /** A grant that carries a console role also gives the person that role in the directory. */
    private static void grantRole(Connection c, String personId, AccessItem item) throws SQLException {
        if (item.consoleRole() != null && !hasRole(c, personId, item.consoleRole())) {
            try (PreparedStatement s = c.prepareStatement(INSERT_ROLE)) {
                s.setString(1, personId);
                s.setString(2, item.consoleRole());
                s.executeUpdate();
            }
        }
    }

    private static String plain(String value, String field, int max) {
        if (value == null) {
            throw new Refused(Refused.Code.INVALID, field + " is needed");
        }
        try {
            return DirectoryPerson.text(value, field, max);
        } catch (IllegalArgumentException e) {
            throw new Refused(Refused.Code.INVALID, e.getMessage());
        }
    }

    private static String optional(String value, int max) {
        return value == null || value.isBlank() ? null : plain(value, "reason", max);
    }

    private static AccessEvent event(String type, String actor, String... kv) {
        Map<String, String> f = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            f.put(kv[i], kv[i + 1]);
        }
        return new AccessEvent(type, actor, f);
    }

    private static String newId(String prefix) {
        byte[] b = new byte[12];
        RANDOM.nextBytes(b);
        return prefix + HexFormat.of().formatHex(b);
    }

    private static OffsetDateTime at(Instant i) {
        return i == null ? null : i.atOffset(ZoneOffset.UTC);
    }

    private static Instant instant(ResultSet r, int column) throws SQLException {
        OffsetDateTime t = r.getObject(column, OffsetDateTime.class);
        return t == null ? null : t.toInstant();
    }

    // ---- helpers: SQL -------------------------------------------------------------------------------------------------------

    private static Map<String, AccessItem> items(Connection c) throws SQLException {
        Map<String, AccessItem> out = new LinkedHashMap<>();
        try (PreparedStatement s = c.prepareStatement(ITEMS); ResultSet r = s.executeQuery()) {
            while (r.next()) {
                out.put(r.getString(1), new AccessItem(r.getString(1), r.getString(2), r.getString(3),
                        AccessItem.Sensitivity.valueOf(r.getString(4)), r.getString(5)));
            }
        }
        return out;
    }

    private static String personStatus(Connection c, String id) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(PERSON_STATUS)) {
            s.setString(1, id);
            try (ResultSet r = s.executeQuery()) {
                return r.next() ? r.getString(1) : null;
            }
        }
    }

    private static boolean hasRole(Connection c, String id, String role) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(HAS_ROLE)) {
            s.setString(1, id);
            s.setString(2, role);
            try (ResultSet r = s.executeQuery()) {
                return r.next();
            }
        }
    }

    private static boolean openJoinerFor(Connection c, String id) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(OPEN_JOINER_FOR)) {
            s.setString(1, id);
            try (ResultSet r = s.executeQuery()) {
                return r.next();
            }
        }
    }

    /** The person holds the item now, or has it waiting for approval. */
    private static boolean holds(Connection c, String person, String item) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(HELD_ITEM)) {
            s.setString(1, person);
            s.setString(2, item);
            try (ResultSet r = s.executeQuery()) {
                return r.next();
            }
        }
    }

    /** One guarded update: it changes the grant only while it is still waiting and every approval it needs is APPROVED. */
    private static int activate(Connection c, String grantId, Instant now) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(ACTIVATE_GRANT)) {
            s.setObject(1, at(now));
            s.setString(2, grantId);
            return s.executeUpdate();
        }
    }

    private static int reject(Connection c, String grantId) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(REJECT_GRANT)) {
            s.setString(1, grantId);
            return s.executeUpdate();
        }
    }

    private static void deleteRoles(Connection c, String person) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(DELETE_ROLES)) {
            s.setString(1, person);
            s.executeUpdate();
        }
    }

    private static int disable(Connection c, String person, Instant now) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(DISABLE_PERSON)) {
            s.setObject(1, at(now));
            s.setString(2, person);
            return s.executeUpdate();
        }
    }

    private static void insertRequest(Connection c, String id, AccessRequest.Kind kind, AccessRequest.Status status, String subject,
                                      String by, String reason, String name, String dept, String job, Instant now)
            throws SQLException {
        try (PreparedStatement s = c.prepareStatement(INSERT_REQUEST)) {
            s.setString(1, id);
            s.setString(2, kind.name());
            s.setString(3, status.name());
            s.setString(4, subject);
            s.setString(5, by);
            s.setString(6, reason);
            s.setString(7, name);
            s.setString(8, dept);
            s.setString(9, job);
            s.setObject(10, at(now));
            s.setObject(11, at(now));
            s.executeUpdate();
        }
    }

    private static void insertRequestItem(Connection c, String requestId, String item) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(INSERT_REQUEST_ITEM)) {
            s.setString(1, requestId);
            s.setString(2, item);
            s.executeUpdate();
        }
    }

    private static void insertPerson(Connection c, AccessRequest req, Instant now) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(INSERT_PERSON)) {
            s.setString(1, req.subjectId());
            s.setString(2, req.displayName());
            s.setString(3, req.department());
            s.setString(4, req.businessRole());
            s.setString(5, "ACTIVE");
            s.setString(6, "HR");
            s.setObject(7, at(now));
            s.setObject(8, at(now));
            s.executeUpdate();
        }
    }

    private static void insertGrant(Connection c, String id, String requestId, String person, String item, AccessGrant.State state,
                                    Instant now, Instant grantedAt) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(INSERT_GRANT)) {
            s.setString(1, id);
            s.setString(2, requestId);
            s.setString(3, person);
            s.setString(4, item);
            s.setString(5, state.name());
            s.setObject(6, at(now));
            s.setObject(7, at(grantedAt));
            s.executeUpdate();
        }
    }

    private static void insertApproval(Connection c, String grantId, String role, String approver, AccessGrant.Decision decision,
                                       String reason, Instant decidedAt) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(INSERT_APPROVAL)) {
            s.setString(1, grantId);
            s.setString(2, role);
            s.setString(3, approver);
            s.setString(4, decision.name());
            s.setString(5, reason);
            s.setObject(6, at(decidedAt));
            s.executeUpdate();
        }
    }

    private static void setStatus(Connection c, String id, AccessRequest.Status from, AccessRequest.Status to, String by, String why,
                                  Instant now) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(SET_REQUEST_STATUS)) {
            s.setString(1, to.name());
            s.setString(2, by);
            s.setString(3, why);
            s.setObject(4, at(now));
            s.setString(5, id);
            s.setString(6, from.name());
            if (s.executeUpdate() != 1) {
                throw new Refused(Refused.Code.CONFLICT, "that request has been dealt with already");
            }
        }
    }

    private static int pendingCount(Connection c, String requestId) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(PENDING_IN_REQUEST)) {
            s.setString(1, requestId);
            try (ResultSet r = s.executeQuery()) {
                return r.next() ? r.getInt(1) : 0;
            }
        }
    }

    private static AccessRequest loadRequest(Connection c, String id) throws SQLException {
        return findRequest(c, id).orElseThrow(() -> new Refused(Refused.Code.NOT_FOUND, "not found"));
    }

    private static Optional<AccessRequest> findRequest(Connection c, String id) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(FIND_REQUEST)) {
            s.setString(1, id);
            List<AccessRequest> found = readRequests(c, s, 1);
            return found.isEmpty() ? Optional.empty() : Optional.of(found.getFirst());
        }
    }

    /** Runs a request query that the caller prepared (so the SQL text is always a constant) and adds each one's items. */
    private static List<AccessRequest> readRequests(Connection c, PreparedStatement query, int limit) throws SQLException {
        List<Object[]> rows = new ArrayList<>();
        try (ResultSet r = query.executeQuery()) {
            while (r.next() && rows.size() < limit) {
                rows.add(new Object[]{r.getString(1), r.getString(2), r.getString(3), r.getString(4), r.getString(5),
                        r.getString(6), r.getString(7), r.getString(8), r.getString(9), r.getString(10), r.getString(11),
                        instant(r, 12), instant(r, 13)});
            }
        }
        List<AccessRequest> out = new ArrayList<>();
        for (Object[] x : rows) {
            List<String> items = new ArrayList<>();
            try (PreparedStatement s = c.prepareStatement(REQUEST_ITEMS)) {
                s.setString(1, (String) x[0]);
                try (ResultSet r = s.executeQuery()) {
                    while (r.next()) {
                        items.add(r.getString(1));
                    }
                }
            }
            out.add(new AccessRequest((String) x[0], AccessRequest.Kind.valueOf((String) x[1]),
                    AccessRequest.Status.valueOf((String) x[2]), (String) x[3], (String) x[4], (String) x[5], (String) x[6],
                    (String) x[7], (String) x[8], (String) x[9], (String) x[10], (Instant) x[11], (Instant) x[12], items));
        }
        return List.copyOf(out);
    }

    private static Optional<AccessGrant> loadGrant(Connection c, String id) throws SQLException {
        if (id == null || id.length() > 40) {
            return Optional.empty();
        }
        try (PreparedStatement s = c.prepareStatement(FIND_GRANT)) {
            s.setString(1, id);
            List<AccessGrant> g = readGrants(c, s);
            return g.isEmpty() ? Optional.empty() : Optional.of(g.getFirst());
        }
    }

    private static List<AccessGrant> requestGrants(Connection c, String requestId) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(GRANTS_OF_REQUEST)) {
            s.setString(1, requestId);
            return readGrants(c, s);
        }
    }

    private static List<AccessGrant> liveGrants(Connection c, String personId) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(GRANTS_LIVE_OF)) {
            s.setString(1, personId);
            return readGrants(c, s);
        }
    }

    private static List<AccessGrant> personGrants(Connection c, String personId) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(GRANTS_OF)) {
            s.setString(1, personId);
            return readGrants(c, s);
        }
    }

    /** Runs a grant query that the caller prepared, and adds each grant's approvals. */
    private static List<AccessGrant> readGrants(Connection c, PreparedStatement query) throws SQLException {
        List<Object[]> rows = new ArrayList<>();
        try (ResultSet r = query.executeQuery()) {
            while (r.next()) {
                rows.add(new Object[]{r.getString(1), r.getString(2), r.getString(3), r.getString(4), r.getString(5),
                        instant(r, 6), instant(r, 7), instant(r, 8), r.getString(9)});
            }
        }
        List<AccessGrant> out = new ArrayList<>();
        for (Object[] x : rows) {
            out.add(new AccessGrant((String) x[0], (String) x[1], (String) x[2], (String) x[3],
                    AccessGrant.State.valueOf((String) x[4]), (Instant) x[5], (Instant) x[6], (Instant) x[7], (String) x[8],
                    approvalsOf(c, (String) x[0])));
        }
        return List.copyOf(out);
    }

    private static List<AccessGrant.Approval> approvalsOf(Connection c, String grantId) throws SQLException {
        List<AccessGrant.Approval> out = new ArrayList<>();
        try (PreparedStatement s = c.prepareStatement(APPROVALS_OF_GRANT)) {
            s.setString(1, grantId);
            try (ResultSet r = s.executeQuery()) {
                while (r.next()) {
                    out.add(approval(r));
                }
            }
        }
        return out;
    }

    private static AccessGrant.Approval approval(ResultSet r) throws SQLException {
        return new AccessGrant.Approval(r.getString(2), r.getString(3), AccessGrant.Decision.valueOf(r.getString(4)),
                r.getString(5), instant(r, 6));
    }
}

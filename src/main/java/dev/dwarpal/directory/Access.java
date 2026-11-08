package dev.dwarpal.directory;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The access process: who may be given what, and how it ends. One door to it, as {@link Directory} is the one door to
 * the people. The rules (who may ask, who may decide, what needs which approvals, what a leaver loses) live behind this
 * interface and are checked against the directory itself, never against what the caller says about itself.
 *
 * <ul>
 *   <li><b>Joiner:</b> HR asks for a new person; the administrator ticks what the person gets (the role's defaults are
 *       pre-ticked) and saves. Only what is ticked at that moment is granted, one grant record per item.</li>
 *   <li><b>More access:</b> a person asks for items for themselves, through the same pipeline.</li>
 *   <li><b>Simple</b> items are granted automatically once the directory shows the person is active. <b>Hard</b> items
 *       need the administrator and a lead, two different people, neither of them the one who asked.</li>
 *   <li><b>Leaver:</b> HR names the person; no approval. The account is disabled, every grant is removed (using the grant
 *       records), the console roles are cleared and the open requests are cancelled, all in one transaction.</li>
 * </ul>
 *
 * Every method that changes anything returns an {@link AccessResult} whose events the caller must write to the audit
 * trail: one per grant, approval and removal.
 */
public interface Access {

    /** What happened, for the audit trail. {@code fields} never hold a secret: ids, items and short reasons only. */
    record AccessEvent(String type, String actor, Map<String, String> fields) {
        public AccessEvent {
            fields = Map.copyOf(fields);
        }
    }

    /** The request as it stands, its grants, and what must be audited. */
    record AccessResult(AccessRequest request, List<AccessGrant> grants, List<AccessEvent> events) {
        public AccessResult {
            grants = List.copyOf(grants);
            events = List.copyOf(events);
        }
    }

    /** A grant waiting for somebody's decision, with the request it belongs to. */
    record Awaiting(AccessGrant grant, AccessRequest request) {
    }

    /** Why a call was refused. The message is safe to show. */
    final class Refused extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public enum Code { INVALID, NOT_FOUND, FORBIDDEN, CONFLICT }

        private final Code code;

        public Refused(Code code, String message) {
            super(message);
            this.code = code;
        }

        public Code code() {
            return code;
        }
    }

    // ---- what can be given -------------------------------------------------------------------------------------

    List<AccessItem> catalog();

    /** Business role to the item ids pre-ticked for it. */
    Map<String, List<String>> templates();

    // ---- changes -----------------------------------------------------------------------------------------------

    /** HR asks for a new person. Nothing exists yet: the administrator decides. */
    AccessResult submitJoiner(String hrId, String personId, String displayName, String department, String businessRole,
                              String reason);

    /** The administrator saves a joiner request with these items ticked: the person is created and the items granted. */
    AccessResult saveJoiner(String adminId, String requestId, Set<String> ticked);

    /** The administrator refuses a joiner request, with a reason. Nothing is created. */
    AccessResult rejectJoiner(String adminId, String requestId, String reason);

    /** A person asks for more access for themselves. Simple items are granted at once; hard ones wait for approvals. */
    AccessResult requestAccess(String personId, Set<String> items, String reason);

    /** An administrator (role ADMIN) or a lead (role LEAD) decides one hard grant. */
    AccessResult decide(String approverId, String approverRole, String grantId, boolean approve, String reason);

    /** HR removes a leaver: no approval, everything in one transaction. */
    AccessResult leaver(String hrId, String personId, String reason);

    // ---- reads -------------------------------------------------------------------------------------------------

    Optional<AccessRequest> request(String id);

    /** Joiner requests waiting for the administrator, oldest first. */
    List<AccessRequest> openJoiners();

    /** The newest requests of every kind and status (at most 50). */
    List<AccessRequest> recent();

    /** Requests a person raised or that are about them, newest first. */
    List<AccessRequest> requestsOf(String personId);

    /** All grants of a person, newest first, with their approvals. */
    List<AccessGrant> grantsOf(String personId);

    /** The grants of one request, with their approvals. */
    List<AccessGrant> grantsOfRequest(String requestId);

    /** Grants waiting for a decision by this approver role (ADMIN or LEAD), oldest first. */
    List<Awaiting> awaiting(String approverRole);
}

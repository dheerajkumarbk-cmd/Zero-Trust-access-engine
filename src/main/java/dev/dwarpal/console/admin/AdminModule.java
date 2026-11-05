package dev.dwarpal.console.admin;

import dev.dwarpal.analytics.RecordedRequest;
import dev.dwarpal.analytics.WhatIf;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.console.ConsoleModule;
import dev.dwarpal.console.lab.ModuleKit;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.lab.scenarios.RuleSandbox;
import dev.dwarpal.pam.PrivilegedAccessManager;
import dev.dwarpal.policy.Policy;
import dev.dwarpal.policy.PolicyLoadException;
import dev.dwarpal.policy.PolicySet;
import dev.dwarpal.policy.SafePolicyLoader;
import dev.dwarpal.sim.SimRequests;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Admin and user views as a console module (id {@code admin}). Every privileged write (approve, install, request or
 * approve an elevation, revoke, review) needs a fresh second factor, checked by the host and again here, and is carried
 * out by the real installers and the real privileged access manager with the administrator's own signature: the
 * module can neither skip a check they make nor approve anything on its own. Reads of other people's decisions are
 * for administrators; an ordinary person sees only their own, and only in the words the engine allows itself to
 * say to a requester.
 *
 * <pre>
 *   GET  whoami                          USER   roles and step-up freshness, for the page
 *   GET  me/decisions                    USER   my latest decisions, in the requester's words
 *   GET  me/decisions/{reference}        USER   one of mine; someone else's reference is "not found"
 *   GET  policy                          ADMIN  the active policy in words, and the history of changes
 *   GET  playbooks                       ADMIN  the active playbooks in words
 *   POST policy/propose, playbooks/propose  ADMIN  {"yaml": "..."}  lints and opens a proposal
 *   GET  proposals                       ADMIN  open proposals and who signed
 *   POST proposals/{id}/whatif           ADMIN  replay recent requests against a proposed policy
 *   POST proposals/{id}/approve          ADMIN, step-up  sign with my own key
 *   POST proposals/{id}/install          ADMIN, step-up  hand the signed bundle to the installer
 *   POST proposals/{id}/withdraw         ADMIN
 *   GET  pam                             ADMIN  open requests, grants, break-glass uses awaiting review
 *   POST pam/request                     ADMIN, step-up  {"role","minutes","justification"}
 *   POST pam/approve/{id}                ADMIN, step-up
 *   POST pam/revoke/{id}                 ADMIN, step-up  {"reason"}
 *   POST pam/review/{id}                 ADMIN, step-up  {"verdict": "justified"|"misuse"}
 *   POST lab/reset                       ADMIN, step-up  the lab back to day zero
 *   GET  sessions, devices               ADMIN  who was decided about, from where, on what, and isolations
 *   GET  decisions/{reference}           ADMIN  one decision with the engine's full reasoning
 * </pre>
 */
public final class AdminModule implements ConsoleModule {

    public static final int MAX_RECORDS = 50_000;
    public static final int WHATIF_MAX = 20_000;

    private static final JsonReader FIELDS = new JsonReader(new JsonLimits(1 << 20, 4, 1 << 16, 64, 8, 32, 512));

    private final AdminServices services;
    private final Changes changes;
    private final RuleSandbox words = new RuleSandbox();

    public AdminModule(AdminServices services) {
        this.services = services;
        this.changes = new Changes(services);
    }

    @Override
    public String id() {
        return "admin";
    }

    @Override
    public String title() {
        return "Administration";
    }

    @Override
    public Role minimum() {
        return Role.USER;
    }

    @Override
    public void routes(Routes routes) {
        routes.get("whoami", Role.USER, ModuleKit.guard(Role.USER, this::whoami));
        routes.get("me/decisions", Role.USER, ModuleKit.guard(Role.USER, this::myDecisions));
        routes.get("me/decisions/{}", Role.USER, ModuleKit.guard(Role.USER, this::myDecision));

        routes.get("policy", Role.ADMIN, ModuleKit.guard(Role.ADMIN, this::policy));
        routes.get("playbooks", Role.ADMIN, ModuleKit.guard(Role.ADMIN, this::playbooks));
        routes.post("policy/propose", Role.ADMIN, false, ModuleKit.guard(Role.ADMIN,
                (r, p) -> propose(r, Changes.Kind.POLICY)));
        routes.post("playbooks/propose", Role.ADMIN, false, ModuleKit.guard(Role.ADMIN,
                (r, p) -> propose(r, Changes.Kind.PLAYBOOK)));
        routes.get("proposals", Role.ADMIN, ModuleKit.guard(Role.ADMIN, (r, p) ->
                ModuleKit.json(Map.of("proposals", changes.all()))));
        routes.post("proposals/{}/whatif", Role.ADMIN, false, ModuleKit.guard(Role.ADMIN, this::whatIf));
        routes.post("proposals/{}/approve", Role.ADMIN, true, ModuleKit.guard(Role.ADMIN, this::approve));
        routes.post("proposals/{}/install", Role.ADMIN, true, ModuleKit.guard(Role.ADMIN, this::install));
        routes.post("proposals/{}/withdraw", Role.ADMIN, false, ModuleKit.guard(Role.ADMIN, this::withdraw));

        routes.get("pam", Role.ADMIN, ModuleKit.guard(Role.ADMIN, this::pam));
        routes.post("pam/request", Role.ADMIN, true, ModuleKit.guard(Role.ADMIN, this::pamRequest));
        routes.post("pam/approve/{}", Role.ADMIN, true, ModuleKit.guard(Role.ADMIN, this::pamApprove));
        routes.post("pam/revoke/{}", Role.ADMIN, true, ModuleKit.guard(Role.ADMIN, this::pamRevoke));
        routes.post("pam/review/{}", Role.ADMIN, true, ModuleKit.guard(Role.ADMIN, this::pamReview));

        routes.post("lab/reset", Role.ADMIN, true, ModuleKit.guard(Role.ADMIN, this::resetLab));
        routes.get("sessions", Role.ADMIN, ModuleKit.guard(Role.ADMIN, this::sessions));
        routes.get("devices", Role.ADMIN, ModuleKit.guard(Role.ADMIN, this::devices));
        routes.get("decisions/{}", Role.ADMIN, ModuleKit.guard(Role.ADMIN, this::decision));
    }

    // ---- the person's own page ------------------------------------------------------------------------

    private Response whoami(Request r, List<String> p) {
        return ModuleKit.json(Map.of("id", r.who().id(), "roles", r.who().roles().stream().map(Enum::name).sorted().toList(),
                "stepUpFresh", r.who().stepUpFresh()));
    }

    private List<Decisions.Row> rows() {
        return Decisions.rows(services.recentAudit(MAX_RECORDS));
    }

    private Response myDecisions(Request r, List<String> p) {
        List<Decisions.Explanation> mine = Decisions.about(rows(), r.who().id(), 20).stream()
                .map(Decisions::explain).toList();
        return ModuleKit.json(Map.of("decisions", mine, "note", "Only your own requests are shown. For your safety "
                + "the reasons behind a decision are not shown here; an administrator can look them up from the reference."));
    }

    private Response myDecision(Request r, List<String> p) {
        String ref = ModuleKit.id(p.get(0));
        return Decisions.own(rows(), r.who().id(), ref).map(row -> ModuleKit.json(Decisions.explain(row)))
                .orElseGet(() -> Response.error(404, "no such request"));
    }

    // ---- policy and playbooks -------------------------------------------------------------------------

    /** One policy in words. */
    public record PolicyLine(String id, String description, String effect, String when) {
    }

    private Response policy(Request r, List<String> p) {
        PolicySet set = services.policies().currentEngine().policySet();
        List<PolicyLine> lines = new ArrayList<>();
        for (Policy pol : set.policies()) {
            lines.add(new PolicyLine(pol.id(), pol.description(), pol.effect().name(), pol.when().describe()));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("version", set.version());
        out.put("sequence", services.policies().currentSequence());
        out.put("algorithm", set.algorithm().name());
        out.put("defaultEffect", set.defaultEffect().name());
        out.put("policies", lines);
        out.put("history", history("POLICY_"));
        out.put("approversRequired", Changes.REQUIRED);
        return ModuleKit.json(out);
    }

    private Response playbooks(Request r, List<String> p) {
        RuleSandbox.PlaybookResult plans = words.playbook(services.activePlaybookYaml());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sequence", services.playbooks().sequence());
        out.put("plays", plans.plans());
        out.put("history", history("PLAYBOOK_"));
        out.put("approversRequired", Changes.REQUIRED);
        return ModuleKit.json(out);
    }

    /** One change (or refusal) in the audit chain, with the record's own plain fields. */
    public record HistoryLine(long sequence, Instant at, String type, String actor, Map<String, String> details) {
        public HistoryLine {
            details = Map.copyOf(details);
        }
    }

    private List<HistoryLine> history(String prefix) {
        List<HistoryLine> out = new ArrayList<>();
        List<AuditRecord> tail = services.recentAudit(MAX_RECORDS);
        for (int i = tail.size() - 1; i >= 0 && out.size() < 30; i--) {
            AuditRecord rec = tail.get(i);
            if (!rec.type().startsWith(prefix)) {
                continue;
            }
            Map<String, String> d = new LinkedHashMap<>();
            try {
                JsonValue.JObject o = (JsonValue.JObject) FIELDS.read(rec.payloadJson());
                for (String k : o.keys()) {
                    if (d.size() < 12 && o.get(k).orElseThrow() instanceof JsonValue.JString s) {
                        d.put(k, s.value().length() > 200 ? s.value().substring(0, 200) : s.value());
                    }
                }
            } catch (RuntimeException unreadable) {
                d.put("note", "payload not readable");
            }
            out.add(new HistoryLine(rec.sequence(), rec.at(), rec.type(), rec.actor(), d));
        }
        return out;
    }

    private Response propose(Request r, Changes.Kind kind) {
        JsonValue.JObject b = ModuleKit.body(r, Set.of("yaml"));
        String yaml = ModuleKit.string(b, "yaml").orElseThrow(() -> new ModuleKit.Refusal(400, "yaml is required"));
        return changed(() -> ModuleKit.json(changes.propose(kind, yaml, r.who().id())));
    }

    private Response whatIf(Request r, List<String> p) {
        Changes.Candidate c = changes.candidate(ModuleKit.id(p.get(0)))
                .orElseThrow(() -> new ModuleKit.Refusal(404, "no such proposal"));
        if (c.kind != Changes.Kind.POLICY) {
            throw new ModuleKit.Refusal(400, "what-if replays requests against policies, not playbooks");
        }
        PolicySet proposed;
        try {
            proposed = new SafePolicyLoader().load(c.yaml);
        } catch (PolicyLoadException | IllegalArgumentException e) {
            throw new ModuleKit.Refusal(400, "the proposed policy has errors");
        }
        List<RecordedRequest> recorded = services.recorder().snapshot();
        if (recorded.size() > WHATIF_MAX) {
            recorded = recorded.subList(recorded.size() - WHATIF_MAX, recorded.size());
        }
        WhatIf.Result res;
        try {
            res = new WhatIf(services.policies().currentEngine(), proposed, services.directory())
                    .replayRecorded(recorded, services.signals());
        } catch (IllegalArgumentException e) {
            throw new ModuleKit.Refusal(400, "the proposed policy has errors");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("result", res);
        out.put("window", services.recorder().stats());
        out.put("note", "Recent requests replayed without their signed evidence; both policies see the same stripped "
                + "request. A gain in access to a restricted resource is listed first: review it before you sign.");
        return ModuleKit.json(out);
    }

    private Response approve(Request r, List<String> p) {
        fresh(r);
        String id = ModuleKit.id(p.get(0));
        ModuleKit.body(r, Set.of());
        return changed(() -> ModuleKit.json(changes.approve(id, r.who().id())));
    }

    private Response install(Request r, List<String> p) {
        fresh(r);
        String id = ModuleKit.id(p.get(0));
        ModuleKit.body(r, Set.of());
        return changed(() -> ModuleKit.json(changes.install(id, r.who().id())));
    }

    private Response withdraw(Request r, List<String> p) {
        ModuleKit.body(r, Set.of());
        return changes.withdraw(ModuleKit.id(p.get(0))) ? ModuleKit.json(Map.of("withdrawn", true))
                : Response.error(404, "no such proposal");
    }

    private static Response changed(java.util.function.Supplier<Response> action) {
        try {
            return action.get();
        } catch (Changes.Refused refused) {
            return Response.error(refused.status(), refused.getMessage());
        }
    }

    private static void fresh(Request r) {
        if (!r.who().stepUpFresh()) {
            throw new ModuleKit.Refusal(403, "a fresh second factor is needed for this");
        }
    }

    // ---- privileged access ----------------------------------------------------------------------------

    private Response pam(Request r, List<String> p) {
        PrivilegedAccessManager pam = services.pam();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("pending", pam.pendingRequests());
        out.put("grants", pam.grants());
        out.put("breakGlassAwaitingReview", pam.pendingReviews());
        out.put("you", r.who().id());
        return ModuleKit.json(out);
    }

    private Response pamRequest(Request r, List<String> p) {
        fresh(r);
        JsonValue.JObject b = ModuleKit.body(r, Set.of("role", "minutes", "justification"));
        String role = ModuleKit.string(b, "role").orElseThrow(() -> new ModuleKit.Refusal(400, "role is required"));
        long minutes = ModuleKit.integer(b, "minutes").orElseThrow(() -> new ModuleKit.Refusal(400, "minutes is required"));
        String why = ModuleKit.string(b, "justification").orElseThrow(() -> new ModuleKit.Refusal(400,
                "a justification is required"));
        if (minutes < 1 || minutes > 480) {
            throw new ModuleKit.Refusal(400, "minutes is 1 to 480");
        }
        Instant now = services.clock().instant();
        String device = "console";
        AuthenticationContext auth = new AuthenticationContext(AuthMethod.WEBAUTHN, now);
        // the host verified a fresh second factor; the identity provider's key vouches for it, as for any login
        SignatureProof proof = SimRequests.signAuthentication(services.idpKey(), services.idpKeyId(), r.who().id(),
                device, auth, now);
        PrivilegedAccessManager.Result res = services.pam().request(r.who().id(), device, role,
                Duration.ofMinutes(minutes), why, auth, proof);
        return ModuleKit.json(res);
    }

    private Response pamApprove(Request r, List<String> p) {
        fresh(r);
        String id = ModuleKit.id(p.get(0));
        ModuleKit.body(r, Set.of());
        PrivilegedAccessManager.ElevationRequest req = services.pam().pendingRequests().stream()
                .filter(x -> x.requestId().equals(id)).findFirst()
                .orElseThrow(() -> new ModuleKit.Refusal(404, "no such open request"));
        KeyPair key = services.signingKey(r.who().id())
                .orElseThrow(() -> new ModuleKit.Refusal(403, "you hold no signing key in this lab"));
        Instant now = services.clock().instant();
        SignatureProof proof = new SignatureProof(services.keyId(r.who().id(), KeyPurpose.ELEVATION_APPROVER), now,
                Ed25519.sign(key.getPrivate(), SignedMessages.elevationApproval(req.requestId(), req.subjectId(),
                        req.role(), req.duration().toSeconds(), now)));
        return ModuleKit.json(services.pam().approve(id, r.who().id(), proof));
    }

    private Response pamRevoke(Request r, List<String> p) {
        fresh(r);
        String id = ModuleKit.id(p.get(0));
        JsonValue.JObject b = ModuleKit.body(r, Set.of("reason"));
        String reason = ModuleKit.string(b, "reason").orElse("revoked from the console");
        int n = services.pam().revokeGrant(id, r.who().id(), reason);
        return n == 0 ? Response.error(404, "no such grant") : ModuleKit.json(Map.of("revoked", n));
    }

    private Response pamReview(Request r, List<String> p) {
        fresh(r);
        String id = ModuleKit.id(p.get(0));
        JsonValue.JObject b = ModuleKit.body(r, Set.of("verdict"));
        String verdict = ModuleKit.string(b, "verdict").orElseThrow(() -> new ModuleKit.Refusal(400, "verdict is required"));
        if (!verdict.equals("justified") && !verdict.equals("misuse")) {
            throw new ModuleKit.Refusal(400, "verdict is justified or misuse");
        }
        KeyPair key = services.signingKey(r.who().id())
                .orElseThrow(() -> new ModuleKit.Refusal(403, "you hold no signing key in this lab"));
        Instant now = services.clock().instant();
        SignatureProof proof = new SignatureProof(services.keyId(r.who().id(), KeyPurpose.ELEVATION_APPROVER), now,
                Ed25519.sign(key.getPrivate(), SignedMessages.breakGlassReview(id, verdict, now)));
        return ModuleKit.json(services.pam().review(id, r.who().id(), verdict, proof));
    }

    /** An administrator is not an analyst in the console, so the lab's reset is also reachable from here. */
    private Response resetLab(Request r, List<String> p) throws java.io.IOException, InterruptedException {
        fresh(r);
        ModuleKit.body(r, Set.of());
        if (services.resetting()) {
            throw new ModuleKit.Refusal(409, "the lab is already being reset");
        }
        services.resetLab();
        return ModuleKit.json(Map.of("reset", true));
    }

    // ---- sessions, devices, decisions -----------------------------------------------------------------

    /** The latest decision about one person on one device. */
    public record SessionLine(String subject, String device, String sourceIp, String outcome, Instant at,
                              boolean deviceVerified, String policy) {
    }

    private Response sessions(Request r, List<String> p) {
        List<Decisions.Row> all = rows();
        Map<String, SessionLine> latest = new LinkedHashMap<>();
        for (int i = all.size() - 1; i >= 0 && latest.size() < 200; i--) {
            Decisions.Row d = all.get(i);
            latest.putIfAbsent(d.subject() + "/" + d.device(), new SessionLine(d.subject(), d.device(), d.sourceIp(),
                    Decisions.shown(d), d.at(), d.deviceVerified(), d.policy()));
        }
        List<AdminServices.Revoked> rev = services.revocations();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sessions", new ArrayList<>(latest.values()));
        out.put("revocations", rev.size() > 50 ? rev.subList(rev.size() - 50, rev.size()) : rev);
        out.put("note", "The lab's simulated organisation makes access requests but holds no gateway sessions, so this "
                + "lists the latest decision per person and device, and what the SOC's playbooks revoked.");
        return ModuleKit.json(out);
    }

    /** What is known about one device. */
    public record DeviceLine(String device, boolean managed, boolean verifiedLastTime, Instant lastSeen, String lastBy,
                             String isolation) {
    }

    private Response devices(Request r, List<String> p) {
        List<Decisions.Row> all = rows();
        Map<String, Decisions.Row> latest = new LinkedHashMap<>();
        for (int i = all.size() - 1; i >= 0; i--) {
            latest.putIfAbsent(all.get(i).device(), all.get(i));
        }
        Map<String, String> iso = services.isolations();
        List<DeviceLine> out = new ArrayList<>();
        for (Decisions.Row d : latest.values()) {
            if (out.size() >= 200) {
                break;
            }
            out.add(new DeviceLine(d.device(), services.directory().isManagedDevice(d.device()), d.deviceVerified(), d.at(),
                    d.subject(), iso.getOrDefault(d.device(), "none")));
        }
        return ModuleKit.json(Map.of("devices", out, "note", "A device is 'verified' only when its own agent key signed "
                + "its health report; a device id alone is a claim anyone can type."));
    }

    private Response decision(Request r, List<String> p) {
        String ref = ModuleKit.id(p.get(0));
        Optional<Decisions.Row> row = Decisions.any(rows(), ref);
        return row.map(x -> ModuleKit.json(x)).orElseGet(() -> Response.error(404, "no such request"));
    }
}

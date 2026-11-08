package dev.dwarpal.console.admin;

import dev.dwarpal.console.ConsoleModule.Principal;
import dev.dwarpal.console.ConsoleModule.Response;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.console.lab.FakeRoutes;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import static dev.dwarpal.console.lab.FakeRoutes.json;
import static dev.dwarpal.console.lab.FakeRoutes.text;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The admin module's routes, called directly, over the real installers, PAM and recorder. */
class AdminModuleTest {

    private static final Principal ADA = new Principal("ada", Set.of(Role.ADMIN), true);
    private static final Principal ADA_STALE = new Principal("ada", Set.of(Role.ADMIN), false);
    private static final Principal RAY = new Principal("ray", Set.of(Role.ADMIN), true);
    private static final Principal MALLORY = new Principal("mallory", Set.of(Role.ADMIN), true);
    private static final Principal ANALYST = new Principal("ana", Set.of(Role.ANALYST), true);

    private AdminFixture fx;
    private FakeRoutes routes;

    @BeforeEach
    void build() {
        fx = new AdminFixture();
        routes = FakeRoutes.of(new AdminModule(fx));
    }

    private static String body(String key, String yaml) {
        return "{\"" + key + "\":" + JsonWriter.write(JsonValue.str(yaml)) + "}";
    }

    private String propose(String path, Principal who, String yaml) {
        Response r = routes.call("POST", path, who, body("yaml", yaml));
        assertEquals(200, r.status(), r.body());
        return text(json(r).get("id").orElseThrow());
    }

    // ---- the route table -------------------------------------------------------------------------------

    @Test
    void everyPrivilegedWriteNeedsAStepUpAndEveryReadOfOthersDataIsForAdministrators() {
        for (String p : List.of("proposals/{}/approve", "proposals/{}/install", "pam/request", "pam/approve/{}",
                "pam/revoke/{}", "pam/review/{}")) {
            assertTrue(routes.route("POST", p).stepUp(), p + " is a privileged write");
            assertEquals(Role.ADMIN, routes.route("POST", p).minimum(), p);
        }
        for (String p : List.of("policy", "playbooks", "proposals", "pam", "sessions", "devices", "decisions/{}")) {
            assertEquals(Role.ADMIN, routes.route("GET", p).minimum(), p);
        }
        assertEquals(Role.USER, routes.route("GET", "me/decisions").minimum());
        assertEquals(Role.USER, routes.route("GET", "me/decisions/{}").minimum());
        assertEquals("admin", new AdminModule(fx).id());
        assertEquals(Role.USER, new AdminModule(fx).minimum());
    }

    @Test
    void handlersRefuseTheWrongRoleEvenWithoutTheHostsCheck() {
        Principal user = FakeRoutes.USER;
        for (String p : List.of("policy", "playbooks", "proposals", "pam", "sessions", "devices", "decisions/x")) {
            assertEquals(403, routes.call("GET", p, user, "").status(), p);
            assertEquals(403, routes.call("GET", p, ANALYST, "").status(), p + " for an analyst");
        }
        for (String p : List.of("policy/propose", "playbooks/propose", "proposals/x/approve", "proposals/x/install",
                "pam/request", "pam/approve/x", "pam/revoke/x", "pam/review/x")) {
            assertEquals(403, routes.call("POST", p, user, "{}").status(), p);
            assertEquals(403, routes.call("POST", p, ANALYST, "{}").status(), p + " for an analyst");
        }
        assertEquals(200, routes.call("GET", "whoami", user, "").status());
    }

    @Test
    void privilegedWritesAlsoRefuseAStaleSecondFactorInsideTheHandler() {
        String id = propose("policy/propose", ADA, fx.policyWithVersion("2026.11.06-1"));
        assertEquals(403, routes.call("POST", "proposals/" + id + "/approve", ADA_STALE, "").status());
        assertEquals(403, routes.call("POST", "proposals/" + id + "/install", ADA_STALE, "").status());
        assertEquals(403, routes.call("POST", "pam/request", ADA_STALE,
                "{\"role\":\"prod-admin\",\"minutes\":30,\"justification\":\"deploy the fix for ticket 42\"}").status());
        assertEquals(0, fx.installer.currentSequence());
    }

    @Test
    void anAdministratorCanResetTheLabButOnlyWithAFreshSecondFactor() {
        assertEquals(Role.ADMIN, routes.route("POST", "lab/reset").minimum());
        assertTrue(routes.route("POST", "lab/reset").stepUp());
        assertEquals(403, routes.call("POST", "lab/reset", ANALYST, "").status());
        assertEquals(403, routes.call("POST", "lab/reset", ADA_STALE, "").status());
        assertFalse(fx.resetCalled);
        assertEquals(200, routes.call("POST", "lab/reset", ADA, "").status());
        assertTrue(fx.resetCalled);
    }

    // ---- the policy, in words -------------------------------------------------------------------------

    @Test
    void theActivePolicyIsReadableAndShowsItsHistory() {
        JsonValue.JObject o = json(routes.call("GET", "policy", ADA, ""));
        assertEquals("2026.11.03-1", text(o.get("version").orElseThrow()));
        assertEquals("DENY_OVERRIDES", text(o.get("algorithm").orElseThrow()));
        assertEquals("DENY", text(o.get("defaultEffect").orElseThrow()));
        JsonValue.JArray pols = (JsonValue.JArray) o.get("policies").orElseThrow();
        assertTrue(pols.size() >= 6);
        JsonValue.JObject first = (JsonValue.JObject) pols.get(0);
        assertEquals("P-01-employees-internal-apps", text(first.get("id").orElseThrow()));
        assertFalse(text(first.get("when").orElseThrow()).isBlank(), "the condition in plain words");
        assertEquals("PERMIT", text(first.get("effect").orElseThrow()));
    }

    // ---- two-person policy install -------------------------------------------------------------------

    @Test
    void aPolicyNeedsTwoDifferentAdministratorsAndOnceInstalledChangesWhatTheEngineDecides() {
        String id = propose("policy/propose", ADA, fx.policyWithVersion("2026.11.06-1"));
        assertEquals(200, routes.call("POST", "proposals/" + id + "/approve", ADA, "").status());
        // the same administrator again counts once
        assertEquals(200, routes.call("POST", "proposals/" + id + "/approve", ADA, "").status());
        JsonValue.JObject none = json(routes.call("POST", "proposals/" + id + "/install", ADA, ""));
        assertEquals(JsonValue.bool(false), none.get("installed").orElseThrow());
        assertTrue(text(none.get("reason").orElseThrow()).contains("1 distinct"), text(none.get("reason").orElseThrow()));
        assertEquals(0, fx.installer.currentSequence());

        assertEquals(200, routes.call("POST", "proposals/" + id + "/approve", RAY, "").status());
        JsonValue.JObject done = json(routes.call("POST", "proposals/" + id + "/install", RAY, ""));
        assertEquals(JsonValue.bool(true), done.get("installed").orElseThrow(), done.toString());
        assertEquals(1, fx.installer.currentSequence());
        assertEquals("2026.11.06-1", text(json(routes.call("GET", "policy", ADA, "")).get("version").orElseThrow()));
        // the change is in the audit chain, with both approvers, and the screen's history shows it
        JsonValue.JArray history = (JsonValue.JArray) json(routes.call("GET", "policy", ADA, "")).get("history").orElseThrow();
        assertTrue(history.size() >= 1);
        assertTrue(history.elements().toString().contains("POLICY_INSTALLED") || fx.recentAudit(100_000).stream()
                .anyMatch(r -> r.type().equals("POLICY_INSTALLED")));
        // new decisions carry the new policy version
        fx.org.run(fx.recorder, fx.org.traffic().subList(120, 130));
        assertTrue(fx.recentAudit(100_000).stream().anyMatch(r -> r.type().equals("ACCESS_DECISION")
                && r.payloadJson().contains("2026.11.06-1")));
        // the paperwork is closed: it cannot be installed twice
        assertEquals(404, routes.call("POST", "proposals/" + id + "/install", RAY, "").status());
    }

    @Test
    void aPersonWithoutASigningKeyCannotApproveAndAnInvalidPolicyIsNeverKept() {
        String id = propose("policy/propose", ADA, fx.policyWithVersion("2026.11.07-1"));
        Response r = routes.call("POST", "proposals/" + id + "/approve", MALLORY, "");
        assertEquals(403, r.status());
        assertTrue(r.body().contains("no signing key"));

        Response bad = routes.call("POST", "policy/propose", ADA, body("yaml", "version: 1\nalgorithm: ANY\n"));
        assertEquals(200, bad.status());
        JsonValue.JObject o = json(bad);
        assertEquals(JsonValue.bool(false), o.get("linted").orElseThrow());
        assertEquals(1, ((JsonValue.JArray) json(routes.call("GET", "proposals", ADA, "")).get("proposals").orElseThrow()).size(),
                "only the valid proposal is kept");
        assertEquals(404, routes.call("POST", "proposals/" + text(o.get("id").orElseThrow()) + "/approve", ADA, "").status());
    }

    @Test
    void anOldSequenceIsRefusedByTheInstallerNotByTheModule() {
        String a = propose("policy/propose", ADA, fx.policyWithVersion("2026.11.08-1"));
        String b = propose("policy/propose", RAY, fx.policyWithVersion("2026.11.08-2"));
        for (String id : List.of(a, b)) {
            routes.call("POST", "proposals/" + id + "/approve", ADA, "");
            routes.call("POST", "proposals/" + id + "/approve", RAY, "");
        }
        assertEquals(JsonValue.bool(true), json(routes.call("POST", "proposals/" + a + "/install", ADA, "")).get("installed")
                .orElseThrow());
        JsonValue.JObject stale = json(routes.call("POST", "proposals/" + b + "/install", ADA, ""));
        assertEquals(JsonValue.bool(false), stale.get("installed").orElseThrow(), "the same sequence again is a rollback");
        assertTrue(text(stale.get("reason").orElseThrow()).contains("rollback"));
    }

    @Test
    void proposalsAreBoundedAndLapse() {
        for (int i = 0; i < Changes.MAX_OPEN; i++) {
            propose("policy/propose", ADA, fx.policyWithVersion("2026.12." + i + "-1"));
        }
        assertEquals(429, routes.call("POST", "policy/propose", ADA, body("yaml", fx.policyWithVersion("2027.1.1-1"))).status());
        fx.org.clock.set(fx.org.clock.instant().plus(Changes.TTL).plusSeconds(1));
        assertEquals(0, ((JsonValue.JArray) json(routes.call("GET", "proposals", ADA, "")).get("proposals").orElseThrow()).size());
        assertEquals(200, routes.call("POST", "policy/propose", ADA, body("yaml", fx.policyWithVersion("2027.1.1-1"))).status());
        assertEquals(400, routes.call("POST", "policy/propose", ADA, body("yaml", "x".repeat(Changes.MAX_YAML + 1))).status());
        assertEquals(400, routes.call("POST", "policy/propose", ADA, "{\"yaml\":\"a\",\"extra\":1}").status());
        assertEquals(400, routes.call("POST", "policy/propose", ADA, "{\"yaml\":5}").status());
        assertEquals(400, routes.call("POST", "policy/propose", ADA, "{}").status());
    }

    // ---- what-if -------------------------------------------------------------------------------------

    @Test
    void whatIfReplaysRecentRequestsAgainstTheProposalAndShowsWhoLosesAccess() {
        assertTrue(fx.recorder.stats().kept() > 50, "there are recent requests to replay");
        // a policy set that permits nobody: every request that was allowed now loses access
        String denyAll = "version: \"2026.11.09-1\"\nalgorithm: DENY_OVERRIDES\ndefault: DENY\npolicies:\n"
                + "  - id: P-99-nobody\n    description: Nobody.\n    when:\n      roleIn: [nobody]\n    effect: PERMIT\n";
        String id = propose("policy/propose", ADA, denyAll);
        Response r = routes.call("POST", "proposals/" + id + "/whatif", ADA, "");
        assertEquals(200, r.status(), r.body());
        JsonValue.JObject res = (JsonValue.JObject) json(r).get("result").orElseThrow();
        assertTrue(((JsonValue.JNumber) res.get("replayed").orElseThrow()).asLong() > 50);
        assertTrue(((JsonValue.JNumber) res.get("losses").orElseThrow()).asLong() > 0, "people lose access");
        assertEquals(0, ((JsonValue.JNumber) res.get("gains").orElseThrow()).asLong());
        assertEquals(0, fx.installer.currentSequence(), "a what-if installs nothing");

        // the unchanged policy changes nothing
        String same = propose("policy/propose", ADA, fx.policyWithVersion("2026.11.09-2"));
        JsonValue.JObject none = (JsonValue.JObject) json(routes.call("POST", "proposals/" + same + "/whatif", ADA, ""))
                .get("result").orElseThrow();
        assertEquals(0, ((JsonValue.JNumber) none.get("losses").orElseThrow()).asLong());
        assertEquals(0, ((JsonValue.JNumber) none.get("gains").orElseThrow()).asLong());
        assertEquals(404, routes.call("POST", "proposals/nonesuch/whatif", ADA, "").status());
    }

    // ---- playbooks -----------------------------------------------------------------------------------

    @Test
    void aPlaybookOnForgeableEvidenceIsNeverKeptAndAGoodOneNeedsTwoSignatures() {
        String forge = "version: \"lab.9\"\nplaybooks:\n  - rule: cloud-download-volume\n    steps:\n      - isolate: device\n";
        JsonValue.JObject refused = json(routes.call("POST", "playbooks/propose", ADA, body("yaml", forge)));
        assertEquals(JsonValue.bool(false), refused.get("linted").orElseThrow());
        assertTrue(refused.get("findings").orElseThrow().toString().length() > 0);
        assertEquals(0, ((JsonValue.JArray) json(routes.call("GET", "proposals", ADA, "")).get("proposals").orElseThrow()).size());

        String good = fx.activePlaybookYaml().replace("reference-2026-11-05", "reference-2026-11-06");
        String id = propose("playbooks/propose", ADA, good);
        routes.call("POST", "proposals/" + id + "/approve", ADA, "");
        JsonValue.JObject one = json(routes.call("POST", "proposals/" + id + "/install", ADA, ""));
        assertEquals(JsonValue.bool(false), one.get("installed").orElseThrow(), "one signature is not enough");
        routes.call("POST", "proposals/" + id + "/approve", RAY, "");
        JsonValue.JObject two = json(routes.call("POST", "proposals/" + id + "/install", ADA, ""));
        assertEquals(JsonValue.bool(true), two.get("installed").orElseThrow(), two.toString());
        assertEquals(1, fx.playbooks.sequence());
        assertEquals(List.of(good), fx.installedPlaybooks, "the SOAR is handed exactly the installed text");
        JsonValue.JObject view = json(routes.call("GET", "playbooks", ADA, ""));
        assertTrue(view.get("plays").orElseThrow() instanceof JsonValue.JArray a && a.size() > 5);
        assertEquals(404, routes.call("POST", "proposals/" + id + "/whatif", ADA, "").status(), "the installed proposal is closed");
    }

    // ---- privileged access ----------------------------------------------------------------------------

    @Test
    void anElevationNeedsADifferentApproverAndCanBeRevoked() {
        String req = "{\"role\":\"prod-admin\",\"minutes\":30,\"justification\":\"deploy the fix for ticket 42\"}";
        JsonValue.JObject made = json(routes.call("POST", "pam/request", ADA, req));
        assertEquals(JsonValue.bool(true), made.get("ok").orElseThrow(), made.toString());
        String reqId = text(made.get("id").orElseThrow());

        JsonValue.JObject own = json(routes.call("POST", "pam/approve/" + reqId, ADA, ""));
        assertEquals(JsonValue.bool(false), own.get("ok").orElseThrow(), "nobody approves their own elevation");
        assertTrue(text(own.get("reason").orElseThrow()).contains("own"));

        JsonValue.JObject granted = json(routes.call("POST", "pam/approve/" + reqId, RAY, ""));
        assertEquals(JsonValue.bool(true), granted.get("ok").orElseThrow(), granted.toString());
        assertFalse(fx.pam.activeRoles("ada", fx.org.clock.instant()).isEmpty());
        String grantId = text(granted.get("id").orElseThrow());
        assertTrue(routes.call("GET", "pam", RAY, "").body().contains(grantId));

        assertEquals(404, routes.call("POST", "pam/revoke/nonesuch", RAY, "{}").status());
        assertEquals(200, routes.call("POST", "pam/revoke/" + grantId, RAY, "{\"reason\":\"done\"}").status());
        assertTrue(fx.pam.activeRoles("ada", fx.org.clock.instant()).isEmpty());
    }

    @Test
    void anElevationForAnIneligibleRoleOrPersonOrWithoutAReasonIsRefusedByThePam() {
        for (String req : List.of(
                "{\"role\":\"root\",\"minutes\":30,\"justification\":\"deploy the fix for ticket 42\"}",
                "{\"role\":\"prod-admin\",\"minutes\":30,\"justification\":\"x\"}",
                "{\"role\":\"prod-admin\",\"minutes\":600,\"justification\":\"deploy the fix for ticket 42\"}")) {
            Response r = routes.call("POST", "pam/request", ADA, req);
            assertTrue(r.status() == 400 || json(r).get("ok").map(v -> v.equals(JsonValue.bool(false))).orElse(false), req + r.body());
        }
        JsonValue.JObject stranger = json(routes.call("POST", "pam/request", MALLORY,
                "{\"role\":\"prod-admin\",\"minutes\":30,\"justification\":\"deploy the fix for ticket 42\"}"));
        assertEquals(JsonValue.bool(false), stranger.get("ok").orElseThrow(), "mallory is not eligible");
        assertTrue(fx.pam.pendingRequests().isEmpty());
        assertEquals(400, routes.call("POST", "pam/request", ADA, "{\"role\":\"prod-admin\"}").status());
        assertEquals(400, routes.call("POST", "pam/review/x", ADA, "{\"verdict\":\"fine\"}").status());
    }

    // ---- sessions and devices ------------------------------------------------------------------------

    @Test
    void theSessionsAndDevicesPagesSaySoWhenTheyAreDerived() {
        fx.isolations.put("laptop-u1", "ISOLATED");
        JsonValue.JObject s = json(routes.call("GET", "sessions", ADA, ""));
        assertTrue(((JsonValue.JArray) s.get("sessions").orElseThrow()).size() > 0);
        assertTrue(text(s.get("note").orElseThrow()).contains("no gateway sessions"));
        JsonValue.JObject d = json(routes.call("GET", "devices", ADA, ""));
        JsonValue.JArray devices = (JsonValue.JArray) d.get("devices").orElseThrow();
        assertTrue(devices.size() > 0);
        assertTrue(devices.elements().toString().length() > 10);
        assertTrue(text(d.get("note").orElseThrow()).contains("claim anyone can type"));
    }

    // ---- why was I denied ----------------------------------------------------------------------------

    @Test
    void theRequestersPageGivesAReasonAndRevealsNoInternals() {
        List<Decisions.Row> rows = Decisions.rows(fx.recentAudit(100_000));
        Decisions.Row denied = rows.stream().filter(r -> r.outcome().equals("DENY")).findFirst().orElseThrow();
        Principal me = new Principal(denied.subject(), Set.of(Role.USER), false);

        Response list = routes.call("GET", "me/decisions", me, "");
        assertEquals(200, list.status());
        String body = list.body();
        assertTrue(body.contains(denied.requestId()));
        assertTrue(body.contains("Access denied. Contact your administrator with reference: " + denied.requestId()));
        assertTrue(body.contains(Decisions.reason(denied)), "a person is told why");
        // nothing that teaches an attacker: no policy, score, signal, address, device or threshold
        for (String secret : List.of(denied.policy(), denied.policyVersion(), denied.pAttack(), denied.sourceIp(), denied.device(),
                "pAttack", "signals", "risk", "threshold", "novelty", "reputation", "impossible", "P-90", "P-01")) {
            if (!secret.isBlank()) {
                assertFalse(body.contains(secret), "the page must not show: " + secret);
            }
        }
        assertEquals(200, routes.call("GET", "me/decisions/" + denied.requestId(), me, "").status());
        assertFalse(routes.call("GET", "me/decisions/" + denied.requestId(), me, "").body().contains(denied.sourceIp()));
    }

    @Test
    void everyReasonIsPlainAndNamesNoCheck() {
        Decisions.Row denied = Decisions.rows(fx.recentAudit(100_000)).stream().filter(r -> r.outcome().equals("DENY")).findFirst().orElseThrow();
        for (String policy : List.of("default", "unknown-subject", "unknown-resource", "P-03-confidential-needs-attested-health",
                "hard-gate:revoked-device", "fail-closed", "engine-error", "audit-failure", "P-90-very-high-risk", "P-01-employees-internal-apps")) {
            Decisions.Row r = new Decisions.Row(denied.sequence(), denied.requestId(), denied.at(), denied.subject(), denied.device(),
                    denied.resource(), denied.action(), "DENY", false, false, policy, denied.policyVersion(), denied.sourceIp(),
                    denied.pAttack(), denied.signals(), denied.reasons());
            String reason = Decisions.reason(r).toLowerCase(java.util.Locale.ROOT);
            assertFalse(reason.isBlank());
            for (String word : List.of("policy", "risk", "score", "threshold", "signal", "country", "travel", "p-", "hard-gate")) {
                assertFalse(reason.contains(word), policy + " gave: " + reason);
            }
        }
    }

    @Test
    void anotherPersonsReferenceLooksExactlyLikeOneThatDoesNotExist() {
        List<Decisions.Row> rows = Decisions.rows(fx.recentAudit(100_000));
        Decisions.Row theirs = rows.getFirst();
        Principal me = new Principal(rows.stream().map(Decisions.Row::subject).filter(s -> !s.equals(theirs.subject()))
                .findFirst().orElseThrow(), Set.of(Role.USER), false);
        Response other = routes.call("GET", "me/decisions/" + theirs.requestId(), me, "");
        Response nothing = routes.call("GET", "me/decisions/no-such-reference", me, "");
        assertEquals(404, other.status());
        assertEquals(nothing.status(), other.status());
        assertEquals(nothing.body(), other.body(), "no way to tell whether the reference exists");
        assertEquals(400, routes.call("GET", "me/decisions/..%2F..", me, "").status());
        // the list holds only my own decisions
        String list = routes.call("GET", "me/decisions", me, "").body();
        assertFalse(list.contains(theirs.requestId()));
    }

    @Test
    void theWordsMatchWhatTheEngineSaysToARequesterForEveryOutcome() {
        // run one request of each outcome through the real engine and compare with Decision.userMessage()
        List<dev.dwarpal.sim.SimOrganisation.Step> steps = fx.org.traffic();
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (dev.dwarpal.sim.SimOrganisation.Step s : steps) {
            if (s instanceof dev.dwarpal.sim.SimOrganisation.RequestStep rs && seen.size() < 3) {
                fx.org.clock.set(s.at());
                Decision d = fx.pipeline.decide(rs.labelled().request(), fx.org.signals.snapshot(s.at()));
                if (seen.add(d.outcome().name())) {
                    Decisions.Row row = Decisions.any(Decisions.rows(fx.recentAudit(100_000)), d.requestId()).orElseThrow();
                    assertEquals(d.userMessage(), Decisions.message(row), d.outcome().name());
                }
            }
        }
        assertTrue(seen.size() >= 2, "at least two outcomes compared: " + seen);
    }

    @Test
    void anAdministratorSeesTheFullReasoningAnOrdinaryPersonDoesNot() {
        Decisions.Row denied = Decisions.rows(fx.recentAudit(100_000)).stream().filter(r -> r.outcome().equals("DENY")).findFirst()
                .orElseThrow();
        Response admin = routes.call("GET", "decisions/" + denied.requestId(), ADA, "");
        assertEquals(200, admin.status());
        assertTrue(admin.body().contains(denied.policy()) && admin.body().contains("pAttack"));
        assertEquals(404, routes.call("GET", "decisions/no-such", ADA, "").status());
        assertEquals(403, routes.call("GET", "decisions/" + denied.requestId(),
                new Principal(denied.subject(), Set.of(Role.USER), false), "").status());
    }

    @Test
    void textFromTheFileComesBackAsDataNeverAsMarkup() {
        String yaml = fx.policyWithVersion("2026.11.10-1").replace("Employees may use internal apps (not administer them).",
                "<script>alert(1)</script> \\\"quoted\\\"");
        Response r = routes.call("POST", "policy/propose", ADA, body("yaml", yaml));
        assertEquals(200, r.status(), r.body());
        JsonValue.JObject o = json(r);          // still valid JSON, whatever the text holds
        assertTrue(text(o.get("yaml").orElseThrow()).contains("<script>"));
        assertEquals(Duration.ofHours(1), Changes.TTL);
    }
}

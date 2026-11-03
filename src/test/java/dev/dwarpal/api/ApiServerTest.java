package dev.dwarpal.api;

import dev.dwarpal.Fixtures;
import dev.dwarpal.audit.AuditLog;
import dev.dwarpal.audit.AuditRecord;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.edge.EdgeFixtures;
import dev.dwarpal.edge.EdgeGrant;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.SessionAuthority;
import dev.dwarpal.edge.WireFormat;
import dev.dwarpal.wire.JsonWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The engine API over real mutual TLS: what each caller may do, and how every bad request is answered. */
class ApiServerTest {

    private ApiKit.Harness h;
    private RemoteSessionAuthority gateway;

    @BeforeEach
    void start() {
        h = new ApiKit.Harness(ApiSettings.defaults());
        gateway = h.client("gateway");
    }

    @AfterEach
    void stop() {
        gateway.close();
        h.close();
    }

    // ---- happy paths: the remote authority answers exactly like the in-process one ---------------------

    @Test
    void aSessionCanBeOpenedAndUsedOverMutualTls() {
        KeyPair key = Ed25519.generateKeyPair();
        EdgeResult opened = h.open(gateway, key, h.world.request().build());
        assertEquals(EdgeResult.Status.OPENED, opened.status());
        EdgeGrant grant = opened.grant().orElseThrow();
        EdgeResult used = h.use(gateway, key, grant, h.world.request().build());
        assertEquals(EdgeResult.Status.GRANTED, used.status());
        assertEquals(1, h.world.administrator.activeSessions());
    }

    @Test
    void remoteAndLocalAnswersAreTheSame() {
        KeyPair key = Ed25519.generateKeyPair();
        EdgeGrant grant = h.open(gateway, key, h.world.request().build()).grant().orElseThrow();
        EdgeRequest write = h.world.request().action(Action.WRITE).build();
        EdgeResult remote = h.use(gateway, key, grant, write);
        EdgeRequest write2 = h.world.request().action(Action.WRITE).build();
        EdgeResult local = h.use(h.world.authority, key, grant, write2);
        assertEquals(local.status(), remote.status());
        assertEquals(local.restricted(), remote.restricted());
        EdgeResult replay = h.use(gateway, key, grant, write);
        assertEquals(EdgeResult.Status.REJECTED, replay.status(), "a request id is used once, also over the network");
    }

    @Test
    void singleDecisionsAndStepUpCrossTheWire() {
        assertEquals(EdgeResult.Status.GRANTED, gateway.decide(h.world.request().resource("web:general").build()).status());
        assertEquals(EdgeResult.Status.DENIED, gateway.decide(h.world.request().resource("web:malicious").build()).status());
        EdgeResult stale = gateway.decide(h.world.request().at(h.world.clock.now().minus(Duration.ofHours(1))).build());
        assertEquals(EdgeResult.Status.REJECTED, stale.status());
        EdgeResult admin = gateway.decide(h.world.request().action(Action.ADMIN).build());
        assertFalse(admin.status().allowed(), "no standing admin, over the API too");
    }

    @Test
    void aMalformedTokenIsRejectedWithoutACall() {
        EdgeRequest r = h.world.request().build();
        SignatureProof p = new SignatureProof("s-1", h.world.clock.now(), "AAAA");
        assertEquals(EdgeResult.Status.REJECTED, gateway.use("not-a-token", p, r).status());
        assertEquals(0, gateway.failures());
    }

    @Test
    void healthSaysOkAndNothingElse() throws Exception {
        try (ApiKit.Raw soc = h.raw("soc")) {
            ApiKit.Reply r = soc.get("/v1/health");
            assertEquals(200, r.status());
            assertEquals("{\"status\":\"ok\"}", r.body());
        }
    }

    // ---- who may call what ---------------------------------------------------------------------------

    @Test
    void eachEndpointServesOnlyItsRoles() throws Exception {
        String revoke = JsonWriter.write(ApiBodies.revoke(new ApiBodies.RevokeBody(ApiBodies.Scope.SUBJECT, "alice",
                "suspected compromise")));
        try (ApiKit.Raw pep = h.raw("gateway"); ApiKit.Raw soc = h.raw("soc"); ApiKit.Raw console = h.raw("console")) {
            assertEquals(403, pep.post("/v1/sessions/revoke", revoke).status(), "an enforcement point cannot revoke");
            assertEquals(403, pep.post("/v1/pam/approvals", "{}").status(), "an enforcement point cannot approve");
            assertEquals(403, soc.post("/v1/pam/break-glass", "{}").status(), "the SOC cannot break glass");
            String open = JsonWriter.write(WireFormat.decide(new WireFormat.DecideBody(h.world.request().build())));
            assertEquals(403, soc.post("/v1/decisions", open).status(), "the SOC is not an enforcement point");
            assertEquals(403, console.post("/v1/sessions", open).status(), "the console cannot open sessions");
            assertEquals(200, soc.post("/v1/sessions/revoke", revoke).status());
            assertEquals(200, console.post("/v1/sessions/revoke", revoke).status());
        }
    }

    @Test
    void aValidCertificateThatIsNotACallerGetsNothing() throws Exception {
        try (ApiKit.Raw stranger = h.raw("stranger")) {
            ApiKit.Reply r = stranger.get("/v1/health");
            assertEquals(403, r.status());
            assertEquals("{\"error\":\"forbidden\"}", r.body());
            assertEquals(403, stranger.get("/v1/nothing-here").status(), "an unknown caller does not learn the routes");
        }
    }

    @Test
    void revocationOverTheApiEndsTheSessionAtOnce() throws Exception {
        KeyPair key = Ed25519.generateKeyPair();
        EdgeGrant grant = h.open(gateway, key, h.world.request().build()).grant().orElseThrow();
        String body = JsonWriter.write(ApiBodies.revoke(new ApiBodies.RevokeBody(ApiBodies.Scope.SESSION,
                grant.sessionId(), "SOC ticket 77")));
        try (ApiKit.Raw soc = h.raw("soc")) {
            ApiKit.Reply r = soc.post("/v1/sessions/revoke", body);
            assertEquals("{\"revoked\":1}", r.body());
        }
        assertEquals(EdgeResult.Status.REJECTED, h.use(gateway, key, grant, h.world.request().build()).status());
        assertTrue(h.world.sink.snapshot().stream().anyMatch(rec -> rec.type().equals("SESSION_REVOKED")
                && rec.actor().equals("api/soc")), "the revocation names the caller");
        for (ApiBodies.Scope scope : List.of(ApiBodies.Scope.SUBJECT, ApiBodies.Scope.DEVICE)) {
            try (ApiKit.Raw console = h.raw("console")) {
                String b = JsonWriter.write(ApiBodies.revoke(new ApiBodies.RevokeBody(scope, "nobody", "cleanup")));
                assertEquals("{\"revoked\":0}", console.post("/v1/sessions/revoke", b).body());
            }
        }
    }

    // ---- routing and methods ---------------------------------------------------------------------------

    @Test
    void onlyExactPathsAreRoutes() throws Exception {
        try (ApiKit.Raw pep = h.raw("gateway")) {
            for (String path : List.of("/", "/v1", "/v1/", "/v1/health/", "/v1/sessions/", "/v1/sessionsX",
                    "/v1/sessions/use/x", "/v1//sessions", "/v1/sessions/./use", "/v1/session%73", "/V1/health",
                    "/v1/health?verbose=1", "/v2/sessions", "/v1/pam/requests/../approvals")) {
                ApiKit.Reply r = pep.get(path);
                assertEquals(404, r.status(), path);
                assertEquals("{\"error\":\"not found\"}", r.body(), path);
            }
            assertEquals(405, pep.get("/v1/sessions").status());
            assertEquals(405, pep.method("PUT", "/v1/decisions").status());
            assertEquals(405, pep.method("DELETE", "/v1/sessions").status());
            assertEquals(405, pep.post("/v1/health", "{}").status());
        }
    }

    // ---- bodies ---------------------------------------------------------------------------------------

    @Test
    void badBodiesGetAGenericAnswerAndTheDetailIsAudited() throws Exception {
        String good = JsonWriter.write(WireFormat.decide(new WireFormat.DecideBody(h.world.request().build())));
        List<String> bad = List.of("", "null", "[]", "{", "{}", "{\"v\":1}", "{\"v\":2,\"request\":{}}",
                good.replace("\"v\":1", "\"v\":1,\"v\":1"),
                good.replace("\"v\":1", "\"v\":1,\"admin\":true"),
                good.replace("\"READ\"", "\"read\""),
                good.replace("\"v\":1", "\"v\":1.0"),
                "{\"v\":1,\"request\":" + "[".repeat(5000) + "]".repeat(5000) + "}",
                good + " x");
        try (ApiKit.Raw pep = h.raw("gateway")) {
            for (String b : bad) {
                ApiKit.Reply r = pep.post("/v1/decisions", b);
                assertEquals(400, r.status(), b.length() > 60 ? b.substring(0, 60) : b);
                assertEquals("{\"error\":\"invalid request\"}", r.body());
            }
            assertEquals(400, pep.post("/v1/decisions", "application/json", new byte[]{'{', (byte) 0xC3, '}'}).status(),
                    "invalid UTF-8");
            assertEquals(415, pep.post("/v1/decisions", "text/plain", good.getBytes()).status());
            assertEquals(415, pep.post("/v1/decisions", "application/x-www-form-urlencoded", good.getBytes()).status());
            assertEquals(200, pep.post("/v1/decisions", "application/json; charset=UTF-8", good.getBytes()).status());
        }
        assertTrue(h.world.sink.snapshot().stream().anyMatch(r -> r.type().equals("API_REFUSED")
                && r.payloadJson().contains("duplicate key")), "the reason is in the audit trail, not the answer");
    }

    @Test
    void bodiesOver64KiBAreRefusedWhetherDeclaredOrChunked() throws Exception {
        byte[] big = ("{\"v\":1,\"request\":\"" + "a".repeat(70_000) + "\"}").getBytes();
        try (ApiKit.Raw pep = h.raw("gateway")) {
            // Refused before the body is read; the client may see the 413 or a reset while still sending.
            try {
                assertEquals(413, pep.post("/v1/decisions", "application/json", big).status());
            } catch (java.io.IOException resetWhileSending) {
                assertTrue(h.world.sink.snapshot().stream().anyMatch(r -> r.payloadJson().contains("\"status\":\"413\"")));
            }
            assertEquals(413, pep.postChunked("/v1/decisions", big).status());
            String good = JsonWriter.write(WireFormat.decide(new WireFormat.DecideBody(h.world.request().build())));
            assertEquals(200, pep.postChunked("/v1/decisions", good.getBytes()).status());
        }
    }

    // ---- fail-closed inside ----------------------------------------------------------------------------

    @Test
    void anExceptionInsideIsADenyWithoutDetail() throws Exception {
        SessionAuthority broken = new SessionAuthority() {
            @Override
            public EdgeResult open(EdgeRequest l, java.security.PublicKey k, Optional<SignatureProof> b) {
                throw new IllegalStateException("database password is hunter2");
            }

            @Override
            public EdgeResult use(String t, SignatureProof p, EdgeRequest r) {
                throw new NullPointerException("boom");
            }

            @Override
            public EdgeResult decide(EdgeRequest r) {
                throw new OutOfMemoryErrorLike();
            }
        };
        EdgeFixtures.World w = EdgeFixtures.world();
        try (ApiKit.Harness broke = new ApiKit.Harness(w, ApiSettings.defaults(), broken, null);
             ApiKit.Raw pep = broke.raw("gateway")) {
            String body = JsonWriter.write(WireFormat.decide(new WireFormat.DecideBody(w.request().build())));
            ApiKit.Reply r = pep.post("/v1/decisions", body);
            assertEquals(403, r.status());
            assertEquals("{\"error\":\"denied\"}", r.body());
            assertEquals(1, broke.server.internalFailures());
            try (RemoteSessionAuthority c = broke.client("gateway")) {
                KeyPair key = Ed25519.generateKeyPair();
                assertEquals(EdgeResult.Status.DENIED, broke.open(c, key, w.request().build()).status());
            }
            assertFalse(w.sink.snapshot().stream().anyMatch(rec -> rec.payloadJson().contains("hunter2")));
        }
    }

    /** A runtime exception standing in for any unexpected failure. */
    private static final class OutOfMemoryErrorLike extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    @Test
    void noAuditNoAccess() throws Exception {
        EdgeFixtures.World w = EdgeFixtures.world();
        AuditLog broken = new AuditLog(KeyGenerator.getInstance("HmacSHA256").generateKey(), rec -> {
            throw new IllegalStateException("disk full");
        });
        try (ApiKit.Harness h2 = new ApiKit.Harness(w, ApiSettings.defaults(), null, broken);
             RemoteSessionAuthority c = h2.client("gateway")) {
            EdgeResult r = c.decide(w.request().resource("web:general").build());
            assertEquals(EdgeResult.Status.DENIED, r.status(), "an allowed answer is not sent unless it was audited");
            assertTrue(h2.server.auditFailures() > 0);
            EdgeResult denied = c.decide(w.request().resource("web:malicious").build());
            assertEquals(EdgeResult.Status.DENIED, denied.status());
        }
    }

    @Test
    void everyCallIsAuditedWithCallerEndpointAndResult() {
        gateway.decide(h.world.request().resource("web:general").build());
        AuditRecord rec = h.world.sink.snapshot().stream().filter(r -> r.type().equals("API_CALL")).findFirst()
                .orElseThrow();
        assertEquals(ApiServer.ACTOR, rec.actor());
        assertTrue(rec.payloadJson().contains("\"caller\":\"gateway\""));
        assertTrue(rec.payloadJson().contains("\"endpoint\":\"/v1/decisions\""));
        assertTrue(rec.payloadJson().contains("\"result\":\"GRANTED\""));
        KeyPair key = Ed25519.generateKeyPair();
        EdgeGrant g = h.open(gateway, key, h.world.request().build()).grant().orElseThrow();
        assertFalse(h.world.sink.snapshot().stream().anyMatch(r -> r.payloadJson().contains(g.token())),
                "the token never reaches the audit trail");
    }

    @Test
    void refusalAuditsAreThrottledButCounted() throws Exception {
        try (ApiKit.Raw pep = h.raw("gateway")) {
            for (int i = 0; i < 40; i++) {
                pep.get("/v1/nope");
            }
        }
        long written = h.world.sink.snapshot().stream().filter(r -> r.type().equals("API_REFUSED")).count();
        assertEquals(20, written);
        assertEquals(20, h.server.suppressedAuditEvents());
    }

    @Test
    void perCallerRateLimitsDoNotSpillOverToOtherCallers() throws Exception {
        try (ApiKit.Harness tight = new ApiKit.Harness(EdgeFixtures.world(),
                ApiSettings.defaults().withCallerLimit(5, Duration.ofMinutes(1)), null, null);
             ApiKit.Raw pep = tight.raw("gateway"); ApiKit.Raw soc = tight.raw("soc")) {
            for (int i = 0; i < 5; i++) {
                assertEquals(200, pep.get("/v1/health").status());
            }
            ApiKit.Reply limited = pep.get("/v1/health");
            assertEquals(429, limited.status());
            assertEquals("{\"error\":\"too many requests\"}", limited.body());
            assertEquals(200, soc.get("/v1/health").status(), "one noisy caller does not lock out the SOC");
            tight.world.clock.advance(Duration.ofMinutes(1));
            assertEquals(200, pep.get("/v1/health").status(), "the window resets");
        }
    }

    // ---- privileged access over the API ------------------------------------------------------------------

    @Test
    void justInTimeElevationThroughTheConsole() throws Exception {
        Instant now = h.world.clock.now();
        AuthenticationContext webauthn = new AuthenticationContext(AuthMethod.WEBAUTHN, now.minus(Duration.ofMinutes(1)));
        SignatureProof idp = Fixtures.signAuthentication(Fixtures.IDP, Fixtures.IDP_KEY_ID, "alice", "laptop-alice",
                webauthn, webauthn.authenticatedAt());
        ApiBodies.ElevationBody req = new ApiBodies.ElevationBody("alice", "laptop-alice", "admin", Duration.ofMinutes(30),
                "INC-4211: rotate the wiki signing key", webauthn, idp);
        KeyPair key = Ed25519.generateKeyPair();
        assertFalse(gateway.decide(adminAction(key)).status().allowed(), "not admin before approval");
        try (ApiKit.Raw console = h.raw("console")) {
            ApiKit.Reply asked = console.post("/v1/pam/requests", JsonWriter.write(ApiBodies.elevation(req)));
            assertEquals(200, asked.status());
            String id = asked.body().replaceAll(".*\"id\":\"([^\"]+)\".*", "$1");
            assertTrue(asked.body().startsWith("{\"ok\":true"));
            assertEquals("{\"ok\":false}", console.post("/v1/pam/requests", JsonWriter.write(ApiBodies.elevation(req))).body(),
                    "the same WebAuthn proof works once; the reason stays in the audit trail");

            SignatureProof approval = new SignatureProof(EdgeFixtures.BOB_APPROVER_KEY_ID, now,
                    Ed25519.sign(EdgeFixtures.BOB_APPROVER.getPrivate(),
                            SignedMessages.elevationApproval(id, "alice", "admin", Duration.ofMinutes(30).toSeconds(), now)));
            ApiKit.Reply ok = console.post("/v1/pam/approvals",
                    JsonWriter.write(ApiBodies.approval(new ApiBodies.ApprovalBody(id, "bob", approval))));
            assertTrue(ok.body().startsWith("{\"ok\":true"), ok.body());
        }
        assertEquals(EdgeResult.Status.GRANTED, gateway.decide(adminAction(key)).status(), "admin while the grant lasts");
    }

    @Test
    void breakGlassAndItsReviewThroughTheConsole() throws Exception {
        Instant now = h.world.clock.now();
        String why = "IdP outage, rotating keys per runbook 12";
        SignatureProof sealed = new SignatureProof(EdgeFixtures.BREAK_GLASS_KEY_ID, now,
                Ed25519.sign(EdgeFixtures.BREAK_GLASS.getPrivate(), SignedMessages.breakGlass("bg-admin-1", "admin", why, now)));
        try (ApiKit.Raw console = h.raw("console")) {
            ApiKit.Reply bg = console.post("/v1/pam/break-glass",
                    JsonWriter.write(ApiBodies.breakGlass(new ApiBodies.BreakGlassBody("bg-admin-1", "admin", why, sealed))));
            assertTrue(bg.body().startsWith("{\"ok\":true"), bg.body());
            assertEquals(1, h.world.alerts.size(), "the SOC is paged");
            String grant = bg.body().replaceAll(".*\"id\":\"([^\"]+)\".*", "$1");
            SignatureProof verdict = new SignatureProof(EdgeFixtures.BOB_APPROVER_KEY_ID, now,
                    Ed25519.sign(EdgeFixtures.BOB_APPROVER.getPrivate(), SignedMessages.breakGlassReview(grant, "justified", now)));
            ApiKit.Reply reviewed = console.post("/v1/pam/reviews",
                    JsonWriter.write(ApiBodies.review(new ApiBodies.ReviewBody(grant, "bob", "justified", verdict))));
            assertTrue(reviewed.body().startsWith("{\"ok\":true"), reviewed.body());
            assertEquals("{\"ok\":false}", console.post("/v1/pam/reviews",
                    JsonWriter.write(ApiBodies.review(new ApiBodies.ReviewBody(grant, "bob", "justified", verdict)))).body());
            assertEquals(400, console.post("/v1/pam/reviews", "{\"v\":1}").status());
        }
    }

    private EdgeRequest adminAction(KeyPair key) {
        return h.world.request().action(Action.ADMIN).mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1), key).build();
    }

    // ---- configuration --------------------------------------------------------------------------------

    @Test
    void misconfigurationIsRefusedAtStartup() {
        assertThrows(IllegalArgumentException.class, () -> ApiServer.builder(h.world.audit, h.world.pam).tls(ApiKit.ctx("api"))
                .authority(h.world.authority).administrator(h.world.administrator)
                .callers(List.of(Caller.component("gateway", CallerRole.PEP), Caller.component("gateway", CallerRole.SOC)))
                .build(), "one certificate, two roles");
        assertThrows(IllegalArgumentException.class, () -> ApiServer.builder(h.world.audit, h.world.pam).tls(ApiKit.ctx("api"))
                .authority(h.world.authority).administrator(h.world.administrator)
                .build(), "nobody may call");
        assertThrows(NullPointerException.class, () -> ApiServer.builder(h.world.audit, h.world.pam).callers(ApiKit.CALLERS).build());
        assertThrows(IllegalArgumentException.class, () -> new ApiSettings(0, 1, 1, 1, Duration.ofSeconds(1), 1,
                Duration.ofSeconds(1), 1));
        assertThrows(IllegalArgumentException.class, () -> new ApiSettings(1, 1, 1, 100_000, Duration.ofSeconds(1), 1,
                Duration.ofSeconds(1), 1), "bodies cannot exceed the JSON limit");
        assertThrows(IllegalArgumentException.class, () -> ApiSettings.defaults().withRequestDeadline(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> Caller.of("CN=x", dev.dwarpal.edge.TlsContexts.component("x"),
                CallerRole.PEP), "a caller name is an identifier, not a certificate subject");
        assertThrows(IllegalArgumentException.class, () -> new Caller("x", "cn=x", CallerRole.PEP),
                "subjects are written exactly as certificates carry them");
        assertThrows(IllegalArgumentException.class, () -> RemoteSessionAuthority.create(
                java.net.URI.create("http://localhost:1"), ApiKit.ctx("gateway"), Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> RemoteSessionAuthority.create(
                java.net.URI.create("https://localhost:1/v1"), ApiKit.ctx("gateway"), Duration.ofSeconds(1)));
    }
}

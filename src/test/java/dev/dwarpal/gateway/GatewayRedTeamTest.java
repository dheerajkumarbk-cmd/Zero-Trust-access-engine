package dev.dwarpal.gateway;

import dev.dwarpal.agent.ClientAgent;
import dev.dwarpal.crypto.Digests;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.crypto.SignedMessages;
import dev.dwarpal.devidp.IdentityProvider;
import dev.dwarpal.domain.Action;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.domain.AuthenticationContext;
import dev.dwarpal.edge.EdgeResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Part B red-team pass. Each test was first written as a working attack against the gateway, the
 * identity provider or their contract, ran red (breach reproduced), then the code was fixed; the test
 * stays as the regression. Findings B1 to B8 in docs/layer-4/part-b.md.
 */
class GatewayRedTeamTest {

    private GatewayWorld g;

    @AfterEach
    void down() {
        if (g != null) {
            g.close();
        }
    }

    // B1: the Policy Administrator treats authentication as evidence, not as a requirement, so a login
    // with no MFA (or with an MFA claim nobody signed) opened a session as anybody whose ids were known.
    @Test
    void b1LoginWithoutVerifiedAuthenticationIsRefused() throws Exception {
        g = GatewayWorld.start();
        GatewayWorld.RawSession none = g.rawLogin("alice", "phone-x", "wiki", false, e -> e);
        assertEquals(403, none.status(), "no MFA at all");

        KeyPair attacker = Ed25519.generateKeyPair();
        GatewayWorld.RawSession forged = g.rawLogin("alice", "phone-x", "wiki", false, e -> {
            AuthenticationContext ctx = new AuthenticationContext(AuthMethod.WEBAUTHN, g.w.clock.now(),
                    Optional.of("0".repeat(64)));
            SignatureProof fake = new SignatureProof("idp-main", g.w.clock.now(), Ed25519.sign(attacker.getPrivate(),
                    SignedMessages.authentication("alice", "phone-x", ctx, g.w.clock.now())));
            return e.withAuthentication(ctx, fake);
        });
        assertNotEquals(201, forged.status(), "MFA signed by a key the identity provider never had");
        assertEquals(0, g.gateway.trackedSessions());
    }

    // B2: the login endpoint opened sessions for any resource the engine knows, including ones this
    // gateway does not front (web:general, SaaS data): a login oracle for other enforcement points.
    @Test
    void b2LoginOnlyForResourcesThisGatewayFronts() throws Exception {
        g = GatewayWorld.start();
        GatewayWorld.RawSession s = g.rawLogin("alice", "laptop-alice", "web:general", true, e -> e);
        assertNotEquals(201, s.status());
    }

    // B3: admin and download routes were matched case-sensitively, the app case-insensitively:
    // POST /wiki/Admin/settings was authorised as WRITE and executed as administration.
    @Test
    void b3RouteClassificationIsCaseInsensitive() throws Exception {
        g = GatewayWorld.start();
        ClientAgent alice = g.alice();
        ClientAgent.Response r = alice.send("POST", "/wiki/Admin/settings", "theme=pwned".getBytes(StandardCharsets.UTF_8));
        assertEquals(403, r.status());
        assertEquals("theme=light", g.app.settings());
        assertEquals(Optional.of(Action.ADMIN), g.routes.match("/wiki/ADMIN/x").orElseThrow().action("GET", "/wiki/ADMIN/x"));
        assertEquals(Optional.of(Action.DOWNLOAD),
                g.routes.match("/wiki/DownLoad/x").orElseThrow().action("GET", "/wiki/DownLoad/x"));
    }

    // B4: method-override headers were forwarded: a READ grant ran as DELETE in the app.
    @Test
    void b4MethodOverrideHeadersAreRefused() throws Exception {
        g = GatewayWorld.start();
        ClientAgent alice = g.alice();
        for (String h : new String[]{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override", "x_http_method_override"}) {
            ClientAgent.Response r = alice.send("GET", "/wiki/pages/home", new byte[0], java.util.Map.of(h, "DELETE"));
            assertEquals(400, r.status(), h);
        }
        assertTrue(g.app.page("home").isPresent(), "the page was not deleted");
    }

    // B5: absolute redirects built by the app (Location: http://127.0.0.1:<port>/...) reached the client,
    // revealing the internal address and inviting it to go around the gateway.
    @Test
    void b5RedirectsNeverRevealTheInternalAddress() throws Exception {
        g = GatewayWorld.start();
        ClientAgent.Response r = g.alice().send("GET", "/wiki/go/home", new byte[0]);
        assertEquals(302, r.status());
        String location = r.headers().firstValue("Location").orElse("");
        assertFalse(location.contains(g.app.uri().getAuthority()), location);
        assertEquals("/wiki/pages/home", location, "rewritten to a gateway-relative path");
    }

    // B6: sessions the Policy Administrator had already closed (per-user limit) stayed in the gateway's
    // table until their 10 h lifetime ran out, so logins by one user could fill it and lock out everyone.
    @Test
    void b6OneUserCannotFillTheGatewaySessionTable() throws Exception {
        g = GatewayWorld.start(b -> b.maxSessions(8));
        for (int i = 0; i < 8; i++) {
            assertEquals(201, g.rawLogin("alice", "laptop-alice", "wiki", true, e -> e).status());
        }
        assertEquals(201, g.rawLogin("carol", "phone-carol", "wiki", true, e -> e).status(), "carol can still log in");
    }

    // B7: a captured login from a device without an agent (no device binding) could be replayed; each
    // replay opened a session and, past the per-user limit, closed the victim's real one.
    @Test
    void b7ACapturedLoginCannotBeReplayed() throws Exception {
        g = GatewayWorld.start();
        GatewayWorld.RawSession carol = g.rawLogin("carol", "phone-carol", "wiki", true, e -> e);
        assertEquals(201, carol.status());
        for (int i = 0; i < 5; i++) {
            assertNotEquals(201, g.postLogin(carol.loginBody(), carol.key(), "carol", "phone-carol").status(), "replay " + i);
        }
        HttpResponse<String> use = g.send(g.signed(carol, carol.key(), "GET", "/wiki/pages/home", Action.READ, "wiki",
                g.newId()));
        assertEquals(200, use.statusCode(), "carol's real session survives");
    }

    // B8: challenges were capped globally but not per address: one address could hold every slot and no
    // one else could log in.
    @Test
    void b8OneAddressCannotExhaustTheIdentityProvidersChallenges() throws Exception {
        g = GatewayWorld.start();
        IdentityProvider attacker = g.idp.forClient("10.0.0.66");
        String thumb = Digests.thumbprint(Ed25519.generateKeyPair().getPublic());
        for (int i = 0; i < dev.dwarpal.devidp.DevIdentityProvider.MAX_PENDING; i++) {
            attacker.challenge("u" + i, "d", thumb);
        }
        assertTrue(g.idp.forClient("127.0.0.1").challenge("alice", "laptop-alice", thumb).isPresent());
    }

    // Held without changes (kept as regressions): MFA bound to another key; a session for one resource
    // used on another; a token presented with another session's id.
    @Test
    void attacksThatHeld() throws Exception {
        g = GatewayWorld.start();
        KeyPair other = Ed25519.generateKeyPair();
        GatewayWorld.RawSession wrongKey = g.rawLogin("alice", "phone-x", "wiki", false,
                e -> g.mfa("alice", "phone-x", other).addTo(e));
        assertEquals(403, wrongKey.status(), "refused at the gateway now; the Policy Administrator refused it before B1");
        assertTrue(wrongKey.result().isEmpty(), "a generic error, not a Dwarpal result");
        EdgeResult direct = g.w.authority.open(new dev.dwarpal.edge.EdgeRequest("held-1", g.w.clock.now(), "alice",
                "phone-x", GatewayWorld.healthy(), "wiki", Action.READ, GatewayWorld.MUMBAI, "mumbai",
                g.mfa("alice", "phone-x", other).addTo(dev.dwarpal.domain.Evidence.none())),
                Ed25519.generateKeyPair().getPublic(), Optional.empty());
        assertEquals(EdgeResult.Status.REJECTED, direct.status(), "and the Policy Administrator still refuses it too");

        GatewayWorld.RawSession a = g.rawLogin("alice", "laptop-alice", "wiki", true, e -> e);
        GatewayWorld.RawSession b = g.rawLogin("alice", "laptop-alice", "vault", true, e -> e);
        assertEquals(403, g.send(g.signed(a, a.key(), "GET", "/vault/secrets/x", Action.READ, "vault", g.newId()))
                .statusCode(), "wiki session on the vault");
        GatewayWorld.RawSession mixed = new GatewayWorld.RawSession(201, b.result(), a.key(), a.loginBody(), "alice",
                "laptop-alice");
        assertEquals(403, g.send(g.signed(mixed, a.key(), "GET", "/vault/secrets/x", Action.READ, "vault", g.newId())
                .setHeader(dev.dwarpal.edge.EdgeHttp.AUTHORIZATION, "Dwarpal " + a.grant().token())).statusCode(),
                "token of one session, id of another");
    }
}

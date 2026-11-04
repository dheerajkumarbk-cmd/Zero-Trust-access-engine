package dev.dwarpal.integration;

import dev.dwarpal.Fixtures;
import dev.dwarpal.api.RemoteSessionAuthority;
import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.edge.ClientProofs;
import dev.dwarpal.edge.EdgeGrant;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Layer 4 cross-part red team: attacks that appear only where the parts meet. Each was first a working
 * probe against the merged parts A, B and C, then fixed, then kept here (findings X2 to X5 in the threat
 * model; X1, slow logins holding the gateway's slots, was fixed in part B as B9).
 */
class CrossPartRedTeamTest {

    private E2eWorld e;

    @BeforeEach
    void up() {
        e = new E2eWorld();
    }

    @AfterEach
    void down() {
        e.close();
    }

    private Optional<dev.dwarpal.crypto.SignatureProof> binding(EdgeRequest login, KeyPair key) {
        return Optional.of(ClientProofs.bindDevice(Fixtures.DEVICE_AGENT.getPrivate(), Fixtures.DEVICE_KEY_ID, login,
                key.getPublic(), e.w.clock.now()));
    }

    @Test
    void x2_aSingleDecisionCannotStandInForASessionOnAPrivateApp() {
        // The gateway's own LoginGuard demands MFA, and every request a session key proof. A stolen gateway
        // certificate skipped both by asking /v1/decisions about the wiki: no session, no MFA, no proof.
        RemoteSessionAuthority gateway = e.remote("gateway");
        EdgeResult r = gateway.decide(e.w.request().build());
        assertFalse(r.status().allowed(), "private applications and SaaS data are reached through sessions only");
        assertFalse(gateway.decide(e.w.request().resource("vault").build()).status().allowed());
        assertFalse(e.remote("casb").decide(e.w.request().resource("drive").build()).status().allowed());
        assertEquals(EdgeResult.Status.GRANTED, e.remote("swg").decide(e.w.request().resource("web:general").build())
                .status(), "web browsing, which has no session, still gets single decisions");
    }

    @Test
    void x3_aStolenGatewayCertificateCannotOpenASessionWithoutMfa() {
        // Before integration the gateway's LoginGuard was the only MFA check: the API opened whatever a
        // PEP certificate asked for. Now the PA itself requires verified, key-bound MFA.
        KeyPair key = Ed25519.generateKeyPair();
        EdgeRequest login = e.w.request().build();
        EdgeResult r = e.remote("gateway").open(login, key.getPublic(), binding(login, key));
        assertEquals(EdgeResult.Status.STEP_UP, r.status());
        assertEquals(0, e.w.audited("SESSION_OPENED"));
        EdgeRequest forged = e.w.request().mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1), key).unsignedMfa().build();
        assertFalse(e.remote("gateway").open(forged, key.getPublic(), binding(forged, key)).status().allowed(),
                "an MFA claim the identity provider did not sign is no MFA");
    }

    @Test
    void x4_aCapturedLoginCannotBeReplayedThroughAnotherGatewayInstance() {
        // Each gateway's LoginGuard remembers the MFA proofs it saw; a second gateway instance (or the
        // attacker with a gateway certificate) did not. The PA now remembers them for every PEP.
        KeyPair key = Ed25519.generateKeyPair();
        EdgeRequest login = e.w.request().mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1), key).build();
        assertEquals(EdgeResult.Status.OPENED, e.remote("gateway").open(login, key.getPublic(), binding(login, key)).status());
        EdgeRequest replay = new EdgeRequest("e-replayed", login.timestamp(), login.subjectId(), login.deviceId(),
                login.claimedPosture(), login.resourceId(), login.action(), login.network(), login.pepRegion(),
                login.evidence());
        assertEquals(EdgeResult.Status.REJECTED,
                e.remote("gateway").open(replay, key.getPublic(), binding(replay, key)).status());
        assertEquals(1, e.w.audited("SESSION_OPENED"));
    }

    @Test
    void x5_eachEnforcementPointStaysWithinItsOwnResources() {
        KeyPair key = Ed25519.generateKeyPair();
        EdgeRequest login = e.w.request().mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1), key).build();
        EdgeGrant wiki = e.remote("gateway").open(login, key.getPublic(), binding(login, key)).grant().orElseThrow();
        for (String pep : new String[]{"swg", "casb"}) {
            EdgeRequest l = e.w.request().mfa(AuthMethod.WEBAUTHN, Duration.ofMinutes(1), key).build();
            assertEquals(EdgeResult.Status.DENIED, e.remote(pep).open(l, key.getPublic(), binding(l, key)).status(),
                    pep + " cannot open wiki sessions");
            EdgeRequest use = e.w.request().build();
            assertEquals(EdgeResult.Status.DENIED, e.remote(pep).use(wiki.token(),
                    ClientProofs.sign(key.getPrivate(), wiki.sessionId(), use, e.w.clock.now()), use).status(),
                    pep + " cannot spend a captured wiki session");
        }
        EdgeRequest use = e.w.request().build();
        assertEquals(EdgeResult.Status.GRANTED, e.remote("gateway").use(wiki.token(),
                ClientProofs.sign(key.getPrivate(), wiki.sessionId(), use, e.w.clock.now()), use).status(),
                "the session itself is untouched");
    }
}

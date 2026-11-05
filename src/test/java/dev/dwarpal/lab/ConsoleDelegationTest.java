package dev.dwarpal.lab;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.crypto.KeyPurpose;
import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.crypto.TrustedKey;
import dev.dwarpal.sim.SimOrganisation;
import dev.dwarpal.socapi.Delegation;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The console acts for an analyst with one signed assertion per call. Each test is an attack or a check; the world
 * is shared because building it is the slow part.
 */
class ConsoleDelegationTest {

    private static LabWorld w;
    private static HttpClient console;
    private static HttpClient ana;
    private static Delegation.Issuer issuer;

    @BeforeAll
    static void build() throws Exception {
        w = LabWorld.create(LabConfig.defaults(Files.createTempDirectory("dwarpal-delegation")).withPort(0).withUsers(30));
        w.warmUp(1);
        console = LabWorldTest.client(w.pki, w.pki, "console");
        ana = LabWorldTest.client(w.pki, w.pki, "ana");
        issuer = w.delegationIssuer();
    }

    @AfterAll
    static void release() {
        w.close();
    }

    private static HttpResponse<String> send(HttpClient c, String method, String path, String body, String header)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(w.socApiUrl() + path)).timeout(Duration.ofSeconds(10));
        if (header != null) {
            b.header(Delegation.HEADER, header);
        }
        if (body == null) {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            b.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(body));
        }
        return c.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static String countsBody(String query) {
        Instant now = w.now();
        return "{\"v\":1,\"query\":\"" + query + "\",\"from\":\"" + now.minus(Duration.ofHours(6)) + "\",\"to\":\""
                + now.plusSeconds(1) + "\"}";
    }

    @Test
    void theConsoleReadsAndWritesAsTheAnalystItIsActingFor() throws Exception {
        assertEquals(200, send(console, "GET", "/v1/queue", null, issuer.header("ana", "GET", "/v1/queue", null)).statusCode());
        String body = countsBody("dataset = firewall | count by action");
        assertEquals(200, send(console, "POST", "/v1/counts", body, issuer.header("ana", "POST", "/v1/counts", body.getBytes(StandardCharsets.UTF_8))).statusCode());
        // a lead's rights come with the lead: reports
        assertEquals(404, send(console, "GET", "/v1/reports/daily", null, issuer.header("ana", "GET", "/v1/reports/daily", null)).statusCode());
        assertEquals(200, send(console, "GET", "/v1/reports/daily", null, issuer.header("cleo", "GET", "/v1/reports/daily", null)).statusCode());
        // the audit trail names the analyst and says the console carried the call
        assertTrue(w.org.sink.snapshot().stream().anyMatch(r -> r.type().equals("SOCAPI_CALL")
                && r.payloadJson().contains("\"caller\":\"ana\"") && r.payloadJson().contains("via console")));
    }

    @Test
    void theConsoleWithoutAValidAssertionIsNobody() throws Exception {
        assertEquals(403, send(console, "GET", "/v1/queue", null, null).statusCode(), "no assertion");
        assertEquals(403, send(console, "GET", "/v1/queue", null, "v1;analyst=ana").statusCode(), "malformed");
        assertEquals(403, send(console, "GET", "/v1/queue", null, "x".repeat(700)).statusCode(), "too long");
        assertEquals(403, send(console, "GET", "/v1/queue", null,
                issuer.header("mallory", "GET", "/v1/queue", null)).statusCode(), "signed, but not an analyst");
        assertTrue(w.org.sink.snapshot().stream().anyMatch(r -> r.type().equals("SOCAPI_REFUSED")
                && r.payloadJson().contains("delegation refused")), "refusals are audited with the reason");
    }

    @Test
    void anAssertionWorksOnceAndOnlyForTheCallItWasSignedFor() throws Exception {
        String h = issuer.header("ana", "GET", "/v1/queue", null);
        assertEquals(200, send(console, "GET", "/v1/queue", null, h).statusCode());
        assertEquals(403, send(console, "GET", "/v1/queue", null, h).statusCode(), "replay");

        String other = issuer.header("ana", "GET", "/v1/queue", null);
        assertEquals(403, send(console, "GET", "/v1/cases", null, other).statusCode(), "another path");
        String post = issuer.header("ana", "POST", "/v1/counts", countsBody("dataset = firewall | count by action")
                .getBytes(StandardCharsets.UTF_8));
        assertEquals(403, send(console, "POST", "/v1/counts", countsBody("dataset = endpoint | count by action"), post)
                .statusCode(), "another body");
        String get = issuer.header("ana", "GET", "/v1/health", null);
        assertEquals(403, send(console, "POST", "/v1/health", "{}", get).statusCode(), "another method");
    }

    @Test
    void anAssertionLapsesAndAForgedOneIsRefused() throws Exception {
        String old = issuer.header("ana", "GET", "/v1/queue", null);
        Instant before = w.now();
        w.advanceTo(before.plusSeconds(Delegation.MAX_LIFETIME_SECONDS + 130));
        assertEquals(403, send(console, "GET", "/v1/queue", null, old).statusCode(), "expired");

        // signed with a key the ring does not trust for delegation
        KeyPair rogue = Ed25519.generateKeyPair();
        Delegation.Issuer forged = new Delegation.Issuer(rogue.getPrivate(), SimOrganisation.CONSOLE_KEY_ID, w.org.clock);
        assertEquals(403, send(console, "GET", "/v1/queue", null, forged.header("ana", "GET", "/v1/queue", null))
                .statusCode(), "right key id, wrong key");
        Delegation.Issuer unknown = new Delegation.Issuer(rogue.getPrivate(), "somebody", w.org.clock);
        assertEquals(403, send(console, "GET", "/v1/queue", null, unknown.header("ana", "GET", "/v1/queue", null))
                .statusCode(), "unknown key id");
        // an analyst's own signing key is not a delegation key
        Delegation.Issuer asAnalyst = new Delegation.Issuer(w.org.consoleKey.getPrivate(), "soc-ana", w.org.clock);
        assertEquals(403, send(console, "GET", "/v1/queue", null, asAnalyst.header("ana", "GET", "/v1/queue", null))
                .statusCode(), "key of another purpose");
    }

    @Test
    void anAnalystsOwnCertificateCannotBorrowAnotherAnalystsRightsWithTheHeader() throws Exception {
        String asLead = issuer.header("cleo", "GET", "/v1/reports/daily", null);
        assertEquals(404, send(ana, "GET", "/v1/reports/daily", null, asLead).statusCode(),
                "the header means nothing on a direct analyst connection");
        assertEquals(200, send(ana, "GET", "/v1/queue", null, null).statusCode(), "direct access still works");
    }

    @Test
    void theVerifierRefusesWhatItCannotCheckAndFailsClosedWhenItsStoreIsFull() {
        Instant t0 = Instant.parse("2026-11-05T10:00:00Z");
        KeyPair k = Ed25519.generateKeyPair();
        KeyRing ring = new KeyRing(List.of(new TrustedKey("console-delegate", KeyPurpose.CONSOLE_DELEGATE, "console",
                k.getPublic(), t0.minus(Duration.ofDays(1)), t0.plus(Duration.ofDays(1)))));
        Clock clock = Clock.fixed(t0, ZoneOffset.UTC);
        Delegation.Verifier v = new Delegation.Verifier(ring, clock, 100);
        Delegation.Issuer iss = new Delegation.Issuer(k.getPrivate(), "console-delegate", clock);
        for (int i = 0; i < 100; i++) {
            assertTrue(v.verify(iss.header("ana", "GET", "/v1/queue", null), "GET", "/v1/queue", null).analystId().isPresent());
        }
        Delegation.Verdict full = v.verify(iss.header("ana", "GET", "/v1/queue", null), "GET", "/v1/queue", null);
        assertFalse(full.analystId().isPresent());
        assertTrue(full.reason().contains("replay store"), full.reason());
        // time passes: the used identifiers expire and room appears again
        Delegation.Verifier later = new Delegation.Verifier(ring, Clock.fixed(t0.plusSeconds(200), ZoneOffset.UTC), 100);
        assertFalse(later.verify("v1;analyst=ana;iat=" + t0 + ";exp=" + t0.plusSeconds(61) + ";jti=" + "a".repeat(22)
                + ";kid=console-delegate;sig=" + "A".repeat(88), "GET", "/v1/queue", null).analystId().isPresent());
        for (String bad : new String[]{null, "", "v2;a=b", "v1;analyst=ana;iat=bad;exp=bad;jti=" + "a".repeat(22) + ";kid=k;sig=" + "A".repeat(88),
                "v1;analyst=ana;iat=" + t0 + ";exp=" + t0.plusSeconds(3600) + ";jti=" + "a".repeat(22) + ";kid=k;sig=" + "A".repeat(88),
                "v1;analyst=ana;iat=" + t0 + ";exp=" + t0 + ";jti=" + "a".repeat(22) + ";kid=k;sig=" + "A".repeat(88),
                "v1;analyst=a b;iat=" + t0 + ";exp=" + t0.plusSeconds(5) + ";jti=" + "a".repeat(22) + ";kid=k;sig=" + "A".repeat(88)}) {
            assertFalse(v.verify(bad, "GET", "/v1/queue", null).analystId().isPresent(), String.valueOf(bad));
        }
    }
}

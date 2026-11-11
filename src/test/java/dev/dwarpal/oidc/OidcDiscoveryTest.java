package dev.dwarpal.oidc;

import dev.dwarpal.oidc.OidcException.Reason;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OidcDiscoveryTest {

    private FakeIdp idp;
    private OidcHttp http;

    @BeforeEach
    void start() throws IOException {
        idp = new FakeIdp(new FakeIdp.TestClock(TestTokens.NOW));
        http = OidcHttp.forLoopbackTests();
    }

    @AfterEach
    void stop() {
        idp.close();
    }

    private OidcDiscovery fetch() {
        return OidcDiscovery.fetch(idp.issuer(), http);
    }

    private void refused(Reason reason) {
        OidcException e = assertThrows(OidcException.class, this::fetch);
        assertEquals(reason, e.reason());
        assertEquals(reason.message(), e.getMessage());
    }

    private static String doc(String issuer, String jwks, String algs) {
        return "{\"issuer\":\"" + issuer + "\",\"jwks_uri\":\"" + jwks + "\",\"authorization_endpoint\":\"" + issuer
                + "/authorize\",\"token_endpoint\":\"" + issuer + "/token\",\"id_token_signing_alg_values_supported\":"
                + algs + "}";
    }

    @Test
    void aGoodDocumentGivesCheckedMetadata() {
        OidcDiscovery d = fetch();
        assertEquals(idp.issuer(), d.issuer());
        assertEquals(URI.create(idp.issuer() + "/jwks"), d.jwksUri());
        assertEquals(URI.create(idp.issuer() + "/authorize"), d.authorizationEndpoint());
        assertEquals(URI.create(idp.issuer() + "/token"), d.tokenEndpoint());
        assertTrue(d.authorizationResponseIssParameterSupported());
        assertEquals(Set.of("RS256", "ES256", "EdDSA"), d.idTokenSigningAlgorithms());
        assertEquals(1, idp.discoveryRequests());
    }

    @Test
    void theIssParameterFlagDefaultsToFalse() {
        String i = idp.issuer();
        idp.discoveryBody(doc(i, i + "/jwks", "[\"RS256\"]"));
        assertFalse(fetch().authorizationResponseIssParameterSupported());
    }

    @Test
    void aTrailingSlashIssuerIsHandledAndMustMatchExactly() {
        String slash = idp.issuer() + "/";
        idp.documentIssuer(slash);
        OidcDiscovery d = OidcDiscovery.fetch(slash, http);
        assertEquals(slash, d.issuer());
        assertEquals(1, idp.discoveryRequests());
        // the configured issuer has the slash, the document does not: not equal
        idp.documentIssuer(idp.issuer());
        assertEquals(Reason.KEYS_INVALID,
                assertThrows(OidcException.class, () -> OidcDiscovery.fetch(slash, http)).reason());
    }

    @Test
    void anIssuerThatDiffersInAnyWayIsRefused() {
        for (String other : new String[] {idp.issuer() + "/", "http://127.0.0.1:1", idp.issuer().replace("http", "HTTP"),
            idp.issuer() + "/x", ""}) {
            idp.documentIssuer(other);
            refused(Reason.KEYS_INVALID);
        }
    }

    @Test
    void aKeyUriOnAnotherHostIsRefusedUnlessNamed() {
        idp.jwksUri("https://keys.evil.example/jwks");
        refused(Reason.KEYS_INVALID);
        OidcDiscovery d = OidcDiscovery.fetch(idp.issuer(), Set.of("KEYS.evil.example"), http);
        assertEquals("keys.evil.example", d.jwksUri().getHost());
    }

    @Test
    void aKeyUriOnAnotherPortOrWithUserInfoOrFragmentIsRefused() {
        String i = idp.issuer();
        for (String bad : new String[] {"http://127.0.0.1:1/jwks", i.replace("//", "//user:pw@") + "/jwks",
            i + "/jwks#frag", "//127.0.0.1/jwks", "/jwks", "ftp://127.0.0.1/jwks", "file:///etc/passwd", "jwks"}) {
            idp.jwksUri(bad);
            refused(Reason.KEYS_INVALID);
        }
    }

    @Test
    void aPlainHttpKeyUriOutsideLoopbackIsRefusedEvenIfTheHostIsNamed() {
        idp.jwksUri("http://example.org/jwks");
        refused(Reason.KEYS_INVALID);
        assertThrows(OidcException.class, () -> OidcDiscovery.fetch(idp.issuer(), Set.of("example.org"), http));
    }

    @Test
    void theOtherEndpointsAreCheckedToo() {
        String i = idp.issuer();
        idp.discoveryBody("{\"issuer\":\"" + i + "\",\"jwks_uri\":\"" + i + "/jwks\",\"authorization_endpoint\":"
                + "\"https://evil.example/a\",\"token_endpoint\":\"" + i + "/token\","
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}");
        refused(Reason.KEYS_INVALID);
        idp.discoveryBody("{\"issuer\":\"" + i + "\",\"jwks_uri\":\"" + i + "/jwks\",\"authorization_endpoint\":\""
                + i + "/a\",\"token_endpoint\":\"http://example.org/t\","
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}");
        refused(Reason.KEYS_INVALID);
    }

    @Test
    void missingOrWrongTypedMembersAreRefused() {
        String i = idp.issuer();
        String[] bad = {
            "[]", "\"x\"", "{}",
            "{\"issuer\":\"" + i + "\",\"jwks_uri\":\"" + i + "/jwks\",\"token_endpoint\":\"" + i + "/t\","
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}",
            doc(i, i + "/jwks", "[\"HS256\"]"),
            doc(i, i + "/jwks", "[\"none\"]"),
            doc(i, i + "/jwks", "[]"),
            doc(i, i + "/jwks", "\"RS256\""),
            doc(i, i + "/jwks", "[\"RS256\",5]"),
            doc(i, i + "/jwks", "[\"RS256\"]").replace("}", ",\"authorization_response_iss_parameter_supported\":\"yes\"}"),
            "{\"issuer\":5}",
            "not json at all",
        };
        for (String text : bad) {
            idp.discoveryBody(text);
            refused(Reason.KEYS_INVALID);
        }
    }

    @Test
    void aRedirectIsRefusedAndNotFollowed() {
        idp.discoveryRedirect(true);
        refused(Reason.KEYS_UNAVAILABLE);
        assertEquals(1, idp.discoveryRequests());
    }

    @Test
    void oversizedDocumentsAreRefusedWhetherOrNotTheLengthIsDeclared() {
        idp.discoveryOversized(true);
        refused(Reason.KEYS_UNAVAILABLE);
        idp.chunked(true);
        refused(Reason.KEYS_UNAVAILABLE);
    }

    @Test
    void theMediaTypeMustBeJson() {
        for (String type : new String[] {"text/html", "text/plain", "application/jsonx", "application/xml", ""}) {
            idp.discoveryContentType(type);
            refused(Reason.KEYS_UNAVAILABLE);
        }
        idp.discoveryContentType("Application/JSON; charset=utf-8");
        fetch();
    }

    @Test
    void aNon200StatusIsRefused() {
        for (int status : new int[] {202, 301, 400, 404, 500, 503}) {
            idp.discoveryStatus(status);
            refused(Reason.KEYS_UNAVAILABLE);
        }
    }

    @Test
    void anUnreachableProviderIsRefusedAsUnavailable() throws IOException {
        String gone;
        try (FakeIdp other = new FakeIdp(new FakeIdp.TestClock(TestTokens.NOW))) {
            gone = other.issuer();
        }
        OidcException e = assertThrows(OidcException.class, () -> OidcDiscovery.fetch(gone, http));
        assertEquals(Reason.KEYS_UNAVAILABLE, e.reason());
        assertFalse(e.getMessage().contains("127.0.0.1"));
    }

    @Test
    void aBadConfiguredIssuerIsRefusedBeforeAnyRequest() {
        String i = idp.issuer();
        String[] bad = {null, "", "   ", i + "?a=secret", i + "#frag", i.replace("//", "//user:pw@"),
            "https://" + "a".repeat(200) + ".example", "not a url", "https:///nohost", "https://", "mailto:a@b.c",
            "http://example.org", "ftp://127.0.0.1", "https://exa mple.org"};
        for (String issuer : bad) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> OidcDiscovery.fetch(issuer, http));
            assertFalse(e.getMessage().contains("secret"));
            assertFalse(e.getMessage().contains("pw"));
        }
        assertEquals(0, idp.discoveryRequests());
    }

    @Test
    void plainHttpIsRefusedWithTheProductionHelper() {
        assertThrows(IllegalArgumentException.class, () -> OidcDiscovery.fetch(idp.issuer()));
        assertThrows(IllegalArgumentException.class, () -> OidcDiscovery.fetch(idp.issuer(), Set.of("127.0.0.1")));
        assertThrows(IllegalArgumentException.class,
                () -> OidcDiscovery.fetch(idp.issuer(), new OidcHttp()));
        assertEquals(0, idp.discoveryRequests());
    }

    @Test
    void theLoopbackFlagCoversOnlyLoopbackLiterals() {
        OidcHttp test = OidcHttp.forLoopbackTests();
        assertTrue(test.accepts(URI.create("http://127.0.0.1:8080/x")));
        assertTrue(test.accepts(URI.create("http://localhost/x")));
        assertTrue(test.accepts(URI.create("http://[::1]:9/x")));
        assertTrue(test.accepts(URI.create("https://idp.example/x")));
        assertFalse(test.accepts(URI.create("http://127.0.0.1.evil.example/x")));
        assertFalse(test.accepts(URI.create("http://localhost.evil.example/x")));
        assertFalse(test.accepts(URI.create("http://10.0.0.1/x")));
        assertFalse(test.accepts(URI.create("http://example.org/x")));
        OidcHttp production = new OidcHttp();
        assertFalse(production.accepts(URI.create("http://127.0.0.1:8080/x")));
        assertFalse(production.accepts(URI.create("http://localhost/x")));
        assertTrue(production.accepts(URI.create("https://idp.example/x")));
    }
}

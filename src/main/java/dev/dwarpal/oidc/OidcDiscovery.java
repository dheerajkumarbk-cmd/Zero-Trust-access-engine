package dev.dwarpal.oidc;

import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * The validated metadata of one OpenID provider (OpenID Connect Discovery 1.0), read from
 * {@code <issuer>/.well-known/openid-configuration}.
 *
 * <p>Trust comes from the configured issuer only. The document's {@code issuer} must equal the
 * configured one exactly; {@code jwks_uri}, {@code authorization_endpoint} and {@code token_endpoint}
 * must be https URLs without user information or fragment, on the issuer's own host and port unless
 * the caller names extra hosts explicitly. A document that breaks any rule is refused whole, so an
 * object of this class always holds checked values (which is why it is a class with a private
 * constructor and not a record: nobody can build one from unchecked values).
 */
public final class OidcDiscovery {

    /** Largest discovery document accepted. */
    public static final int MAX_BYTES = 64 * 1024;

    private static final int MAX_ISSUER_CHARS = 200;
    private static final int MAX_URL_CHARS = 2048;
    private static final int MAX_ALGS = 64;
    private static final Set<String> JSON_TYPES = Set.of("application/json");
    private static final Set<String> SUPPORTED_ALGS = Set.of(OidcPolicy.RS256, OidcPolicy.ES256, OidcPolicy.EDDSA);
    private static final JsonLimits LIMITS = new JsonLimits(MAX_BYTES, 8, 4096, 256, 256, 32, 5000);

    private final String issuer;
    private final URI jwksUri;
    private final URI authorizationEndpoint;
    private final URI tokenEndpoint;
    private final boolean issParameterSupported;
    private final Set<String> signingAlgorithms;

    private OidcDiscovery(String issuer, URI jwksUri, URI authorizationEndpoint, URI tokenEndpoint,
                          boolean issParameterSupported, Set<String> signingAlgorithms) {
        this.issuer = issuer;
        this.jwksUri = jwksUri;
        this.authorizationEndpoint = authorizationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.issParameterSupported = issParameterSupported;
        this.signingAlgorithms = Set.copyOf(signingAlgorithms);
    }

    /**
     * Fetches and validates the discovery document of {@code issuer}; all URLs must be on the issuer's host.
     *
     * @throws IllegalArgumentException if the issuer is not an https URL without query, fragment or user information
     * @throws OidcException            if the document cannot be fetched ({@code KEYS_UNAVAILABLE}) or is not acceptable
     *                                  ({@code KEYS_INVALID})
     */
    public static OidcDiscovery fetch(String issuer) {
        return fetch(issuer, Set.of(), new OidcHttp());
    }

    /**
     * As {@link #fetch(String)}, but the endpoints may also be on the named hosts (lower-case host names,
     * no scheme or port). Use only for a provider known to serve its keys from another host.
     */
    public static OidcDiscovery fetch(String issuer, Set<String> extraHosts) {
        return fetch(issuer, extraHosts, new OidcHttp());
    }

    static OidcDiscovery fetch(String issuer, OidcHttp http) {
        return fetch(issuer, Set.of(), http);
    }

    static OidcDiscovery fetch(String issuer, Set<String> extraHosts, OidcHttp http) {
        Objects.requireNonNull(http, "http");
        Set<String> extra = lowerCase(Objects.requireNonNull(extraHosts, "extraHosts"));
        URI issuerUri = checkIssuer(issuer, http);
        String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        URI documentUri = URI.create(base + "/.well-known/openid-configuration");
        byte[] body = http.get(documentUri, MAX_BYTES, JSON_TYPES);
        JsonValue root;
        try {
            root = new JsonReader(LIMITS).read(body);
        } catch (JsonException e) {
            throw invalid();
        }
        if (!(root instanceof JsonValue.JObject doc)) {
            throw invalid();
        }
        if (!issuer.equals(requiredString(doc, "issuer"))) {
            throw invalid();
        }
        URI jwks = endpoint(doc, "jwks_uri", issuerUri, extra, http);
        URI authorization = endpoint(doc, "authorization_endpoint", issuerUri, extra, http);
        URI token = endpoint(doc, "token_endpoint", issuerUri, extra, http);
        return new OidcDiscovery(issuer, jwks, authorization, token, issParameter(doc), algorithms(doc));
    }

    /** The issuer, exactly as configured and as the provider states it. */
    public String issuer() {
        return issuer;
    }

    /** Where the provider's signing keys are published. */
    public URI jwksUri() {
        return jwksUri;
    }

    public URI authorizationEndpoint() {
        return authorizationEndpoint;
    }

    public URI tokenEndpoint() {
        return tokenEndpoint;
    }

    /** Whether the provider adds {@code iss} to authorization responses (RFC 9207); false if it does not say. */
    public boolean authorizationResponseIssParameterSupported() {
        return issParameterSupported;
    }

    /** The ID-token signing algorithms the provider lists; at least one of RS256, ES256, EdDSA is among them. */
    public Set<String> idTokenSigningAlgorithms() {
        return signingAlgorithms;
    }

    private static URI checkIssuer(String issuer, OidcHttp http) {
        URI uri = null;
        if (issuer != null && !issuer.isEmpty() && issuer.length() <= MAX_ISSUER_CHARS) {
            try {
                uri = new URI(issuer);
            } catch (URISyntaxException e) {
                uri = null;
            }
        }
        if (uri == null || !http.accepts(uri) || uri.getRawQuery() != null || issuer.indexOf('#') >= 0
                || issuer.indexOf('?') >= 0) {
            throw new IllegalArgumentException("the issuer must be an https URL of at most 200 characters "
                    + "without query, fragment or user information");
        }
        return uri;
    }

    private static URI endpoint(JsonValue.JObject doc, String name, URI issuerUri, Set<String> extraHosts,
                                OidcHttp http) {
        String text = requiredString(doc, name);
        if (text.length() > MAX_URL_CHARS) {
            throw invalid();
        }
        URI uri;
        try {
            uri = new URI(text);
        } catch (URISyntaxException e) {
            throw invalid();
        }
        if (!http.accepts(uri)) {
            throw invalid();
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        boolean sameOrigin = host.equals(issuerUri.getHost().toLowerCase(Locale.ROOT))
                && port(uri) == port(issuerUri);
        if (!sameOrigin && !extraHosts.contains(host)) {
            throw invalid();
        }
        return uri;
    }

    private static int port(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static boolean issParameter(JsonValue.JObject doc) {
        JsonValue v = doc.get("authorization_response_iss_parameter_supported").orElse(null);
        if (v == null) {
            return false;
        }
        if (v instanceof JsonValue.JBool b) {
            return b.value();
        }
        throw invalid();
    }

    private static Set<String> algorithms(JsonValue.JObject doc) {
        if (!(doc.get("id_token_signing_alg_values_supported").orElse(null) instanceof JsonValue.JArray array)
                || array.size() > MAX_ALGS) {
            throw invalid();
        }
        Set<String> algs = new HashSet<>();
        for (JsonValue e : array.elements()) {
            if (!(e instanceof JsonValue.JString s) || s.value().length() > 32) {
                throw invalid();
            }
            algs.add(s.value());
        }
        if (algs.stream().noneMatch(SUPPORTED_ALGS::contains)) {
            throw invalid();
        }
        return algs;
    }

    private static String requiredString(JsonValue.JObject doc, String name) {
        if (doc.get(name).orElse(null) instanceof JsonValue.JString s && !s.value().isEmpty()) {
            return s.value();
        }
        throw invalid();
    }

    private static Set<String> lowerCase(Set<String> hosts) {
        Set<String> out = new HashSet<>();
        for (String h : hosts) {
            out.add(Objects.requireNonNull(h, "host").toLowerCase(Locale.ROOT));
        }
        return out;
    }

    private static OidcException invalid() {
        return new OidcException(OidcException.Reason.KEYS_INVALID);
    }
}

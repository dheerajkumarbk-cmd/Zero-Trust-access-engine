package dev.dwarpal.console;

import dev.dwarpal.edge.DevPki;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.socapi.Delegation;
import dev.dwarpal.soc.Verdict;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonLimits;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

/**
 * The {@link SocChannel} of part 0b: the console connects with its <i>own</i> certificate ({@code console}, mutual TLS
 * 1.3, server pinned to {@code CN=soc-api}) and adds to every call a signed assertion naming the analyst
 * ({@link Delegation}, header {@code Dwarpal-On-Behalf-Of}): method, path and body hash are signed, it lives 60
 * seconds and works once. The console process therefore holds no analyst certificates; the SOC API still decides what
 * the analyst may do. Request bodies are built here from typed arguments, never copied from the browser; answers are
 * bounded and checked to be JSON. Any failure to reach the SOC API is {@link Reply#unavailable()}.
 */
public final class DelegatedSocChannel implements SocChannel {

    /** The largest answer taken from the SOC API. */
    static final int MAX_REPLY_BYTES = 4 * 1024 * 1024;
    private static final JsonReader CHECK = new JsonReader(new JsonLimits(MAX_REPLY_BYTES, 32, 16_384, 2_048, 8_192, 40,
            1_000_000));

    private final java.util.function.Supplier<String> baseUrl;
    private final Set<String> analysts;
    private final Duration timeout;
    private final java.util.function.Supplier<Delegation.Issuer> issuer;
    private final HttpClient client;

    /**
     * @param baseUrl  {@code https://localhost:<port>} of the SOC API
     * @param analysts the people the SOC API knows as analysts (the console refuses to ask for anyone else)
     */
    public DelegatedSocChannel(DevPki pki, String baseUrl, Delegation.Issuer issuer, Set<String> analysts, Duration timeout)
            throws IOException, GeneralSecurityException {
        this(pki, () -> baseUrl, () -> issuer, analysts, timeout);
    }

    /** With suppliers, so a lab reset (new SOC API port, new delegation key) is followed without rebuilding the channel. */
    public DelegatedSocChannel(DevPki pki, java.util.function.Supplier<String> baseUrl,
                               java.util.function.Supplier<Delegation.Issuer> issuer, Set<String> analysts, Duration timeout)
            throws IOException, GeneralSecurityException {
        this.baseUrl = baseUrl;
        this.issuer = issuer;
        this.analysts = Set.copyOf(analysts);
        this.timeout = timeout;
        SSLContext ctx = TlsContexts.createPinned(pki.keyStore("console"), pki.password(), pki.trustStore(), pki.password(),
                TlsContexts.component("soc-api"));
        this.client = HttpClient.newBuilder().sslContext(ctx).sslParameters(TlsContexts.clientParameters(ctx))
                .version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER).build();
    }

    @Override
    public Optional<Calls> forAnalyst(String analystId) {
        if (!analysts.contains(analystId)) {
            return Optional.empty();
        }
        return Optional.of(new As(analystId));
    }

    private final class As implements Calls {
        private final String analyst;

        As(String analyst) {
            this.analyst = analyst;
        }

        private Reply call(String method, String path, String body) {
            try {
                byte[] sent = body == null ? null : body.getBytes(StandardCharsets.UTF_8);
                HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl.get() + path)).timeout(timeout)
                        .header(Delegation.HEADER, issuer.get().header(analyst, method, path, sent));
                if (sent == null) {
                    b.GET();
                } else {
                    b.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofByteArray(sent));
                }
                HttpResponse<InputStream> r = client.send(b.build(), HttpResponse.BodyHandlers.ofInputStream());
                byte[] bytes;
                try (InputStream in = r.body()) {
                    bytes = in.readNBytes(MAX_REPLY_BYTES + 1);
                }
                if (bytes.length > MAX_REPLY_BYTES) {
                    return Reply.unavailable();
                }
                String text = new String(bytes, StandardCharsets.UTF_8);
                CHECK.read(bytes);
                return new Reply(r.statusCode(), text);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Reply.unavailable();
            } catch (IOException | JsonException | IllegalArgumentException e) {
                return Reply.unavailable();
            }
        }

        @Override
        public Reply queue() {
            return call("GET", "/v1/queue", null);
        }

        @Override
        public Reply cases() {
            return call("GET", "/v1/cases", null);
        }

        @Override
        public Reply caseDetail(String caseId) {
            return call("GET", "/v1/cases/" + ConsoleIds.plain(caseId), null);
        }

        @Override
        public Reply timeline(String caseId) {
            return call("GET", "/v1/cases/" + ConsoleIds.plain(caseId) + "/timeline", null);
        }

        @Override
        public Reply note(String caseId, String text) {
            return call("POST", "/v1/cases/" + ConsoleIds.plain(caseId) + "/notes",
                    write(JsonValue.object().put("v", JsonValue.num(1)).put("text", text).build()));
        }

        @Override
        public Reply assign(String caseId, String assignee) {
            return call("POST", "/v1/cases/" + ConsoleIds.plain(caseId) + "/assignment",
                    write(JsonValue.object().put("v", JsonValue.num(1)).put("assignee", assignee).build()));
        }

        @Override
        public Reply verdict(Verdict v) {
            JsonValue proof = JsonValue.object().put("keyId", v.proof().keyId()).put("signedAt", v.proof().signedAt().toString())
                    .put("signature", v.proof().signature()).build();
            return call("POST", "/v1/verdicts", write(JsonValue.object().put("v", JsonValue.num(1))
                    .put("alertId", v.alertId()).put("analystId", v.analystId()).put("outcome", v.outcome().name())
                    .put("proof", proof).build()));
        }

        @Override
        public Reply riskTop() {
            return call("GET", "/v1/risk/top", null);
        }

        @Override
        public Reply risk(String kind, String id) {
            return call("GET", "/v1/risk/" + ConsoleIds.plain(kind) + "/" + ConsoleIds.plain(id), null);
        }

        @Override
        public Reply search(Search s) {
            return call("POST", "/v1/search", write(JsonValue.object().put("v", JsonValue.num(1)).put("query", s.query())
                    .put("from", s.from().toString()).put("to", s.to().toString()).put("limit", JsonValue.num(s.limit()))
                    .build()));
        }

        @Override
        public Reply counts(Search s) {
            return call("POST", "/v1/counts", write(JsonValue.object().put("v", JsonValue.num(1)).put("query", s.query())
                    .put("from", s.from().toString()).put("to", s.to().toString()).build()));
        }

        @Override
        public Reply isolations() {
            return call("GET", "/v1/isolations", null);
        }

        @Override
        public Reply metrics() {
            return call("GET", "/v1/metrics", null);
        }

        @Override
        public Reply report(String name) {
            return call("GET", "/v1/reports/" + ConsoleIds.plain(name), null);
        }

        private String write(JsonValue v) {
            return JsonWriter.write(v);
        }
    }
}

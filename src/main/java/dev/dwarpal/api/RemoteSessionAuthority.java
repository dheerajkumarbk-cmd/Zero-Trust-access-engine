package dev.dwarpal.api;

import dev.dwarpal.crypto.SignatureProof;
import dev.dwarpal.domain.AuthMethod;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.SessionAuthority;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.edge.WireFormat;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import javax.net.ssl.SSLContext;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.time.Duration;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.time.Instant;

/**
 * {@link SessionAuthority} over the network: the enforcement point's client for {@link ApiServer}.
 *
 * <p>Fail-closed in every way it can fail: a refused connection, a TLS failure, a server that is not
 * the API, a status other than 200, an answer that is late, too large, not JSON, not a valid result,
 * or not the answer to this question, all become DENIED (a token that is not even well-formed is
 * REJECTED without a call, as the in-process authority answers). It never throws for those, never
 * follows redirects and never uses a proxy.
 *
 * <ul>
 *   <li><b>Pinned server</b> (A1): the CA <em>and</em> the API's exact certificate subject, checked in the
 *       handshake, so another Dwarpal component cannot answer in the API's place.</li>
 *   <li><b>One deadline for the whole exchange, at most 64 KiB</b> (A3): a server that drips or floods
 *       its answer is cut off.</li>
 *   <li><b>The answer must fit the question</b> (A4): its reference is this request's id, and a login is
 *       never answered with a bare grant, nor a request with a new session.</li>
 * </ul>
 *
 * <p><b>Engine-down alarm:</b> after {@value #DEFAULT_ALARM_THRESHOLD} (settable) consecutive unacceptable
 * answers the {@link EngineAlarm} is told once; the first acceptable answer afterwards tells it once more.
 * The alarm never changes an answer, and an alarm that throws is counted ({@link #alarmFailures()}) and ignored.
 */
public final class RemoteSessionAuthority implements SessionAuthority, AutoCloseable {

    /** Consecutive failures before the alarm fires, unless set. */
    public static final int DEFAULT_ALARM_THRESHOLD = 5;
    private static final int MAX_ANSWER_BYTES = 64 * 1024;
    private static final Set<EdgeResult.Status> OPEN_ANSWERS = EnumSet.of(EdgeResult.Status.OPENED,
            EdgeResult.Status.STEP_UP, EdgeResult.Status.DENIED, EdgeResult.Status.REJECTED);
    private static final Set<EdgeResult.Status> REQUEST_ANSWERS = EnumSet.complementOf(EnumSet.of(EdgeResult.Status.OPENED));

    private final HttpClient http;
    private final URI base;
    private final Duration timeout;
    private final JsonReader json = new JsonReader();
    private final AtomicLong failures = new AtomicLong();
    private final EngineAlarm alarm;
    private final long alarmThreshold;
    private final AtomicLong consecutive = new AtomicLong();
    private final AtomicBoolean down = new AtomicBoolean();
    private final AtomicLong alarmFailures = new AtomicLong();

    private RemoteSessionAuthority(URI base, SSLContext tls, Duration timeout, EngineAlarm alarm, int threshold) {
        this.alarm = Objects.requireNonNull(alarm, "alarm");
        if (threshold < 1) {
            throw new IllegalArgumentException("threshold must be at least 1");
        }
        this.alarmThreshold = threshold;
        this.base = Objects.requireNonNull(base, "base");
        if (!"https".equals(base.getScheme()) || base.getHost() == null
                || (base.getRawPath() != null && !base.getRawPath().isEmpty())) {
            throw new IllegalArgumentException("base must be an https origin without a path");
        }
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
        this.http = HttpClient.newBuilder()
                .sslContext(Objects.requireNonNull(tls, "tls"))
                .sslParameters(TlsContexts.clientParameters(tls))
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .proxy(HttpClient.Builder.NO_PROXY)
                .connectTimeout(timeout)
                .build();
    }

    /**
     * A client that presents this enforcement point's certificate and talks only to the API.
     *
     * @param base       the API's origin, for example {@code https://localhost:8443}
     * @param keyStore   this enforcement point's key and certificate chain (PKCS12)
     * @param trustStore the Dwarpal CA only (PKCS12)
     * @param api        the API's exact certificate subject, normally {@code TlsContexts.component("api")}
     * @param timeout    for connecting, and for the whole exchange
     */
    public static RemoteSessionAuthority connect(URI base, Path keyStore, char[] keyStorePassword, Path trustStore,
                                                 char[] trustStorePassword, X500Principal api, Duration timeout)
            throws IOException, GeneralSecurityException {
        return connect(base, keyStore, keyStorePassword, trustStore, trustStorePassword, api, timeout,
                EngineAlarm.NONE, DEFAULT_ALARM_THRESHOLD);
    }

    /** As above, with an alarm told when {@code threshold} calls in a row fail, and when the engine answers again. */
    public static RemoteSessionAuthority connect(URI base, Path keyStore, char[] keyStorePassword, Path trustStore,
                                                 char[] trustStorePassword, X500Principal api, Duration timeout,
                                                 EngineAlarm alarm, int threshold)
            throws IOException, GeneralSecurityException {
        return new RemoteSessionAuthority(base,
                TlsContexts.createPinned(keyStore, keyStorePassword, trustStore, trustStorePassword, api), timeout,
                alarm, threshold);
    }

    /** With a context made elsewhere (tests only: such a context trusts any component as the server). */
    static RemoteSessionAuthority create(URI base, SSLContext tls, Duration timeout) {
        return new RemoteSessionAuthority(base, tls, timeout, EngineAlarm.NONE, DEFAULT_ALARM_THRESHOLD);
    }

    /** With a context made elsewhere and an alarm (tests only). */
    static RemoteSessionAuthority create(URI base, SSLContext tls, Duration timeout, EngineAlarm alarm, int threshold) {
        return new RemoteSessionAuthority(base, tls, timeout, alarm, threshold);
    }

    @Override
    public void close() {
        http.close();
    }

    @Override
    public EdgeResult open(EdgeRequest login, PublicKey sessionKey, Optional<SignatureProof> deviceBinding) {
        Objects.requireNonNull(login, "login");
        Objects.requireNonNull(sessionKey, "sessionKey");
        Objects.requireNonNull(deviceBinding, "deviceBinding");
        try {
            return call(ApiServer.Endpoint.OPEN, WireFormat.open(new WireFormat.OpenBody(login, sessionKey, deviceBinding)),
                    login.requestId(), OPEN_ANSWERS);
        } catch (RuntimeException e) {
            return denied(login.requestId());
        }
    }

    @Override
    public EdgeResult use(String token, SignatureProof proof, EdgeRequest request) {
        Objects.requireNonNull(request, "request");
        WireFormat.UseBody body;
        try {
            body = new WireFormat.UseBody(token, proof, request);
        } catch (RuntimeException e) {
            return answer(EdgeResult.Status.REJECTED, request.requestId());
        }
        try {
            return call(ApiServer.Endpoint.USE, WireFormat.use(body), request.requestId(), REQUEST_ANSWERS);
        } catch (RuntimeException e) {
            return denied(request.requestId());
        }
    }

    @Override
    public EdgeResult decide(EdgeRequest request) {
        Objects.requireNonNull(request, "request");
        try {
            return call(ApiServer.Endpoint.DECIDE, WireFormat.decide(new WireFormat.DecideBody(request)),
                    request.requestId(), REQUEST_ANSWERS);
        } catch (RuntimeException e) {
            return denied(request.requestId());
        }
    }

    /** Calls answered DENIED because the API could not be reached or its answer was not acceptable. */
    public long failures() {
        return failures.get();
    }

    /** Alarm calls that threw (the answer was still DENIED). */
    public long alarmFailures() {
        return alarmFailures.get();
    }

    private EdgeResult call(ApiServer.Endpoint endpoint, JsonValue body, String reference,
                            Set<EdgeResult.Status> fitting) {
        HttpRequest req = HttpRequest.newBuilder(base.resolve(endpoint.path()))
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(JsonWriter.bytes(body)))
                .build();
        CompletableFuture<HttpResponse<byte[]>> pending = http.sendAsync(req, info -> new Limited(MAX_ANSWER_BYTES));
        HttpResponse<byte[]> res;
        try {
            res = pending.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (ExecutionException | TimeoutException e) {
            pending.cancel(true);
            return denied(reference);
        } catch (InterruptedException e) {
            pending.cancel(true);
            Thread.currentThread().interrupt();
            return denied(reference);
        }
        if (res.statusCode() != 200) {
            return denied(reference);
        }
        EdgeResult r = WireFormat.readResult(json.read(res.body()));
        if (!r.reference().equals(reference) || !fitting.contains(r.status())) {
            return denied(reference);
        }
        succeeded();
        return r;
    }

    private void succeeded() {
        consecutive.set(0);
        if (down.compareAndSet(true, false)) {
            try {
                alarm.engineBack(Instant.now());
            } catch (RuntimeException | Error e) {
                alarmFailures.incrementAndGet();
            }
        }
    }

    private void failed() {
        long n = consecutive.incrementAndGet();
        if (n >= alarmThreshold && down.compareAndSet(false, true)) {
            try {
                alarm.engineDown(n, Instant.now());
            } catch (RuntimeException | Error e) {
                alarmFailures.incrementAndGet();
            }
        }
    }

    private EdgeResult denied(String reference) {
        failures.incrementAndGet();
        failed();
        return answer(EdgeResult.Status.DENIED, reference);
    }

    private static EdgeResult answer(EdgeResult.Status status, String reference) {
        Optional<AuthMethod> none = Optional.empty();
        return new EdgeResult(status, reference, EdgeResult.genericMessage(status, reference), false, none,
                Optional.empty(), false);
    }

    /** Collects at most {@code max} bytes; one byte more cancels the exchange. */
    private static final class Limited implements HttpResponse.BodySubscriber<byte[]> {
        private final int max;
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private Flow.Subscription subscription;

        Limited(int max) {
            this.max = max;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result.minimalCompletionStage();
        }

        @Override
        public void onSubscribe(Flow.Subscription s) {
            subscription = s;
            s.request(1);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer b : buffers) {
                if (bytes.size() + b.remaining() > max) {
                    subscription.cancel();
                    result.completeExceptionally(new IOException("answer larger than " + max + " bytes"));
                    return;
                }
                byte[] chunk = new byte[b.remaining()];
                b.get(chunk);
                bytes.writeBytes(chunk);
            }
            subscription.request(1);
        }

        @Override
        public void onError(Throwable t) {
            result.completeExceptionally(t);
        }

        @Override
        public void onComplete() {
            result.complete(bytes.toByteArray());
        }
    }
}

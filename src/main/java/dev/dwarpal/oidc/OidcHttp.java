package dev.dwarpal.oidc;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * The only way this package talks to an identity provider: one GET, over https, with every limit
 * set. Redirects are never followed (a redirect is a refusal), the connection is made within 3
 * seconds and the whole answer must arrive within 5 seconds, the status must be 200, the media type
 * must be one the caller names, and the body is read as a stream that stops at the size cap.
 *
 * <p>Every failure is an {@link OidcException} ({@code KEYS_UNAVAILABLE}) with its fixed message:
 * no URL, query, header or body text ever appears in an error.
 *
 * <p>Plain http is refused. The one exception is a flag that only code in this package can set
 * (tests use it): it permits http when the host is literally {@code localhost}, {@code 127.0.0.1}
 * or {@code [::1]}. Production code never sets it.
 */
final class OidcHttp {

    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(3);
    static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final HttpClient client;
    private final boolean allowLoopbackHttp;
    private final Duration requestTimeout;

    /** The production helper: https only, 5 second limit. */
    OidcHttp() {
        this(false, REQUEST_TIMEOUT);
    }

    OidcHttp(boolean allowLoopbackHttp, Duration requestTimeout) {
        this.allowLoopbackHttp = allowLoopbackHttp;
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(CONNECT_TIMEOUT)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    /** A helper that also permits http to a loopback host (tests only). */
    static OidcHttp forLoopbackTests() {
        return new OidcHttp(true, REQUEST_TIMEOUT);
    }

    /**
     * Whether this helper would ever contact {@code uri}: an absolute https URL with a host, no
     * user information and no fragment; or, only when the loopback flag is set, an http URL whose
     * host is literally localhost, 127.0.0.1 or [::1].
     */
    boolean accepts(URI uri) {
        if (uri == null || !uri.isAbsolute() || uri.isOpaque() || uri.getHost() == null
                || uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
            return false;
        }
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if ("https".equals(scheme)) {
            return true;
        }
        return allowLoopbackHttp && "http".equals(scheme) && isLoopbackLiteral(uri.getHost());
    }

    private static boolean isLoopbackLiteral(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        return h.equals("localhost") || h.equals("127.0.0.1") || h.equals("[::1]");
    }

    /** Fetches with the helper's own request limit. */
    byte[] get(URI uri, int maxBytes, Set<String> mediaTypes) {
        return get(uri, maxBytes, requestTimeout, mediaTypes);
    }

    /**
     * Fetches {@code uri}.
     *
     * @param maxBytes   most body bytes accepted; more is a refusal
     * @param timeout    limit for the whole answer, headers and body together
     * @param mediaTypes lower-case media types the response may declare (parameters such as charset are ignored)
     * @throws OidcException {@code KEYS_UNAVAILABLE} on any failure
     */
    byte[] get(URI uri, int maxBytes, Duration timeout, Set<String> mediaTypes) {
        if (!accepts(uri) || maxBytes < 1) {
            throw unavailable();
        }
        HttpRequest request;
        try {
            request = HttpRequest.newBuilder(uri).timeout(timeout).header("Accept", String.join(", ", mediaTypes))
                    .GET().build();
        } catch (RuntimeException e) {
            throw unavailable();
        }
        CompletableFuture<HttpResponse<byte[]>> pending =
                client.sendAsync(request, info -> bodyFor(info, maxBytes, mediaTypes));
        HttpResponse<byte[]> response;
        try {
            response = pending.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException | ExecutionException | RuntimeException e) {
            pending.cancel(true);
            throw unavailable();
        } catch (InterruptedException e) {
            pending.cancel(true);
            Thread.currentThread().interrupt();
            throw unavailable();
        }
        byte[] body = response.body();
        if (!acceptable(response.statusCode(), response.headers(), maxBytes, mediaTypes) || body == null
                || body.length > maxBytes) {
            throw unavailable();
        }
        return body;
    }

    private static OidcException unavailable() {
        return new OidcException(OidcException.Reason.KEYS_UNAVAILABLE);
    }

    private static boolean acceptable(int status, HttpHeaders headers, int maxBytes, Set<String> mediaTypes) {
        if (status != 200) {
            return false;
        }
        String type = headers.firstValue("Content-Type").orElse("");
        int semicolon = type.indexOf(';');
        String media = (semicolon >= 0 ? type.substring(0, semicolon) : type).trim().toLowerCase(Locale.ROOT);
        if (!mediaTypes.contains(media)) {
            return false;
        }
        try {
            OptionalLong declared = headers.firstValueAsLong("Content-Length");
            return declared.isEmpty() || declared.getAsLong() <= maxBytes;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static HttpResponse.BodySubscriber<byte[]> bodyFor(HttpResponse.ResponseInfo info, int maxBytes,
                                                               Set<String> mediaTypes) {
        if (!acceptable(info.statusCode(), info.headers(), maxBytes, mediaTypes)) {
            return HttpResponse.BodySubscribers.replacing(new byte[0]);
        }
        return new CappedBody(maxBytes);
    }

    /** Collects a body but stops, and fails, as soon as it would pass the cap. */
    private static final class CappedBody implements HttpResponse.BodySubscriber<byte[]> {

        private final int max;
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private Flow.Subscription subscription;
        private boolean finished;

        CappedBody(int max) {
            this.max = max;
        }

        @Override
        public CompletableFuture<byte[]> getBody() {
            return result;
        }

        @Override
        public synchronized void onSubscribe(Flow.Subscription s) {
            this.subscription = s;
            s.request(1);
        }

        @Override
        public synchronized void onNext(List<ByteBuffer> items) {
            if (finished) {
                return;
            }
            for (ByteBuffer b : items) {
                if ((long) out.size() + b.remaining() > max) {
                    finished = true;
                    subscription.cancel();
                    result.completeExceptionally(unavailable());
                    return;
                }
                byte[] chunk = new byte[b.remaining()];
                b.get(chunk);
                out.write(chunk, 0, chunk.length);
            }
            subscription.request(1);
        }

        @Override
        public synchronized void onError(Throwable throwable) {
            finished = true;
            result.completeExceptionally(unavailable());
        }

        @Override
        public synchronized void onComplete() {
            if (!finished) {
                finished = true;
                result.complete(out.toByteArray());
            }
        }
    }
}

package dev.dwarpal.integration;

import dev.dwarpal.edge.DevPki;
import dev.dwarpal.edge.TlsContexts;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.List;

/** A client of the SOC API over mutual TLS with a certificate from the development CA made at run time. */
final class SocApiClient implements AutoCloseable {

    record Reply(int status, String body) {
    }

    private static DevPki pki;

    static synchronized DevPki pki() {
        if (pki == null) {
            try {
                Path dir = Files.createTempDirectory("dwarpal-soc-e2e-pki");
                pki = DevPki.create(dir.resolve("dwarpal"), "Dwarpal Dev CA", List.of(DevPki.Leaf.valid("soc-api"),
                        DevPki.Leaf.valid("ana"), DevPki.Leaf.valid("ben"), DevPki.Leaf.valid("cleo"), DevPki.Leaf.valid("stranger")));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
        return pki;
    }

    static SSLContext ctx(String leaf) {
        try {
            return TlsContexts.create(pki().keyStore(leaf), pki().password(), pki().trustStore(), pki().password());
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private final HttpClient http;
    private final URI base;

    SocApiClient(URI base, String leaf) {
        this.base = base;
        SSLContext c = ctx(leaf);
        http = HttpClient.newBuilder().sslContext(c).sslParameters(TlsContexts.clientParameters(c))
                .version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(5)).build();
    }

    Reply get(String path) throws IOException, InterruptedException {
        return send(HttpRequest.newBuilder(base.resolve(path)).GET());
    }

    Reply post(String path, String json) throws IOException, InterruptedException {
        return send(HttpRequest.newBuilder(base.resolve(path)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8)));
    }

    private Reply send(HttpRequest.Builder b) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(b.timeout(Duration.ofSeconds(10)).build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return new Reply(r.statusCode(), r.body());
    }

    @Override
    public void close() {
        http.close();
    }
}

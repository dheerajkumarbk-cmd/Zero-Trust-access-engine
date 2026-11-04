package dev.dwarpal.agent;

import dev.dwarpal.devidp.DevIdpServer;
import dev.dwarpal.devidp.IdentityProvider;
import dev.dwarpal.devidp.IdpWire;
import dev.dwarpal.devidp.WebAuthn;
import dev.dwarpal.wire.JsonException;
import dev.dwarpal.wire.JsonReader;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/**
 * The identity provider over HTTP, as the client agent uses it. Any network, status or parse problem
 * is simply "no answer": the agent then has no proof and cannot log in.
 */
public final class HttpIdentityProvider implements IdentityProvider {

    private static final int MAX_RESPONSE = 16 * 1024;

    private final URI base;
    private final HttpClient http;
    private final Duration timeout;

    public HttpIdentityProvider(URI base, HttpClient http, Duration timeout) {
        this.base = Objects.requireNonNull(base, "base");
        this.http = Objects.requireNonNull(http, "http");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
    }

    @Override
    public Optional<WebAuthn.Challenge> challenge(String subjectId, String deviceId, String keyThumbprint) {
        return post(DevIdpServer.CHALLENGE_PATH, IdpWire.challengeRequest(
                new IdpWire.ChallengeRequest(subjectId, deviceId, keyThumbprint)), IdpWire::readChallenge);
    }

    @Override
    public Optional<MfaProof> authenticate(Attempt attempt) {
        return post(DevIdpServer.AUTHENTICATE_PATH, IdpWire.attempt(attempt), IdpWire::readMfa);
    }

    private <T> Optional<T> post(String path, JsonValue body, Function<JsonValue, T> parse) {
        HttpRequest req = HttpRequest.newBuilder(base.resolve(path)).timeout(timeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(JsonWriter.bytes(body))).build();
        try {
            HttpResponse<byte[]> resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() != 200 || resp.body().length > MAX_RESPONSE) {
                return Optional.empty();
            }
            return Optional.of(parse.apply(new JsonReader().read(resp.body())));
        } catch (IOException | JsonException e) {
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }
}

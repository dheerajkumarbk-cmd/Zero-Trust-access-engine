package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Sess;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The event stream: bounded, one per session, closed with the session, every header, no data in the events. */
class ConsoleStreamTest {

    private static ConsoleFixture f;

    @BeforeAll
    static void start() throws Exception {
        f = ConsoleFixture.start(b -> {
        }, ConsoleSettings.defaults().fastHashing().withSessionLimits(3, 200, 2));
    }

    @AfterAll
    static void stop() {
        f.close();
    }

    private HttpResponse<InputStream> open(Sess s) throws Exception {
        HttpRequest r = HttpRequest.newBuilder(URI.create(f.base + "/console/api/stream")).header("User-Agent", ConsoleFixture.UA)
                .header("Cookie", ConsoleServer.COOKIE + "=" + s.cookie()).timeout(Duration.ofSeconds(30)).build();
        return f.http.send(r, HttpResponse.BodyHandlers.ofInputStream());
    }

    /** The next line that starts with {@code prefix}, or null if the stream ends or nothing comes in time. */
    private static String lineStartingWith(InputStream in, String prefix, int seconds) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        CompletableFuture<String> found = CompletableFuture.supplyAsync(() -> {
            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith(prefix)) {
                        return line;
                    }
                }
                return null;
            } catch (IOException e) {
                return null;
            }
        });
        try {
            return found.get(seconds, TimeUnit.SECONDS);
        } catch (java.util.concurrent.TimeoutException e) {
            return "TIMEOUT";
        }
    }

    @Test
    void aSessionGetsTickEventsWithTheScenarioClockAndTheBaselineHeaders() throws Exception {
        Sess ana = f.login("ana");
        HttpResponse<InputStream> r = open(ana);
        assertEquals(200, r.statusCode());
        assertEquals("text/event-stream; charset=utf-8", r.headers().firstValue("Content-Type").orElse(""));
        assertEquals("no-store", r.headers().firstValue("Cache-Control").orElse(""));
        for (var h : SecurityHeaders.ALL.entrySet()) {
            assertEquals(h.getValue(), r.headers().firstValue(h.getKey()).orElse(null), h.getKey());
        }
        String tick = lineStartingWith(r.body(), "data:", 10);
        assertTrue(tick != null && tick.contains("\"time\"") && tick.contains("\"state\""), String.valueOf(tick));
        assertTrue(!tick.contains("case-") && !tick.contains("ana"), "events carry no case ids or names: " + tick);
        r.body().close();
    }

    @Test
    void aStreamNeedsASession() throws Exception {
        HttpRequest r = HttpRequest.newBuilder(URI.create(f.base + "/console/api/stream")).build();
        assertEquals(401, f.http.send(r, HttpResponse.BodyHandlers.ofString()).statusCode());
    }

    @Test
    void aNewStreamForTheSameSessionReplacesTheOld() throws Exception {
        Sess ben = f.login("ben");
        HttpResponse<InputStream> first = open(ben);
        assertEquals("data:", lineStartingWith(first.body(), "data:", 10).substring(0, 5));
        HttpResponse<InputStream> second = open(ben);
        assertNull(lineStartingWith(first.body(), "never-matches", 10), "the first stream was ended by the server");
        assertEquals(1, f.server.openStreams());
        second.body().close();
    }

    @Test
    void theNumberOfStreamsIsCappedAndLogoutAndTimeoutEndThem() throws Exception {
        Sess a = f.login("ana");
        Sess b = f.login("ben");
        Sess c = f.login("cleo");
        HttpResponse<InputStream> ra = open(a);
        HttpResponse<InputStream> rb = open(b);
        assertEquals(200, ra.statusCode());
        assertEquals(200, rb.statusCode());
        assertEquals(503, open(c).statusCode(), "the third stream is refused: the cap is 2");

        f.post("/console/api/session/logout", a, "{}");
        assertNull(lineStartingWith(ra.body(), "never-matches", 10), "logout ends the stream");

        f.clock.advance(Duration.ofMinutes(16));
        assertNull(lineStartingWith(rb.body(), "never-matches", 10), "so does the idle timeout");
        assertEquals(0, f.server.openStreams());
    }
}

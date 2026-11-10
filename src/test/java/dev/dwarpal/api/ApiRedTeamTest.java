package dev.dwarpal.api;

import com.sun.net.httpserver.HttpsServer;
import dev.dwarpal.edge.EdgeFixtures;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.edge.WireFormat;
import dev.dwarpal.wire.JsonWriter;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Red-team pass on the engine API. Each test here was first written as a working attack against the
 * first version of the code; the ones that succeeded are findings A1 to A5 in docs/layer-4/part-a.md,
 * fixed and kept as regression tests. The rest are attacks that held from the start.
 */
class ApiRedTeamTest {

    private static final String GRANTED_FOR_ANYTHING = "{\"status\":\"GRANTED\",\"reference\":\"%s\","
            + "\"message\":\"Access granted.\",\"restricted\":false,\"sessionEnded\":false}";

    // ---- A1: another Dwarpal component impersonates the API -------------------------------------------

    @Test
    void a1_aCompromisedComponentCannotPoseAsTheApi() throws Exception {
        // Every component certificate from the dev CA is valid for "localhost". A compromised web gateway
        // listening on a port the enforcement point is told to use must not be believed, and must not
        // even receive the session token and proof.
        AtomicInteger bodiesSeen = new AtomicInteger();
        EdgeFixtures.World w = EdgeFixtures.world();
        String ref = "e-impostor";
        HttpsServer impostor = ApiKit.fakeApi("swg", ex -> {
            bodiesSeen.incrementAndGet();
            byte[] b = String.format(GRANTED_FOR_ANYTHING, ref).getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(b);
            }
        });
        try (RemoteSessionAuthority c = ApiKit.pinned(ApiKit.base(impostor), "gateway")) {
            EdgeResult r = c.decide(w.request().id(ref).resource("web:malicious").build());
            assertEquals(EdgeResult.Status.DENIED, r.status());
            assertEquals(0, bodiesSeen.get(), "nothing is sent to a server that is not the API");
        } finally {
            impostor.stop(0);
        }
    }

    // ---- A2: slow clients hold every worker -----------------------------------------------------------

    @Test
    void a2_slowBodiesAndSlowHeadersCannotStarveTheServer() throws Exception {
        ApiSettings tight = ApiSettings.defaults().withThreads(2, 2).withRequestDeadline(Duration.ofSeconds(1));
        try (ApiKit.Harness h = new ApiKit.Harness(EdgeFixtures.world(), tight, null, null)) {
            List<SSLSocket> attackers = new ArrayList<>();
            try {
                for (int i = 0; i < 2; i++) {
                    SSLSocket s = ApiKit.socket(h.base, "gateway");
                    String head = "POST /v1/decisions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
                            + "Content-Length: 1000\r\n\r\n{\"v\":";
                    s.getOutputStream().write(head.getBytes(StandardCharsets.US_ASCII));
                    s.getOutputStream().flush();
                    attackers.add(s);
                }
                for (int i = 0; i < 2; i++) {
                    SSLSocket s = ApiKit.socket(h.base, "gateway");
                    s.getOutputStream().write("POST /v1/decisions HTTP/1.1\r\nHost: loc".getBytes(StandardCharsets.US_ASCII));
                    s.getOutputStream().flush();
                    attackers.add(s);
                }
                try (ApiKit.Raw soc = h.raw("soc")) {
                    assertEquals(200, soc.get("/v1/health").status(), "the SOC still gets through");
                }
            } finally {
                for (SSLSocket s : attackers) {
                    s.close();
                }
            }
            assertTrue(h.server.timedOut() >= 2, "the slow requests were cut off");
        }
    }

    // ---- A3: a server that never stops answering -------------------------------------------------------

    @Test
    void a3_theClientHasADeadlineForTheWholeAnswerAndASizeLimit() throws Exception {
        HttpsServer drip = ApiKit.fakeApi("api", ex -> {
            ex.sendResponseHeaders(200, 0);
            try (OutputStream out = ex.getResponseBody()) {
                for (int i = 0; i < 300; i++) {
                    out.write(' ');
                    out.flush();
                    Thread.sleep(100);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        HttpsServer flood = ApiKit.fakeApi("api", ex -> {
            ex.sendResponseHeaders(200, 0);
            byte[] spaces = " ".repeat(64 * 1024).getBytes(StandardCharsets.US_ASCII);
            try (OutputStream out = ex.getResponseBody()) {
                for (int i = 0; i < 2000; i++) {
                    out.write(spaces);
                }
            }
        });
        EdgeFixtures.World w = EdgeFixtures.world();
        try (RemoteSessionAuthority slow = RemoteSessionAuthority.create(ApiKit.base(drip), ApiKit.ctx("gateway"),
                Duration.ofSeconds(1));
             RemoteSessionAuthority big = RemoteSessionAuthority.create(ApiKit.base(flood), ApiKit.ctx("gateway"),
                     Duration.ofSeconds(5))) {
            assertTimeoutPreemptively(Duration.ofSeconds(8), () ->
                    assertEquals(EdgeResult.Status.DENIED, slow.decide(w.request().build()).status()));
            assertTimeoutPreemptively(Duration.ofSeconds(8), () ->
                    assertEquals(EdgeResult.Status.DENIED, big.decide(w.request().build()).status()),
                    "a 128 MB answer is cut off at 64 KiB, not buffered");
        } finally {
            drip.stop(0);
            flood.stop(0);
        }
    }

    // ---- A4: an answer that belongs to another question ------------------------------------------------

    @Test
    void a4_anAnswerMustBelongToTheQuestion() throws Exception {
        HttpsServer confused = ApiKit.fakeApi("api", ex -> {
            byte[] b = String.format(GRANTED_FOR_ANYTHING, "e-someone-else").getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(b);
            }
        });
        EdgeFixtures.World w = EdgeFixtures.world();
        try (RemoteSessionAuthority c = RemoteSessionAuthority.create(ApiKit.base(confused), ApiKit.ctx("gateway"),
                Duration.ofSeconds(5))) {
            assertEquals(EdgeResult.Status.DENIED, c.decide(w.request().resource("web:malicious").build()).status(),
                    "a GRANTED for another request id is not this request's answer");
            assertEquals(EdgeResult.Status.DENIED, c.open(w.request().id("e-someone-else").build(),
                    dev.dwarpal.crypto.Ed25519.generateKeyPair().getPublic(), Optional.empty()).status(),
                    "a login is answered OPENED, STEP_UP, DENIED or REJECTED, never a bare GRANTED");
        } finally {
            confused.stop(0);
        }
    }

    // ---- A5: certificate subjects compared with case folding ----------------------------------------

    @Test
    void a5_callerSubjectsAreComparedExactlyNotCanonically() {
        // X500Principal.equals compares canonical forms, which fold case: CN=GATEWAY "equals" CN=gateway.
        assertTrue(new X500Principal("CN=GATEWAY").equals(TlsContexts.component("gateway")));
        try (ApiKit.Harness h = new ApiKit.Harness(ApiSettings.defaults())) {
            assertTrue(h.server.caller(TlsContexts.component("gateway")).isPresent());
            assertTrue(h.server.caller(new X500Principal("CN=GATEWAY")).isEmpty(), "another name, another caller");
            assertTrue(h.server.caller(new X500Principal("CN=gateway,O=Evil")).isEmpty());
            assertTrue(h.server.caller(new X500Principal("CN=gateway+OU=x")).isEmpty());
            assertTrue(h.server.caller(new X500Principal("OU=gateway")).isEmpty());
        }
    }

    // ---- attacks that held ------------------------------------------------------------------------------

    @Test
    void noCertificateWrongCaAndExpiredCertificatesNeverReachAHandler() throws Exception {
        try (ApiKit.Harness h = new ApiKit.Harness(ApiSettings.defaults())) {
            EdgeFixtures.World w = h.world;
            for (javax.net.ssl.SSLContext bad : List.of(ApiKit.ctx(ApiKit.rogue(), "gateway"), ApiKit.ctx("old-gateway"),
                    anonymous())) {
                try (RemoteSessionAuthority c = RemoteSessionAuthority.create(h.base, bad, Duration.ofSeconds(5))) {
                    assertEquals(EdgeResult.Status.DENIED, c.decide(w.request().resource("web:general").build()).status());
                    assertEquals(1, c.failures());
                }
            }
            assertEquals(0, w.sink.snapshot().stream().filter(r -> r.type().startsWith("API_")).count(),
                    "TLS refused them before any request existed");
            try (RemoteSessionAuthority wrongRole = h.client("console")) {
                assertEquals(EdgeResult.Status.DENIED, wrongRole.decide(w.request().resource("web:general").build()).status(),
                        "a valid certificate in the wrong role is refused like anyone else");
            }
        }
    }

    @Test
    void theApiUnreachableIsADeny() {
        EdgeFixtures.World w = EdgeFixtures.world();
        try (RemoteSessionAuthority c = RemoteSessionAuthority.create(java.net.URI.create("https://localhost:1"),
                ApiKit.ctx("gateway"), Duration.ofSeconds(2))) {
            assertEquals(EdgeResult.Status.DENIED, c.decide(w.request().build()).status());
            assertEquals(EdgeResult.Status.DENIED, c.open(w.request().build(),
                    dev.dwarpal.crypto.Ed25519.generateKeyPair().getPublic(), Optional.empty()).status());
            assertEquals(2, c.failures());
        }
    }

    @Test
    void garbageFromTheServerIsADeny() throws Exception {
        List<String> answers = List.of("", "{}", "not json", "{\"status\":\"GRANTED\"}", "[1,2]",
                "{\"error\":\"invalid request\"}");
        for (String answer : answers) {
            HttpsServer s = ApiKit.fakeApi("api", ex -> {
                byte[] b = answer.getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(200, b.length == 0 ? -1 : b.length);
                try (OutputStream out = ex.getResponseBody()) {
                    out.write(b);
                }
            });
            try (RemoteSessionAuthority c = RemoteSessionAuthority.create(ApiKit.base(s), ApiKit.ctx("gateway"),
                    Duration.ofSeconds(5))) {
                assertEquals(EdgeResult.Status.DENIED, c.decide(EdgeFixtures.world().request().build()).status(), answer);
            } finally {
                s.stop(0);
            }
        }
        HttpsServer redirect = ApiKit.fakeApi("api", ex -> {
            ex.getResponseHeaders().set("Location", "https://example.com/");
            ex.sendResponseHeaders(307, -1);
            ex.close();
        });
        try (RemoteSessionAuthority c = RemoteSessionAuthority.create(ApiKit.base(redirect), ApiKit.ctx("gateway"),
                Duration.ofSeconds(5))) {
            assertEquals(EdgeResult.Status.DENIED, c.decide(EdgeFixtures.world().request().build()).status(),
                    "redirects are not followed");
        } finally {
            redirect.stop(0);
        }
    }

    @Test
    void fuzzingEveryEndpointNeverBreaksTheServer() throws Exception {
        java.util.Random rnd = new java.util.Random(4);
        try (ApiKit.Harness h = new ApiKit.Harness(ApiSettings.defaults()); ApiKit.Raw pep = h.raw("gateway");
             ApiKit.Raw console = h.raw("console")) {
            String valid = JsonWriter.write(WireFormat.decide(new WireFormat.DecideBody(h.world.request().build())));
            for (ApiServer.Endpoint e : ApiServer.Endpoint.values()) {
                if (e == ApiServer.Endpoint.HEALTH || e == ApiServer.Endpoint.READY) {
                    continue;
                }
                ApiKit.Raw who = e.serves(CallerRole.PEP) ? pep : console;
                for (int i = 0; i < 60; i++) {
                    byte[] b = mutate(valid.getBytes(StandardCharsets.UTF_8), rnd);
                    ApiKit.Reply r = who.post(e.path(), "application/json", b);
                    assertTrue(List.of(200, 400, 413).contains(r.status()), e + " answered " + r.status());
                    assertTrue(r.body().startsWith("{\"error\":\"") || r.status() == 200, r.body());
                    assertTrue(!r.body().contains("Exception") && !r.body().contains("at dev."), r.body());
                }
            }
            assertEquals(0, h.server.internalFailures());
            assertEquals(200, pep.get("/v1/health").status());
        }
    }

    private static final String PUNCTUATION = "{}[]\",:e-0";

    private static byte[] mutate(byte[] in, java.util.Random rnd) {
        byte[] b = in.clone();
        int edits = 1 + rnd.nextInt(6);
        for (int i = 0; i < edits; i++) {
            int at = rnd.nextInt(b.length);
            switch (rnd.nextInt(4)) {
                case 0 -> b[at] = (byte) rnd.nextInt(256);
                case 1 -> b[at] = (byte) PUNCTUATION.charAt(rnd.nextInt(PUNCTUATION.length()));
                case 2 -> b = java.util.Arrays.copyOf(b, at);
                default -> {
                    byte[] longer = new byte[b.length + 1];
                    System.arraycopy(b, 0, longer, 0, at);
                    longer[at] = (byte) rnd.nextInt(128);
                    System.arraycopy(b, at, longer, at + 1, b.length - at);
                    b = longer;
                }
            }
            if (b.length == 0) {
                return b;
            }
        }
        return b;
    }

    @Test
    void aFloodIsAnsweredBusyNotByFallingOver() throws Exception {
        ApiSettings small = ApiSettings.defaults().withThreads(4, 1);
        try (ApiKit.Harness h = new ApiKit.Harness(EdgeFixtures.world(), small, null, null)) {
            List<Integer> statuses = java.util.Collections.synchronizedList(new ArrayList<>());
            List<Thread> threads = new ArrayList<>();
            for (int t = 0; t < 8; t++) {
                Thread th = new Thread(() -> {
                    try (ApiKit.Raw r = h.raw("gateway")) {
                        for (int i = 0; i < 10; i++) {
                            statuses.add(r.get("/v1/health").status());
                        }
                    } catch (IOException | InterruptedException e) {
                        statuses.add(-1);
                    }
                });
                threads.add(th);
                th.start();
            }
            for (Thread th : threads) {
                th.join(30_000);
            }
            assertTrue(statuses.stream().allMatch(s -> s == 200 || s == 503 || s == -1), statuses.toString());
            assertTrue(statuses.contains(200));
            try (ApiKit.Raw r = h.raw("soc")) {
                assertEquals(200, r.get("/v1/health").status(), "fine again once the flood is over");
            }
        }
    }

    private static javax.net.ssl.SSLContext anonymous() throws Exception {
        javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance("PKIX");
        java.security.KeyStore trust = java.security.KeyStore.getInstance("PKCS12");
        try (java.io.InputStream in = java.nio.file.Files.newInputStream(ApiKit.pki().trustStore())) {
            trust.load(in, ApiKit.pki().password());
        }
        tmf.init(trust);
        javax.net.ssl.SSLContext c = javax.net.ssl.SSLContext.getInstance("TLSv1.3");
        c.init(null, tmf.getTrustManagers(), null);
        return c;
    }
}

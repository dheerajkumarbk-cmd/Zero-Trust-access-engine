package dev.dwarpal.lab;

import dev.dwarpal.edge.DevPki;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.soc.Priority;
import dev.dwarpal.soc.RankedAlert;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The lab world on the simulated organisation: it runs the whole script, a stepped run (as the live clock does)
 * reaches the same alerts as one big run, and the SOC API answers analysts over mutual TLS while time moves.
 */
class LabWorldTest {

    private static Path dir;
    private static LabWorld whole;
    private static LabWorld stepped;

    @BeforeAll
    static void build() throws Exception {
        dir = Files.createTempDirectory("dwarpal-lab-test");
        whole = LabWorld.create(LabConfig.defaults(dir.resolve("whole")).withPort(0));
        whole.advanceTo(whole.scriptEnd);
        stepped = LabWorld.create(LabConfig.defaults(dir.resolve("stepped")).withPort(0));
        // the live clock moves in small steps: here 90 simulated minutes at a time
        Instant t = stepped.scriptStart;
        while (!stepped.finished()) {
            t = t.plus(Duration.ofMinutes(90));
            stepped.advanceTo(t);
        }
    }

    @AfterAll
    static void release() {
        whole.close();
        stepped.close();
    }

    private static Set<String> alertKeys(LabWorld w) {
        Set<String> keys = new TreeSet<>();
        for (LabWorld.Raised r : w.raised) {
            keys.add(r.engine() + ":" + r.alert().rule() + ":" + r.alert().entities().stream()
                    .map(e -> e.kind() + "/" + e.id()).sorted().toList());
        }
        return keys;
    }

    @Test
    void theWholeScriptRunsAndTheSocFindsTheAttacksItShould() {
        assertTrue(whole.finished());
        List<RankedAlert> ranked = whole.rankedNow();
        assertTrue(ranked.size() > 50, "the simulated organisation produces a queue worth working: " + ranked.size());
        assertTrue(ranked.stream().anyMatch(r -> r.priority() == Priority.P1 && r.actionable()),
                "a stolen laptop is a P1 that the SOC may act on");
        assertTrue(whole.raised.stream().anyMatch(r -> r.alert().rule().equals("stolen-laptop-access")
                || r.alert().rule().equals("cr-stolen-device")), "the A6 attack is raised");
        assertEquals(720, whole.requestsDecided(), "the 8-day script of the 60-user organisation");
        assertTrue(whole.store.search("dataset = firewall", whole.scriptStart, whole.scriptEnd.plusSeconds(1), 1)
                .matched() > 1_000, "the firewall's lines are searchable");
    }

    @Test
    void aSteppedRunLikeTheLiveClockRaisesTheSameAlertsAsOneBigRun() {
        // rules (parts A and D) are exact: same alerts, same counts, however the chain is read
        assertEquals(countsOf(whole, "A", "D"), countsOf(stepped, "A", "D"));
        // UEBA learns as it reads, so a stepped run can group its anomalies a little differently (an alert that
        // grows 2, 3, 5 in one run may go 2, 4 in the other); both raise about the same people and devices
        assertEquals(alertKeys(whole), alertKeys(stepped));
        assertTrue(Math.abs(whole.rankedNow().size() - stepped.rankedNow().size()) <= 10,
                whole.rankedNow().size() + " against " + stepped.rankedNow().size());
    }

    private static java.util.Map<String, Long> countsOf(LabWorld w, String... engines) {
        Set<String> wanted = Set.of(engines);
        return w.raised.stream().filter(r -> wanted.contains(r.engine())).collect(java.util.stream.Collectors.groupingBy(
                r -> r.engine() + ":" + r.alert().rule() + ":" + r.alert().entities().stream()
                        .map(e -> e.kind() + "/" + e.id()).sorted().toList(), java.util.TreeMap::new,
                java.util.stream.Collectors.counting()));
    }

    @Test
    void theAnalystsReachTheSocApiOverMutualTlsAndNobodyElseDoes() throws Exception {
        HttpClient ana = client(whole.pki, whole.pki, "ana");
        HttpResponse<String> health = get(ana, whole, "/v1/health");
        assertEquals(200, health.statusCode());
        HttpResponse<String> queue = get(ana, whole, "/v1/queue");
        assertEquals(200, queue.statusCode());
        assertTrue(queue.body().contains("P1"), "the queue shows the priorities");
        assertEquals(404, get(ana, whole, "/v1/reports/daily").statusCode(), "reports are for the lead");
        assertEquals(200, get(client(whole.pki, whole.pki, "cleo"), whole, "/v1/reports/daily").statusCode());

        DevPki rogue = DevPki.create(dir.resolve("rogue"), "Some Other CA", List.of(DevPki.Leaf.valid("ana")));
        HttpClient forged = client(rogue, whole.pki, "ana");
        assertThrows(IOException.class, () -> get(forged, whole, "/v1/health"), "a certificate from another CA is refused");

        // the console's own certificate is valid but is no analyst: the SOC API does not know it
        HttpClient console = client(whole.pki, whole.pki, "console");
        assertEquals(403, get(console, whole, "/v1/queue").statusCode());
    }

    @Test
    void theApiAnswersWhileScenarioTimeMovesOnAnotherThread() throws Exception {
        try (LabWorld w = LabWorld.create(LabConfig.defaults(dir.resolve("busy")).withPort(0))) {
            w.warmUp(2);
            AtomicBoolean stop = new AtomicBoolean();
            AtomicInteger bad = new AtomicInteger();
            AtomicInteger calls = new AtomicInteger();
            HttpClient ana = client(w.pki, w.pki, "ana");
            Thread asker = new Thread(() -> {
                while (!stop.get()) {
                    try {
                        for (String p : List.of("/v1/queue", "/v1/risk/top", "/v1/cases", "/v1/metrics")) {
                            int s = get(ana, w, p).statusCode();
                            calls.incrementAndGet();
                            if (s != 200) {
                                bad.incrementAndGet();
                            }
                        }
                    } catch (IOException | InterruptedException e) {
                        bad.incrementAndGet();
                    }
                }
            });
            asker.start();
            Instant t = w.now();
            while (!w.finished()) {
                t = t.plus(Duration.ofMinutes(45));
                w.advanceTo(t);
            }
            stop.set(true);
            asker.join(20_000);
            assertTrue(calls.get() > 20, "the analyst kept asking: " + calls.get());
            assertEquals(0, bad.get(), "no answer failed while the scenario moved");
        }
    }

    @Test
    void anAnalystSignsAVerdictAndTheLabActsOnIt() {
        try (LabWorld w = freshWorld()) {
            w.advanceTo(w.scriptEnd);
            RankedAlert p1 = w.rankedNow().stream().filter(r -> r.priority() == Priority.P1 && r.actionable())
                    .findFirst().orElseThrow();
            var result = w.soar.handle(w.signVerdict("ana", p1.alert().id(), dev.dwarpal.soc.Verdict.Outcome.TRUE_POSITIVE));
            assertTrue(result.status() == dev.dwarpal.response.Playbooks.Status.APPLIED || result.status() == dev.dwarpal.response.Playbooks.Status.AWAITING_SECOND_ANALYST, result.message());
        } catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void theDefaultsAreChecked() {
        assertThrows(IllegalArgumentException.class, () -> LabConfig.defaults(Path.of("x")).withUsers(5));
        assertThrows(IllegalArgumentException.class, () -> LabConfig.defaults(Path.of("x")).withSpeed(0));
        assertThrows(IllegalArgumentException.class, () -> LabConfig.defaults(Path.of("x")).withSpeed(1e9));
        assertThrows(IllegalArgumentException.class, () -> LabConfig.defaults(Path.of("x")).withWarmupDays(99));
        assertFalse(LabWorld.CERTIFICATES.isEmpty());
    }

    private LabWorld freshWorld() throws IOException, InterruptedException {
        return LabWorld.create(LabConfig.defaults(dir.resolve("fresh-" + System.nanoTime())).withPort(0));
    }

    static HttpClient client(DevPki from, DevPki trustOf, String leaf) throws Exception {
        SSLContext c = TlsContexts.create(from.keyStore(leaf), from.password(), trustOf.trustStore(), trustOf.password());
        return HttpClient.newBuilder().sslContext(c).sslParameters(TlsContexts.clientParameters(c))
                .version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(5)).build();
    }

    static HttpResponse<String> get(HttpClient c, LabWorld w, String path) throws IOException, InterruptedException {
        return c.send(HttpRequest.newBuilder(URI.create(w.socApiUrl() + path)).timeout(Duration.ofSeconds(10)).GET().build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }
}

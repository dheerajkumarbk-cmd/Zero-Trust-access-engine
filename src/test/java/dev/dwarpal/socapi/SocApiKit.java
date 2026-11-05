package dev.dwarpal.socapi;

import dev.dwarpal.edge.DevPki;
import dev.dwarpal.edge.TlsContexts;
import dev.dwarpal.soar.SoarWorld;
import dev.dwarpal.soc.ChainedEvent;
import dev.dwarpal.soc.Entity;
import dev.dwarpal.soc.EntityRisk;
import dev.dwarpal.soc.EventSearch;
import dev.dwarpal.soc.SecurityEvent;

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
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A running SOC API over the part F test world, with a development CA (made with the JDK's keytool at run time),
 * and fakes of part D's search and part E's entity risk.
 */
final class SocApiKit implements AutoCloseable {

    private static DevPki pki;
    private static DevPki rogue;

    static synchronized DevPki pki() {
        if (pki == null) {
            try {
                Path dir = Files.createTempDirectory("dwarpal-socapi-pki");
                pki = DevPki.create(dir.resolve("dwarpal"), "Dwarpal Dev CA", List.of(DevPki.Leaf.valid("soc-api"),
                        DevPki.Leaf.valid("ana"), DevPki.Leaf.valid("ben"), DevPki.Leaf.valid("cleo"),
                        DevPki.Leaf.valid("stranger"), DevPki.Leaf.expired("old-ana")));
                rogue = DevPki.create(dir.resolve("rogue"), "Some Other CA", List.of(DevPki.Leaf.valid("ana")));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
        return pki;
    }

    static synchronized DevPki rogue() {
        pki();
        return rogue;
    }

    static SSLContext ctx(DevPki from, String leaf) {
        try {
            return TlsContexts.create(from.keyStore(leaf), from.password(), pki().trustStore(), pki().password());
        } catch (IOException | java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Part D's search, faked: answers with the events it holds, or a problem, or fails. */
    static final class FakeSearch implements EventSearch {
        final List<ChainedEvent> events = new ArrayList<>();
        final AtomicReference<String> problem = new AtomicReference<>();
        final AtomicBoolean down = new AtomicBoolean();
        final AtomicReference<String> lastQuery = new AtomicReference<>();

        @Override
        public Result search(String query, Instant from, Instant to, int limit) {
            EventSearch.check(query, from, to, limit);
            if (down.get()) {
                throw new IllegalStateException("index unavailable");
            }
            lastQuery.set(query);
            if (problem.get() != null) {
                return Result.refused(problem.get());
            }
            List<ChainedEvent> out = events.stream().limit(limit).toList();
            return new Result(out, events.size(), events.size() > limit, Optional.empty());
        }

        void add(long seq, Instant at, Entity... entities) {
            events.add(new ChainedEvent(seq, at, new SecurityEvent("ev-" + seq, at, "endpoint",
                    SecurityEvent.Category.PROCESS, "process.start", SecurityEvent.EventOutcome.SUCCESS,
                    SecurityEvent.Provenance.SIGNED_SENSOR, List.of(entities), Map.of("process", "powershell.exe"))));
        }
    }

    /** Part E's entity risk, faked: a fixed score per entity id. */
    static final class FakeRisk implements EntityRisk {
        final java.util.Map<Entity, Double> scores = new java.util.LinkedHashMap<>();
        final AtomicBoolean down = new AtomicBoolean();

        @Override
        public RiskView view(Entity entity, Instant now) {
            if (down.get()) {
                throw new IllegalStateException("risk unavailable");
            }
            double s = scores.getOrDefault(entity, 0.0);
            if (s == 0) {
                return RiskView.none(entity, now);
            }
            return new RiskView(entity, s, Level.of(s), now, List.of(new Contribution("alert:honeytoken-touched",
                    2.3, now, List.of(1L), "confirmed alert")));
        }

        @Override
        public List<RiskView> top(int n, Instant now) {
            if (down.get()) {
                throw new IllegalStateException("risk unavailable");
            }
            return scores.keySet().stream().map(e -> view(e, now)).limit(n).toList();
        }
    }

    record Reply(int status, String body) {
    }

    final SoarWorld world;
    final FakeSearch search = new FakeSearch();
    final FakeRisk risk = new FakeRisk();
    final SocApiServer server;
    final URI base;

    SocApiKit() {
        this(new SoarWorld(), SocApiSettings.defaults());
    }

    SocApiKit(SoarWorld world, SocApiSettings settings) {
        this.world = world;
        try {
            server = SocApiServer.builder(world.audit, world.soar).tls(ctx(pki(), "soc-api")).clock(world.clock)
                    .callers(List.of(SocCaller.component("ana", SoarWorld.ANA), SocCaller.component("ben", SoarWorld.BEN),
                            SocCaller.component("cleo", SoarWorld.LEAD)))
                    .settings(settings).search(search).risk(risk)
                    .reports((name, now) -> name.equals("daily") ? Optional.of("SOC daily report (simulated data)")
                            : name.equals("huge") ? Optional.of("x".repeat(ReportSource.MAX_CHARS + 1))
                            : name.equals("broken") ? failing() : Optional.empty())
                    .build().start();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        base = URI.create("https://localhost:" + server.port());
    }

    private static Optional<String> failing() {
        throw new IllegalStateException("report store down");
    }

    Client as(String leaf) {
        return new Client(ctx(pki(), leaf));
    }

    Client rogue(String leaf) {
        return new Client(ctx(rogue(), leaf));
    }

    @Override
    public void close() {
        server.close();
    }

    final class Client implements AutoCloseable {
        private final HttpClient http;

        Client(SSLContext c) {
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

        Reply post(String path, String contentType, byte[] body) throws IOException, InterruptedException {
            return send(HttpRequest.newBuilder(base.resolve(path)).header("Content-Type", contentType)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body)));
        }

        Reply method(String method, String path) throws IOException, InterruptedException {
            return send(HttpRequest.newBuilder(base.resolve(path)).header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString("{}")));
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
}

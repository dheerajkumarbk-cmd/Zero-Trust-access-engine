package dev.dwarpal.integration;

import dev.dwarpal.api.ApiServer;
import dev.dwarpal.api.Caller;
import dev.dwarpal.api.CallerRole;
import dev.dwarpal.api.RemoteSessionAuthority;
import dev.dwarpal.edge.DevPki;
import dev.dwarpal.edge.EdgeFixtures;
import dev.dwarpal.edge.TlsContexts;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Layer 4 as deployed: the engine, PA and PAM behind the API over mutual TLS 1.3, and every enforcement
 * point reaching them only through a {@link RemoteSessionAuthority} pinned to the API, with its own
 * certificate and its own resource scope.
 *
 * <pre>
 *   gateway  PEP  wiki, vault      (ZTNA, part B)
 *   swg      PEP  web:*            (web gateway, part C)
 *   casb     PEP  drive            (SaaS data guard, part C)
 *   soc      SOC                   (revocation)
 * </pre>
 *
 * The world is {@link EdgeFixtures#strictWorld()}: the PA opens sessions only on verified, single-use MFA.
 */
public final class E2eWorld implements AutoCloseable {

    public static final List<Caller> CALLERS = List.of(
            Caller.pepComponent("gateway", "wiki", "vault"),
            Caller.pepComponent("swg", "web:*"),
            Caller.pepComponent("casb", "drive"),
            Caller.component("soc", CallerRole.SOC));

    private static DevPki pki;

    public final EdgeFixtures.World w = EdgeFixtures.strictWorld();
    public final ApiServer api;
    public final URI base;
    private final List<AutoCloseable> open = new ArrayList<>();

    public E2eWorld() {
        try {
            api = ApiServer.builder(w.audit, w.pam).tls(ctx("api")).authority(w.authority)
                    .administrator(w.administrator).clock(w.clock).callers(CALLERS).build().start();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        base = URI.create("https://localhost:" + api.port());
    }

    /** One development CA for the whole deployment; created once per test run, never committed. */
    public static synchronized DevPki pki() {
        if (pki == null) {
            try {
                Path dir = Files.createTempDirectory("dwarpal-e2e-pki");
                pki = DevPki.create(dir.resolve("dwarpal"), "Dwarpal Dev CA", List.of(DevPki.Leaf.valid("api"),
                        DevPki.Leaf.valid("gateway"), DevPki.Leaf.valid("swg"), DevPki.Leaf.valid("casb"),
                        DevPki.Leaf.valid("soc")));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
        return pki;
    }

    public static SSLContext ctx(String leaf) {
        try {
            return TlsContexts.create(pki().keyStore(leaf), pki().password(), pki().trustStore(), pki().password());
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** How the component {@code leaf} reaches the engine: its certificate, the CA, the API pinned. */
    public RemoteSessionAuthority remote(String leaf) {
        try {
            RemoteSessionAuthority r = RemoteSessionAuthority.connect(base, pki().keyStore(leaf), pki().password(),
                    pki().trustStore(), pki().password(), TlsContexts.component("api"), Duration.ofSeconds(5));
            open.add(r);
            return r;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Closes {@code c} with this world. */
    public <T extends AutoCloseable> T keep(T c) {
        open.add(c);
        return c;
    }

    @Override
    public void close() {
        for (AutoCloseable c : open.reversed()) {
            try {
                c.close();
            } catch (Exception ignored) {
                // closing a test world; the next one starts clean
            }
        }
        api.close();
    }
}

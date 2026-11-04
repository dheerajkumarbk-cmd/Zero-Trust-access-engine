package dev.dwarpal.swg;

import dev.dwarpal.edge.EdgeFixtures;
import dev.dwarpal.edge.EdgeRequest;
import dev.dwarpal.edge.SessionAuthority;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/** The part C test world on top of the shared {@link EdgeFixtures}: lists, filter, access, Alice's identity. */
final class SwgWorld {

    final EdgeFixtures.World world = EdgeFixtures.world();
    final AtomicReference<DomainList> blocklist = new AtomicReference<>(sampleBlocklist());
    final AtomicReference<CategoryMap> categories = new AtomicReference<>(sampleCategories());

    static DomainList sampleBlocklist() {
        try (InputStream in = Objects.requireNonNull(SwgWorld.class.getResourceAsStream("sample-blocklist.hosts"))) {
            return DomainList.parse(new InputStreamReader(in, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static CategoryMap sampleCategories() {
        try (InputStream in = Objects.requireNonNull(SwgWorld.class.getResourceAsStream("sample-categories.txt"))) {
            return CategoryMap.parse(new InputStreamReader(in, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** news and search are general web; gambling is malicious; everything else uncategorised. */
    static WebPolicy.Builder policy() {
        return WebPolicy.builder().category("news", "web:general").category("search", "web:general")
                .category("gambling", WebPolicy.MALICIOUS);
    }

    WebFilter filter(WebPolicy p) {
        return new WebFilter(p, blocklist::get, categories::get);
    }

    WebAccess access(WebPolicy p) {
        return access(p, world.authority);
    }

    WebAccess access(WebPolicy p, SessionAuthority authority) {
        return new WebAccess(filter(p), authority, "mumbai", world.clock);
    }

    /** Alice on her managed laptop with agent-signed posture. */
    WebIdentity alice() {
        EdgeRequest r = world.request().resource("web:general").build();
        return new WebIdentity(r.subjectId(), r.deviceId(), r.claimedPosture(), r.evidence(), r.network());
    }

    WebIdentity identity(String subject, String device) {
        EdgeRequest r = world.request().subject(subject).device(device).resource("web:general").build();
        return new WebIdentity(r.subjectId(), r.deviceId(), r.claimedPosture(), r.evidence(), r.network());
    }

    IdentityResolver loopbackIsAlice() {
        return IdentityResolver.fixed(Map.of(InetAddress.getLoopbackAddress(), alice()));
    }

    /** Every name resolves to loopback, where the test servers listen. */
    static HostResolver allLoopback() {
        return host -> List.of(InetAddress.getLoopbackAddress());
    }

    long decisions() {
        return world.audited("ACCESS_DECISION");
    }
}

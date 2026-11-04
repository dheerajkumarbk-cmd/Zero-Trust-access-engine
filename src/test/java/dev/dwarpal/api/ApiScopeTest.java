package dev.dwarpal.api;

import dev.dwarpal.crypto.Ed25519;
import dev.dwarpal.edge.EdgeGrant;
import dev.dwarpal.edge.EdgeResult;
import dev.dwarpal.edge.WireFormat;
import dev.dwarpal.wire.JsonWriter;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration request R7: each enforcement point asks only about the resources it fronts. Before this,
 * a compromised web gateway certificate could open wiki sessions and spend wiki sessions it captured.
 */
class ApiScopeTest {

    @Test
    void theWebGatewayCannotDecideOpenOrUseSessionsForTheWiki() throws Exception {
        try (ApiKit.Harness h = new ApiKit.Harness(ApiSettings.defaults());
             RemoteSessionAuthority gateway = h.client("gateway");
             RemoteSessionAuthority swg = h.client("swg");
             ApiKit.Raw raw = h.raw("swg")) {
            assertTrue(swg.decide(h.world.request().resource("web:general").build()).status().allowed(),
                    "in scope: web:*");
            String wiki = JsonWriter.write(WireFormat.decide(new WireFormat.DecideBody(h.world.request().build())));
            assertEquals(403, raw.post("/v1/decisions", wiki).status(), "the wiki is not the web gateway's");

            KeyPair key = Ed25519.generateKeyPair();
            assertEquals(EdgeResult.Status.DENIED, h.open(swg, key, h.world.request().build()).status(),
                    "no wiki login through the web gateway");

            EdgeGrant grant = h.open(gateway, key, h.world.request().build()).grant().orElseThrow();
            assertEquals(EdgeResult.Status.DENIED, h.use(swg, key, grant, h.world.request().build()).status(),
                    "a captured wiki session cannot be spent through the web gateway");
            assertTrue(h.use(gateway, key, grant, h.world.request().build()).status().allowed(),
                    "and the refusal did not touch the session itself");
            assertTrue(h.world.sink.snapshot().stream().anyMatch(r -> r.type().equals("API_REFUSED")
                    && r.payloadJson().contains("outside the caller's scope")));
        }
    }

    @Test
    void scopesAreRequiredForEnforcementPointsAndOnlyForThem() {
        assertThrows(IllegalArgumentException.class, () -> Caller.component("gateway", CallerRole.PEP),
                "an enforcement point without a scope is a configuration error, not 'everything'");
        assertThrows(IllegalArgumentException.class,
                () -> new Caller("soc", "CN=soc", CallerRole.SOC, List.of("wiki")));
        assertThrows(IllegalArgumentException.class, () -> Caller.pepComponent("swg", "web:*", "bad id!"));
        assertThrows(IllegalArgumentException.class, () -> Caller.pepComponent("swg", "**"));
        String[] many = new String[Caller.MAX_RESOURCES + 1];
        java.util.Arrays.fill(many, "wiki");
        assertThrows(IllegalArgumentException.class, () -> Caller.pepComponent("swg", many));

        Caller swg = Caller.pepComponent("swg", "web:*", "saas:crm");
        assertTrue(swg.mayAsk("web:general"));
        assertTrue(swg.mayAsk("saas:crm"));
        assertFalse(swg.mayAsk("saas:crm2"), "an exact entry is not a prefix");
        assertFalse(swg.mayAsk("wiki"));
        assertTrue(Caller.pepComponent("gateway", "*").mayAsk("anything"));
    }
}

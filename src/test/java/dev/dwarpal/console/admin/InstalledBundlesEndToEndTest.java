package dev.dwarpal.console.admin;

import dev.dwarpal.analytics.RecordedRequest;
import dev.dwarpal.console.ConsoleModule.Principal;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.console.lab.FakeRoutes;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.lab.InstalledBundles;
import dev.dwarpal.lab.LabConfig;
import dev.dwarpal.lab.LabWorld;
import dev.dwarpal.lab.scenarios.LabSession;
import dev.dwarpal.risk.SignalSnapshot;
import dev.dwarpal.wire.JsonValue;
import dev.dwarpal.wire.JsonWriter;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static dev.dwarpal.console.lab.FakeRoutes.json;
import static dev.dwarpal.console.lab.FakeRoutes.text;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** An installed policy and playbook set survive a restart and a reset; a changed saved file stops the lab. */
class InstalledBundlesEndToEndTest {

    private static final Principal ADA = new Principal("ada", Set.of(Role.ADMIN), true);
    private static final Principal RAY = new Principal("ray", Set.of(Role.ADMIN), true);
    private static final String LOCKDOWN = "version: \"lockdown-9\"\nalgorithm: DENY_OVERRIDES\ndefault: DENY\npolicies: []\n";

    private static LabConfig config(Path dir) {
        return LabConfig.defaults(dir).withPort(0).withUsers(30).withWarmupDays(1);
    }

    private static String body(String yaml) {
        return "{\"yaml\":" + JsonWriter.write(JsonValue.str(yaml)) + "}";
    }

    private static void install(FakeRoutes routes, String proposePath, String yaml) {
        String id = text(json(routes.call("POST", proposePath, ADA, body(yaml))).get("id").orElseThrow());
        assertEquals(200, routes.call("POST", "proposals/" + id + "/approve", ADA, "").status());
        assertEquals(200, routes.call("POST", "proposals/" + id + "/approve", RAY, "").status());
        JsonValue.JObject done = json(routes.call("POST", "proposals/" + id + "/install", ADA, ""));
        assertEquals(JsonValue.bool(true), done.get("installed").orElseThrow(), done.toString());
    }

    private static Outcome decide(LabWorld w) {
        RecordedRequest any = w.recorder.snapshot().getFirst();
        return w.policies.decide(any.request(), SignalSnapshot.empty()).outcome();
    }

    @Test
    void installedBundlesSurviveARestartAndAResetAndATamperedFileStopsTheLab() throws Exception {
        Path dir = Files.createTempDirectory("dwarpal-keep");
        String playbooks;
        Outcome before;
        try (LabSession session = LabSession.open(config(dir))) {
            session.runner().pause();
            before = decide(session.world());
            playbooks = new LabAdminServices(session).activePlaybookYaml().replaceFirst("version: \"", "version: \"kept-");
            FakeRoutes routes = FakeRoutes.of(new AdminModule(new LabAdminServices(session)));
            install(routes, "policy/propose", LOCKDOWN);
            install(routes, "playbooks/propose", playbooks);
            assertEquals(1, session.world().policies.currentSequence());
            assertEquals(1, session.world().playbooks.sequence());
        }
        assertNotEquals(Outcome.DENY, before, "the shipped policy does not deny this request");

        // a restart: a new world on the same folder
        try (LabSession session = LabSession.open(config(dir))) {
            session.runner().pause();
            LabWorld w = session.world();
            assertEquals(1, w.policies.currentSequence());
            assertEquals("lockdown-9", w.policies.currentEngine().policySet().version());
            assertEquals(Outcome.DENY, decide(w), "the new policy's outcome");
            assertEquals(1, w.playbooks.sequence());
            assertEquals(2, w.notices.size(), w.notices.toString());
            assertTrue(w.notices.getFirst().contains("approved by ada, ray"), w.notices.toString());
            assertEquals(playbooks, new LabAdminServices(session).activePlaybookYaml());
            assertTrue(w.org.sink.snapshot().stream().anyMatch(r -> r.type().equals("POLICY_RESTORED")));

            // a reset keeps them too
            session.reset();
            LabWorld after = session.world();
            assertEquals(1, after.policies.currentSequence());
            assertEquals(Outcome.DENY, decide(after));
            assertEquals(1, after.playbooks.sequence());
            assertEquals(playbooks, new LabAdminServices(session).activePlaybookYaml());
        }

        // a changed saved file: the lab does not start, and says so plainly
        Path file = new InstalledBundles(dir).file(InstalledBundles.Kind.POLICY);
        byte[] raw = Files.readAllBytes(file);
        raw[raw.length / 2] ^= 0x01;
        Files.write(file, raw);
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> LabSession.open(config(dir)));
        assertTrue(e.getMessage().contains("cannot start"), e.getMessage());
        assertTrue(!e.getMessage().contains("lockdown-9") && !e.getMessage().contains("DENY_OVERRIDES"), "no file content");
        // the folder lock was released, so putting the file back lets the lab start again
        raw[raw.length / 2] ^= 0x01;
        Files.write(file, raw);
        try (LabSession again = LabSession.open(config(dir))) {
            assertEquals(1, again.world().policies.currentSequence());
        }
    }
}

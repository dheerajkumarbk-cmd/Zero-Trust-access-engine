package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Resp;
import dev.dwarpal.console.ConsoleFixture.Sess;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The monitoring page: each administrator sees what the OTHER administrator did, a lead sees the limited vault log (who, when,
 * on whom, never the secret), and nobody can change a record through it.
 */
class MonitorEndToEndTest {

    @TempDir
    Path dir;

    private ConsoleTrail trail;
    private ConsoleFixture f;

    @BeforeEach
    void start() throws Exception {
        trail = ConsoleTrail.open(dir, Clock.systemUTC());
        f = ConsoleFixture.start(b -> b.trail(trail).module(new MonitorModule(() -> Set.of("dana", "spector"))),
                ConsoleSettings.defaults().fastHashing());
        trail.log().append("ACCESS_ROLE_ADDED", "spector", Clock.systemUTC().instant(),
                Map.of("person", "uma", "before", "USER", "after", "USER,ADMIN", "elevation", "el-1", "session", "hidden-tag"));
        trail.log().append("CONSOLE_VIEW", "spector", Clock.systemUTC().instant(), Map.of("route", "lab/status"));
        trail.log().append("ELEVATION_STARTED", "dana", Clock.systemUTC().instant(), Map.of("reason", "agreeing to the cover", "elevation", "el-2"));
        trail.log().append("VAULT_REVEAL", "dana", Clock.systemUTC().instant(),
                Map.of("action", "reveal", "target", "uma", "secret", "hunter2-the-secret", "reason", "locked out"));
    }

    @AfterEach
    void stop() throws Exception {
        f.close();
        trail.close();
    }

    @Test
    void anAdministratorSeesTheOtherAdministratorsActionsAndNotTheirOwn() throws Exception {
        Resp r = f.get("/console/api/monitor/admins", f.login("dana"));
        assertEquals(200, r.status());
        assertTrue(r.body().contains("ACCESS_ROLE_ADDED") && r.body().contains("spector") && r.body().contains("USER,ADMIN"), r.body());
        assertTrue(r.body().contains("elevation: el-1"), "the elevation id is shown with the action");
        assertFalse(r.body().contains("hidden-tag"), "housekeeping fields are left out");
        assertFalse(r.body().contains("lab/status"), "plain page views are not actions");
        assertFalse(r.body().contains("ELEVATION_STARTED"), "dana's own action is not 'the other administrator's'");
        Resp back = f.get("/console/api/monitor/admins", f.login("spector"));
        assertTrue(back.body().contains("ELEVATION_STARTED") && back.body().contains("agreeing to the cover"), back.body());
        assertFalse(back.body().contains("ACCESS_ROLE_ADDED"));
    }

    @Test
    void theOtherAdministratorSeesAVaultActionButNeverItsSecretOrReasonAndTheLeadSeesOnlyWhoWhenOnWhom() throws Exception {
        Resp spector = f.get("/console/api/monitor/admins", f.login("spector"));
        assertTrue(spector.body().contains("VAULT_REVEAL") && spector.body().contains("action: reveal; target: uma"), spector.body());
        assertFalse(spector.body().contains("hunter2") || spector.body().contains("locked out"), spector.body());
        Resp vault = f.get("/console/api/monitor/vault", f.login("cleo"));
        assertEquals(200, vault.status());
        assertTrue(vault.body().contains("\"who\":\"dana\"") && vault.body().contains("\"action\":\"reveal\"")
                && vault.body().contains("\"target\":\"uma\""), vault.body());
        assertFalse(vault.body().contains("hunter2") || vault.body().contains("locked out"), "never the secret, never the reason");
        assertEquals(404, f.get("/console/api/monitor/vault", f.login("dana")).status(), "an administrator is not a lead");
        assertEquals(404, f.get("/console/api/monitor/admins", f.login("cleo")).status(), "a lead is not an administrator");
    }

    @Test
    void otherPeopleDoNotGetThePageAndThereIsNoWayToChangeARecord() throws Exception {
        Sess ana = f.login("ana");
        assertEquals(403, f.get("/console/api/monitor/me", ana).status());
        assertEquals(403, f.get("/console/api/monitor/admins", ana).status());
        assertEquals(403, f.get("/console/api/monitor/vault", ana).status());
        assertEquals(403, f.get("/console/api/monitor/team", ana).status());
        Sess dana = f.login("dana");
        for (String path : new String[]{"/console/api/monitor/admins", "/console/api/monitor/vault", "/console/api/monitor/team", "/console/api/monitor/me"}) {
            assertTrue(f.post(path, dana, "{}").status() >= 400, path);
        }
    }
}

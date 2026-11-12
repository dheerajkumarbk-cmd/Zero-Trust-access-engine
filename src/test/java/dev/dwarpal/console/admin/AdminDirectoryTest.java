package dev.dwarpal.console.admin;

import dev.dwarpal.console.ConsoleModule.Principal;
import dev.dwarpal.console.ConsoleModule.Response;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.console.lab.FakeRoutes;
import dev.dwarpal.directory.DirectoryPerson;
import dev.dwarpal.directory.MemoryDirectory;
import dev.dwarpal.wire.JsonValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static dev.dwarpal.console.lab.FakeRoutes.json;
import static dev.dwarpal.console.lab.FakeRoutes.text;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The Directory page's one call: read-only, for the administrator only, and never a way into the database. */
class AdminDirectoryTest {

    private static final Principal ADMIN = new Principal("dana", Set.of(Role.ADMIN), true);

    private AdminFixture fx;
    private FakeRoutes routes;

    @BeforeEach
    void build() {
        fx = new AdminFixture();
        routes = FakeRoutes.of(new AdminModule(fx));
    }

    private static DirectoryPerson person(String id, DirectoryPerson.Status status, String... roles) {
        return new DirectoryPerson(id, "Name of " + id, "SOC", "Analyst", status, DirectoryPerson.Source.SEED,
                Instant.parse("2026-11-08T10:00:00Z"), Set.of(roles));
    }

    @Test
    void theAdministratorSeesEveryoneWithCountsAndTheDatabaseVersion() {
        MemoryDirectory directory = new MemoryDirectory();
        directory.addIfAbsent(person("ana", DirectoryPerson.Status.ACTIVE, "ANALYST"));
        directory.addIfAbsent(person("ben", DirectoryPerson.Status.DISABLED, "ANALYST"));
        fx.people = directory;
        Response r = routes.call("GET", "directory", ADMIN, "");
        assertEquals(200, r.status(), r.body());
        JsonValue.JObject o = json(r);
        assertEquals(JsonValue.bool(true), o.get("available").orElseThrow());
        JsonValue.JObject counts = (JsonValue.JObject) o.get("counts").orElseThrow();
        assertEquals(2L, ((JsonValue.JNumber) counts.get("people").orElseThrow()).asLong());
        assertEquals(1L, ((JsonValue.JNumber) counts.get("active").orElseThrow()).asLong());
        assertEquals(1L, ((JsonValue.JNumber) counts.get("disabled").orElseThrow()).asLong());
        JsonValue.JArray people = (JsonValue.JArray) o.get("people").orElseThrow();
        assertEquals(2, people.size());
        assertEquals("ana", text(((JsonValue.JObject) people.get(0)).get("id").orElseThrow()));
        assertTrue(text(o.get("server").orElseThrow()).startsWith("PostgreSQL"));
    }

    @Test
    void theAnswerHoldsNoAddressNoUserNameAndNoPassword() {
        fx.people = new MemoryDirectory();
        String body = routes.call("GET", "directory", ADMIN, "").body().toLowerCase(java.util.Locale.ROOT);
        for (String word : List.of("jdbc", "localhost", "password", "dwarpal_app", "dwarpal_migrator", "5432")) {
            assertFalse(body.contains(word), word);
        }
    }

    @Test
    void withoutADatabaseThePageSaysSoInsteadOfFailing() {
        Response r = routes.call("GET", "directory", ADMIN, "");
        assertEquals(200, r.status());
        assertEquals(JsonValue.bool(false), json(r).get("available").orElseThrow());
    }

    @Test
    void nobodyButAnAdministratorMayReadItAndThereIsNoWriteRoute() {
        fx.people = new MemoryDirectory();
        assertEquals(Role.ADMIN, routes.route("GET", "directory").minimum());
        for (Principal who : List.of(new Principal("ana", Set.of(Role.ANALYST), true), new Principal("cleo", Set.of(Role.LEAD, Role.ANALYST), true),
                new Principal("uma", Set.of(Role.USER), true), new Principal("hana", Set.of(Role.HR), true))) {
            assertEquals(403, routes.call("GET", "directory", who, "").status(), who.id());
        }
        assertTrue(routes.all().stream().filter(r -> r.pattern().equals("directory")).allMatch(r -> r.method().equals("GET")),
                "the directory has no write route");
    }
}

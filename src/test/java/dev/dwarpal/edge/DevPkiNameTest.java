package dev.dwarpal.edge;

import dev.dwarpal.console.ConsoleModule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Names that reach the JDK's keytool are checked first; the console contract's records keep their own copies. */
class DevPkiNameTest {

    @TempDir
    Path dir;

    @Test
    void namesThatCouldBecomeAKeytoolOptionOrAPathAreRefusedBeforeAnythingRuns() {
        for (String bad : List.of("-genkeypair", "a/b", "..", "a\\b", "x;y", "name with space", "a\nb", "x=y", "", "$(id)",
                "a".repeat(80))) {
            assertThrows(IllegalArgumentException.class,
                    () -> DevPki.create(dir.resolve("p"), "Lab CA", List.of(DevPki.Leaf.valid(bad))), bad);
        }
        assertThrows(IllegalArgumentException.class,
                () -> DevPki.create(dir.resolve("q"), "-ext x", List.of(DevPki.Leaf.valid("ok"))));
        assertThrows(IllegalArgumentException.class,
                () -> DevPki.create(dir.resolve("r"), "CA,O=evil", List.of(DevPki.Leaf.valid("ok"))));
    }

    @Test
    void aConsoleRequestKeepsAnImmutableCopyOfItsQuery() {
        java.util.HashMap<String, String> query = new java.util.HashMap<>(Map.of("a", "1"));
        ConsoleModule.Request r = new ConsoleModule.Request(
                new ConsoleModule.Principal("ana", Set.of(ConsoleModule.Role.ANALYST), false), "GET", "/x", query, "");
        query.put("b", "2");
        assertEquals(Map.of("a", "1"), r.query());
        assertThrows(UnsupportedOperationException.class, () -> r.query().put("c", "3"));
        assertTrue(r.who().has(ConsoleModule.Role.ANALYST));
        assertEquals(403, ConsoleModule.Response.error(403, "no \"way\"").status());
    }
}

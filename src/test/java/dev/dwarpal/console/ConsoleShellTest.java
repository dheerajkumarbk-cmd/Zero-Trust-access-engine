package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleFixture.Resp;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The real console files (not a fixture) through the real server: every file is served and every import resolves. */
class ConsoleShellTest {

    private static final Path ROOT = Path.of("src/main/resources/console");
    private static ConsoleFixture f;

    @BeforeAll
    static void start() throws Exception {
        f = ConsoleFixture.start(b -> b.staticRoot("console"), ConsoleSettings.defaults().fastHashing());
    }

    @AfterAll
    static void stop() {
        f.close();
    }

    private static List<Path> served() throws IOException {
        try (Stream<Path> s = Files.walk(ROOT)) {
            return s.filter(Files::isRegularFile).filter(p -> !ROOT.relativize(p).toString().replace('\\', '/').startsWith("modules/"))
                    .sorted().toList();
        }
    }

    @Test
    void theShellPageLoadsOnlyItsOwnScriptAndStyle() throws Exception {
        Resp r = f.get("/", null);
        assertEquals(200, r.status());
        assertTrue(r.body().contains("<dw-app>") && r.body().contains("src=\"/console/shell.js\"") && r.body().contains("href=\"/console/style.css\""));
        assertTrue(r.body().contains("type=\"module\""));
        assertEquals("text/html; charset=utf-8", r.header("Content-Type"));
    }

    @Test
    void everyConsoleFileIsServedWithItsType() throws Exception {
        List<String> missing = new ArrayList<>();
        for (Path p : served()) {
            String rel = ROOT.relativize(p).toString().replace('\\', '/');
            Resp r = f.get("/console/" + rel, null);
            if (r.status() != 200) {
                missing.add(rel + " -> " + r.status());
            } else if (rel.endsWith(".js")) {
                assertEquals("text/javascript; charset=utf-8", r.header("Content-Type"), rel);
            }
        }
        assertEquals(List.of(), missing);
    }

    @Test
    void everyRelativeImportPointsAtAFileThatExists() throws Exception {
        Pattern imp = Pattern.compile("(?:from|import)\\s*['\"](\\.{1,2}/[^'\"]+)['\"]");
        List<String> broken = new ArrayList<>();
        for (Path p : served()) {
            if (!p.toString().endsWith(".js")) {
                continue;
            }
            Matcher m = imp.matcher(Files.readString(p, StandardCharsets.UTF_8));
            while (m.find()) {
                if (!Files.isRegularFile(p.getParent().resolve(m.group(1)).normalize())) {
                    broken.add(ROOT.relativize(p) + " imports " + m.group(1));
                }
            }
        }
        assertEquals(List.of(), broken);
    }

    @Test
    void theNavigationNamesOnlyViewsThatExist() throws Exception {
        String shell = Files.readString(ROOT.resolve("shell.js"), StandardCharsets.UTF_8);
        for (String[] view : ConsoleRoutes.BUILT_IN) {
            assertTrue(shell.contains(view[0] + ": 'dw-"), "the shell routes the built-in view " + view[0]);
        }
        for (Path p : served()) {
            String rel = ROOT.relativize(p).toString().replace('\\', '/');
            if (rel.startsWith("views/") && !rel.equals("views/login.js") && !rel.equals("views/statusbar.js")) {
                assertTrue(shell.contains("./" + rel), rel + " is imported by the shell");
            }
        }
    }
}

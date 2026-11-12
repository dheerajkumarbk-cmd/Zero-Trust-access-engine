package dev.dwarpal.console;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * One script that does not parse leaves the whole console page blank, and nothing in the Java build used to notice (a stray
 * apostrophe in a glossary text did exactly that). This runs the real parser of Node.js over every console script, as a
 * module, the way the browser loads it. It needs Node.js on the machine that builds, and says so when it is skipped.
 */
class ConsoleScriptsParseTest {

    private static final Path ROOT = Path.of("src/main/resources/console");

    private static List<Path> scripts() throws IOException {
        try (Stream<Path> s = Files.walk(ROOT)) {
            return s.filter(Files::isRegularFile).filter(p -> p.getFileName().toString().endsWith(".js")).sorted().toList();
        }
    }

    private static boolean nodeAvailable() {
        try {
            Process p = new ProcessBuilder("node", "--version").redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor(20, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    @Test
    void thereAreScriptsToCheck() throws IOException {
        assertFalse(scripts().isEmpty());
    }

    @Test
    void everyScriptParsesAsAModuleWhenNodeIsInstalled() throws Exception {
        Assumptions.assumeTrue(nodeAvailable(), "Node.js is not installed here, so the console scripts were not parsed");
        List<String> hits = new ArrayList<>();
        for (Path f : scripts()) {
            Process p = new ProcessBuilder("node", "--input-type=module", "--check").redirectInput(f.toFile())
                    .redirectErrorStream(true).start();
            String said = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(p.waitFor(30, TimeUnit.SECONDS), "node did not finish on " + f);
            if (p.exitValue() != 0) {
                hits.add(ROOT.relativize(f) + ": " + said.lines().limit(3).reduce("", (a, b) -> a + " " + b));
            }
        }
        assertEquals(List.of(), hits);
    }
}

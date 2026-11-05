package dev.dwarpal.lab.scenarios;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Markdown guide under docs/layer-6/guide is generated from the same data as the console pages. Run with
 * {@code -Dguide.regen=true} to rewrite the files after changing the walkthroughs; otherwise a stale file fails.
 */
class GuideDocsTest {

    private static final Path DIR = Path.of("docs/layer-6/guide");

    private static String norm(String s) {
        return s.replace("\r\n", "\n");
    }

    @Test
    void theMarkdownFilesAreTheGeneratedOnes() throws IOException {
        boolean regen = Boolean.getBoolean("guide.regen");
        if (regen) {
            Files.createDirectories(DIR);
            Files.writeString(DIR.resolve("README.md"), Walkthroughs.index(), StandardCharsets.UTF_8);
        }
        assertEquals(norm(Walkthroughs.index()), norm(Files.readString(DIR.resolve("README.md"))));
        for (Walkthroughs.Walkthrough w : Walkthroughs.all()) {
            Path f = DIR.resolve(w.scenario() + ".md");
            if (regen) {
                Files.writeString(f, Walkthroughs.markdown(w), StandardCharsets.UTF_8);
            }
            assertEquals(norm(Walkthroughs.markdown(w)), norm(Files.readString(f)), f + " is stale; run with -Dguide.regen=true");
        }
    }

    @Test
    void everyScenarioHasAWalkthroughWithEveryPartTheTaskAsks() {
        assertEquals(ScenarioCatalog.all().size(), Walkthroughs.all().size());
        for (Scenario s : ScenarioCatalog.all()) {
            Walkthroughs.Walkthrough w = Walkthroughs.byScenario(s.id()).orElseThrow();
            assertTrue(w.steps().size() >= 3, s.id() + ": a path through the console");
            assertFalse(w.commercial().isEmpty(), s.id() + ": what it looks like in a commercial product");
            assertFalse(w.notice().isEmpty(), s.id() + ": what to notice");
            assertEquals(s.kind() == Scenario.Kind.ATTACK, !w.mitre().isEmpty(),
                    s.id() + ": attacks name a technique, look-alikes and baselines none");
            assertFalse(s.attacker().isBlank());
            assertFalse(s.defender().isBlank());
            assertTrue(Walkthroughs.markdown(w).contains("Your path through the console"));
        }
    }

    @Test
    void theTechniquesNamedAreOnesTheLabKnows() {
        for (Scenario s : ScenarioCatalog.all()) {
            for (String t : s.techniques()) {
                String id = t.split(" ")[0];
                assertTrue(dev.dwarpal.soc.Techniques.byId(id).isPresent(), s.id() + ": " + id);
            }
        }
    }
}

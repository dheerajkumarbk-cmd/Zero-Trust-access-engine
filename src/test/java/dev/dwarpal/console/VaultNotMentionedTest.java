package dev.dwarpal.console;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The vault is mentioned nowhere a non-administrator can read: not in the Guide, not in the Glossary, not in any menu text or
 * page of the shell. Only the vault's own pages and the lead's limited log (a decision) say the word.
 */
class VaultNotMentionedTest {

    private static final List<Path> ROOTS = List.of(Path.of("src/main/resources/console"), Path.of("src/main/java/dev/dwarpal/lab"),
            Path.of("src/main/java/dev/dwarpal/console/lab"));
    private static final List<String> ALLOWED = List.of("modules/vault/", "modules/monitor/");

    @Test
    void onlyTheVaultsOwnPagesAndTheLeadsLogUseTheWord() throws IOException {
        List<String> hits = new ArrayList<>();
        for (Path root : ROOTS) {
            try (Stream<Path> s = Files.walk(root)) {
                for (Path f : s.filter(Files::isRegularFile).toList()) {
                    String name = f.toString().replace(File.separatorChar, '/');
                    if (ALLOWED.stream().anyMatch(name::contains)) {
                        continue;
                    }
                    String n = f.getFileName().toString();
                    if (!n.endsWith(".js") && !n.endsWith(".java") && !n.endsWith(".html") && !n.endsWith(".css") && !n.endsWith(".json")) {
                        continue;
                    }
                    if (Files.readString(f, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT).contains("vault")) {
                        hits.add(name);
                    }
                }
            }
        }
        assertEquals(List.of(), hits);
    }
}

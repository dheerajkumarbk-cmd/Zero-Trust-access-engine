package dev.dwarpal;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Build gate against "Trojan Source" (CVE-2021-42574): invisible bidirectional-override and
 * line-separator characters can make source code display differently from how it compiles,
 * hiding logic from reviewers. None may appear in our sources, configs or docs; use ASCII
 * escapes instead.
 */
class SourceHygieneTest {

    private static boolean forbidden(int c) {
        return c == 0x2028 || c == 0x2029 || c == 0x200E || c == 0x200F
                || (c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069) || c == 0xFEFF;
    }

    @Test
    void noInvisibleOrBidiCharactersInTheRepository() throws IOException {
        List<String> hits = new ArrayList<>();
        for (String root : List.of("src", ".github", "docs")) {
            Path dir = Path.of(root);
            if (!Files.exists(dir)) {
                continue;
            }
            try (Stream<Path> files = Files.walk(dir)) {
                for (Path f : files.filter(Files::isRegularFile)
                        .filter(p -> p.toString().matches(".*\\.(java|ya?ml|xml|md)$")).toList()) {
                    String text = Files.readString(f, StandardCharsets.UTF_8);
                    int line = 1;
                    for (int i = 0; i < text.length(); i++) {
                        char c = text.charAt(i);
                        if (c == '\n') {
                            line++;
                        } else if (forbidden(c)) {
                            hits.add(f + ":" + line + " U+" + Integer.toHexString(c).toUpperCase());
                        }
                    }
                }
            }
        }
        assertTrue(hits.isEmpty(), "invisible/bidi characters found: " + hits);
    }
}

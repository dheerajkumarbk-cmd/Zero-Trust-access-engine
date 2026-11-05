package dev.dwarpal.console.lab;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The front-end rules of docs/layer-6/standards.md section 3 for the pages of the lab, guide and admin modules: no
 * innerHTML, no eval, no inline script, style or handler, no external address. Text goes in through textContent.
 */
class FrontEndRulesTest {

    private static final Path ROOT = Path.of("src/main/resources/console/modules");
    private static final List<String> MODULES = List.of("lab", "guide", "admin");
    private static final List<Pattern> FORBIDDEN = List.of(
            Pattern.compile("innerHTML"), Pattern.compile("outerHTML"), Pattern.compile("insertAdjacentHTML"),
            Pattern.compile("document\\s*\\.\\s*write"), Pattern.compile("\\beval\\s*\\("), Pattern.compile("new\\s+Function"),
            Pattern.compile("setTimeout\\s*\\(\\s*[\"'`]"), Pattern.compile("setInterval\\s*\\(\\s*[\"'`]"),
            Pattern.compile("\\bon[a-z]{3,}\\s*="), Pattern.compile("<script", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE), Pattern.compile("https?://"),
            Pattern.compile("setAttribute\\(\\s*['\"]style"), Pattern.compile("\\.style\\s*[.=\\[]"),
            Pattern.compile("localStorage|sessionStorage|document\\.cookie"),
            Pattern.compile("DOMParser|createContextualFragment"), Pattern.compile("unsafe-inline|unsafe-eval"));

    private static List<Path> files() throws IOException {
        List<Path> out = new ArrayList<>();
        for (String m : MODULES) {
            Path dir = ROOT.resolve(m);
            if (Files.isDirectory(dir)) {
                try (Stream<Path> s = Files.walk(dir)) {
                    s.filter(Files::isRegularFile).forEach(out::add);
                }
            }
        }
        return out;
    }

    @Test
    void thePagesObeyTheFrontEndRules() throws IOException {
        List<Path> files = files();
        assertTrue(files.stream().anyMatch(p -> p.endsWith("lab/index.js"))
                && files.stream().anyMatch(p -> p.endsWith("guide/index.js")));
        List<String> breaches = new ArrayList<>();
        for (Path p : files) {
            String text = Files.readString(p, StandardCharsets.UTF_8);
            for (Pattern f : FORBIDDEN) {
                if (f.matcher(text).find()) {
                    breaches.add(p + " matches " + f.pattern());
                }
            }
            if (p.toString().endsWith(".html")) {
                breaches.add(p + ": modules ship no HTML; the shell owns the page");
            }
        }
        assertEquals(List.of(), breaches);
    }

    @Test
    void everyModuleHasTheEntryPointTheShellImports() throws IOException {
        for (String m : List.of("lab", "guide")) {
            String js = Files.readString(ROOT.resolve(m).resolve("index.js"), StandardCharsets.UTF_8);
            assertTrue(js.contains("export default { id: '" + m + "'"), m);
            assertTrue(js.contains("view"), m);
        }
    }

    @Test
    void theHelperAllowsOnlyListedAttributesAndLinkTargets() throws IOException {
        String dom = Files.readString(ROOT.resolve("lab/dom.js"), StandardCharsets.UTF_8);
        assertTrue(dom.contains("attribute not allowed"));
        assertTrue(dom.contains("link target not allowed"));
        assertFalse(dom.contains("'style'") || dom.contains("'srcdoc'") || dom.contains("'src'"),
                "no style, srcdoc or src attribute");
        assertEquals(dom, Files.readString(ROOT.resolve("guide/dom.js"), StandardCharsets.UTF_8),
                "one helper, two copies");
    }
}

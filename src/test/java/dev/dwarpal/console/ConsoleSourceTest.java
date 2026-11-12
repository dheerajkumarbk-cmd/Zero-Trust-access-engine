package dev.dwarpal.console;

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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Build gate for the front end (standards section 3, "Output and input"): the console's sources must never contain a way
 * to turn text into markup or code, nor load anything from outside. The scan covers every file under
 * {@code src/main/resources/console}, including the modules of other parts, so a module that breaks the rule breaks the
 * build. The patterns are checked against themselves first (a gate that matches nothing proves nothing).
 */
class ConsoleSourceTest {

    private static final Path ROOT = Path.of("src/main/resources/console");

    /** Things no console script may contain. */
    private static final List<String[]> FORBIDDEN_IN_JS = List.of(
            new String[]{"innerHTML", "\\binnerHTML\\b"},
            new String[]{"outerHTML", "\\bouterHTML\\b"},
            new String[]{"insertAdjacentHTML", "\\binsertAdjacentHTML\\b"},
            new String[]{"document.write", "\\bdocument\\s*\\.\\s*write(ln)?\\s*\\("},
            new String[]{"eval", "\\beval\\s*\\("},
            new String[]{"new Function", "\\bnew\\s+Function\\b|\\bFunction\\s*\\("},
            new String[]{"setTimeout/setInterval with a string", "\\bset(Timeout|Interval)\\s*\\(\\s*[\"'`]"},
            new String[]{"setAttribute of an event handler", "setAttribute\\s*\\(\\s*[\"']on"},
            new String[]{"setAttribute of style", "setAttribute\\s*\\(\\s*[\"']style[\"']"},
            new String[]{"inline style through .style", "\\.style\\s*[.\\[]|\\.style\\s*=|\\.cssText"},
            new String[]{"srcdoc", "\\bsrcdoc\\b"},
            new String[]{"createContextualFragment / DOMParser", "createContextualFragment|\\bDOMParser\\b"},
            new String[]{"a script element made by code", "createElement\\s*\\(\\s*[\"']script[\"']"},
            new String[]{"javascript: URL", "javascript\\s*:"},
            new String[]{"an address outside this server", "https?://|//[a-z0-9.-]+\\.[a-z]{2,}/|\\bwss?://"},
            new String[]{"document.cookie", "document\\s*\\.\\s*cookie"},
            new String[]{"postMessage / window.open", "\\bpostMessage\\b|\\bwindow\\s*\\.\\s*open\\s*\\("},
            new String[]{"sessionStorage", "\\bsessionStorage\\b|\\bindexedDB\\b"},
            new String[]{"import() of a variable address outside /console/", "import\\s*\\(\\s*[\"']https?:"});

    private static final List<String[]> FORBIDDEN_IN_HTML = List.of(
            new String[]{"inline event handler", "(?i)\\son[a-z]+\\s*="},
            new String[]{"inline style attribute", "(?i)\\sstyle\\s*="},
            new String[]{"style element", "(?i)<style"},
            new String[]{"inline script", "(?i)<script(?![^>]*\\ssrc=)"},
            new String[]{"javascript: URL", "(?i)javascript\\s*:"},
            new String[]{"an address outside this server", "(?i)(src|href|action)\\s*=\\s*[\"']?(https?:)?//"},
            new String[]{"iframe/object/embed/form to elsewhere", "(?i)<(iframe|object|embed|base)\\b"});

    private static final List<String[]> FORBIDDEN_IN_CSS = List.of(
            new String[]{"@import", "(?i)@import"},
            new String[]{"an address outside this server", "(?i)url\\s*\\(\\s*[\"']?(https?:)?//"},
            new String[]{"expression()", "(?i)expression\\s*\\("});

    /** Only api.js may talk to the network. */
    private static final Pattern NETWORK = Pattern.compile("\\bfetch\\s*\\(|\\bXMLHttpRequest\\b|\\bEventSource\\b|\\bWebSocket\\b|\\bsendBeacon\\b|\\bnavigator\\s*\\.\\s*serviceWorker\\b");

    private static String withoutComments(String js) {
        // block comments and whole-line // comments (strings with // inside are rare here and the gate errs on the strict side)
        return js.replaceAll("(?s)/\\*.*?\\*/", " ").replaceAll("(?m)^\\s*//.*$", "");
    }

    private static List<Path> files(String... extensions) throws IOException {
        try (Stream<Path> s = Files.walk(ROOT)) {
            return s.filter(Files::isRegularFile).filter(p -> {
                String n = p.getFileName().toString();
                for (String e : extensions) {
                    if (n.endsWith(e)) {
                        return true;
                    }
                }
                return false;
            }).sorted().toList();
        }
    }

    private static String read(Path p) throws IOException {
        return Files.readString(p, StandardCharsets.UTF_8);
    }

    private static List<String> scan(List<Path> files, List<String[]> rules, boolean stripComments) throws IOException {
        List<String> hits = new ArrayList<>();
        for (Path f : files) {
            String text = read(f);
            if (stripComments) {
                text = withoutComments(text);
            }
            for (String[] rule : rules) {
                if (Pattern.compile(rule[1]).matcher(text).find()) {
                    hits.add(ROOT.relativize(f) + ": " + rule[0]);
                }
            }
        }
        return hits;
    }

    @Test
    void thereIsAConsoleToScan() throws IOException {
        assertTrue(files(".js").size() >= 10, "the console has its scripts: " + files(".js").size());
        assertTrue(Files.isRegularFile(ROOT.resolve("index.html")));
        assertTrue(Files.isRegularFile(ROOT.resolve("api.js")));
    }

    @Test
    void noScriptCanTurnTextIntoMarkupOrCodeOrLoadFromElsewhere() throws IOException {
        List<String> hits = scan(files(".js", ".mjs"), FORBIDDEN_IN_JS, true);
        assertEquals(List.of(), hits);
    }

    @Test
    void noPageHasInlineScriptStyleOrHandlers() throws IOException {
        assertEquals(List.of(), scan(files(".html"), FORBIDDEN_IN_HTML, false));
        assertEquals(List.of(), scan(files(".css"), FORBIDDEN_IN_CSS, true));
    }

    @Test
    void onlyApiJsTalksToTheServer() throws IOException {
        List<String> hits = new ArrayList<>();
        for (Path f : files(".js", ".mjs")) {
            if (!f.getFileName().toString().equals("api.js") && NETWORK.matcher(withoutComments(read(f))).find()) {
                hits.add(ROOT.relativize(f).toString());
            }
        }
        assertEquals(List.of(), hits);
    }

    @Test
    void storageIsOnlyInThePreferencesFileAndAlwaysGuarded() throws IOException {
        for (Path f : files(".js")) {
            String text = withoutComments(read(f));
            if (text.contains("localStorage")) {
                assertEquals("prefs.js", f.getFileName().toString(), "localStorage is only for interface preferences, in prefs.js");
                assertTrue(text.split("localStorage", -1).length - 1 <= text.split("try\\s*\\{", -1).length + 1);
            }
        }
    }

    @Test
    void theGateCatchesWhatItIsMeantToCatch() {
        String[] bad = {"el.innerHTML = x;", "a.outerHTML", "el.insertAdjacentHTML('beforeend', x)", "document.write('x')",
                "eval(code)", "new Function('return 1')", "setTimeout('alert(1)', 5)", "el.setAttribute('onclick', 'x()')",
                "el.style.color = 'red'", "el.setAttribute('style', 'x')", "fetch('https://evil.example/x')", "document.cookie",
                "location = 'javascript:alert(1)'", "const s = document.createElement('script')", "new DOMParser()"};
        for (String code : bad) {
            boolean caught = FORBIDDEN_IN_JS.stream().anyMatch(r -> Pattern.compile(r[1]).matcher(code).find());
            assertTrue(caught, "not caught: " + code);
        }
        String[] badHtml = {"<div onclick=\"x()\">", "<p style=\"color:red\">", "<style>a{}</style>", "<script>alert(1)</script>",
                "<a href=\"javascript:alert(1)\">", "<img src=\"https://evil.example/x.png\">", "<iframe src=\"/x\">"};
        for (String code : badHtml) {
            boolean caught = FORBIDDEN_IN_HTML.stream().anyMatch(r -> Pattern.compile(r[1]).matcher(code).find());
            assertTrue(caught, "not caught: " + code);
        }
        String[] fine = {"el.textContent = x;", "el.setAttribute('href', '#/x');", "<script type=\"module\" src=\"/console/shell.js\"></script>",
                "el.classList.add('x')", "// innerHTML is forbidden"};
        for (String code : fine) {
            String js = withoutComments(code);
            assertTrue(FORBIDDEN_IN_JS.stream().noneMatch(r -> Pattern.compile(r[1]).matcher(js).find()), "wrongly caught: " + code);
        }
        assertTrue(FORBIDDEN_IN_HTML.stream().noneMatch(r -> Pattern.compile(r[1]).matcher(fine[2]).find()));
        assertTrue(NETWORK.matcher("await fetch('/x')").find() && NETWORK.matcher("new EventSource(u)").find());
    }
}

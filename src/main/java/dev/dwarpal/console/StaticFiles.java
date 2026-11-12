package dev.dwarpal.console;

import dev.dwarpal.crypto.Digests;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * The static console: a fixed allow-list of files read once, at start-up, from the jar (or the class directory in a
 * build). A request is answered only if its path equals a name in this table; the request path is never turned into a
 * file path, so there is nothing to traverse, no directory listing and no way to read a file that was not packaged
 * (standards section 3, "Static files"). Only the extensions below are served, each with its own content type.
 */
final class StaticFiles {

    /** One served file. */
    record Asset(String path, String contentType, byte[] bytes, String etag) {
    }

    private static final Map<String, String> TYPES = Map.of(
            "html", "text/html; charset=utf-8",
            "css", "text/css; charset=utf-8",
            "js", "text/javascript; charset=utf-8",
            "mjs", "text/javascript; charset=utf-8",
            "json", "application/json; charset=utf-8",
            "svg", "image/svg+xml",
            "png", "image/png",
            "ico", "image/x-icon",
            "woff2", "font/woff2",
            "txt", "text/plain; charset=utf-8");
    private static final long MAX_FILE = 2L * 1024 * 1024;
    private static final long MAX_TOTAL = 24L * 1024 * 1024;
    private static final int MAX_FILES = 2_000;

    private final Map<String, Asset> assets;

    private StaticFiles(Map<String, Asset> assets) {
        this.assets = Map.copyOf(assets);
    }

    /** Everything under {@code root} on the class path, e.g. {@code console} for {@code resources/console/}. */
    static StaticFiles fromClasspath(String root) throws IOException {
        return fromClasspath(StaticFiles.class.getClassLoader(), root);
    }

    /** The same, from a given class loader (a test loads a jar this way). */
    static StaticFiles fromClasspath(ClassLoader loader, String root) throws IOException {
        URL url = loader.getResource(root);
        Map<String, Asset> found = new HashMap<>();
        if (url == null) {
            return new StaticFiles(found);
        }
        try {
            URI uri = url.toURI();
            if (uri.getScheme().equals("jar")) {
                FileSystem fs;
                try {
                    fs = FileSystems.newFileSystem(uri, Map.of());
                } catch (FileSystemAlreadyExistsException shared) {
                    fs = FileSystems.getFileSystem(uri);
                }
                scan(fs.getPath("/" + root), found);
            } else {
                scan(Path.of(uri), found);
            }
        } catch (URISyntaxException e) {
            throw new IOException("class path resource has no usable address", e);
        }
        return new StaticFiles(found);
    }

    static StaticFiles of(List<Asset> list) {
        Map<String, Asset> m = new HashMap<>();
        list.forEach(a -> m.put(a.path(), a));
        return new StaticFiles(m);
    }

    private static void scan(Path base, Map<String, Asset> out) throws IOException {
        long total = 0;
        try (Stream<Path> walk = Files.walk(base)) {
            for (Path f : (Iterable<Path>) walk.filter(Files::isRegularFile)::iterator) {
                String rel = base.relativize(f).toString().replace('\\', '/');
                String type = typeOf(rel);
                if (type == null || !safeName(rel)) {
                    continue;
                }
                long size = Files.size(f);
                total += size;
                if (size > MAX_FILE || total > MAX_TOTAL || out.size() >= MAX_FILES) {
                    throw new IOException("static console too large");
                }
                byte[] bytes = Files.readAllBytes(f);
                out.put(rel, new Asset(rel, type, bytes, "\"" + Digests.sha256Hex(bytes).substring(0, 32) + "\""));
            }
        }
    }

    /** Names the server will ever serve: plain segments, no leading dot, no {@code ..}, nothing under {@code api}. */
    static boolean safeName(String rel) {
        if (rel.isEmpty() || rel.length() > 200 || rel.startsWith("api/") || rel.equals("api")) {
            return false;
        }
        for (String seg : rel.split("/", -1)) {
            if (seg.isEmpty() || seg.startsWith(".") || seg.contains("..")) {
                return false;
            }
            for (int i = 0; i < seg.length(); i++) {
                char c = seg.charAt(i);
                boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
                        || c == '.';
                if (!ok) {
                    return false;
                }
            }
        }
        return true;
    }

    private static String typeOf(String rel) {
        int dot = rel.lastIndexOf('.');
        return dot < 0 ? null : TYPES.get(rel.substring(dot + 1).toLowerCase(Locale.ROOT));
    }

    /** The asset whose name is exactly {@code rel}. */
    Optional<Asset> get(String rel) {
        return Optional.ofNullable(assets.get(rel));
    }

    int size() {
        return assets.size();
    }
}

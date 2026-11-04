package dev.dwarpal.swg;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Host to category, from a local file of {@code domain category} lines ({@code #} starts a comment):
 * <pre>
 *   news.example     news
 *   mail.example     webmail
 * </pre>
 * The most specific entry wins: with {@code example news} and {@code shop.example shopping},
 * {@code a.shop.example} is shopping. A domain listed twice with different categories is a conflict and
 * the second line is rejected, so the file order cannot silently change a category.
 */
public final class CategoryMap {

    public static final int MAX_ENTRIES = 2_000_000;
    private static final Pattern CATEGORY = Pattern.compile("[a-z0-9_-]{1,64}");

    private final Map<String, String> categories;
    private final int rejectedLines;

    private CategoryMap(Map<String, String> categories, int rejectedLines) {
        this.categories = Map.copyOf(categories);
        this.rejectedLines = rejectedLines;
    }

    public static CategoryMap empty() {
        return new CategoryMap(Map.of(), 0);
    }

    public static CategoryMap parse(String text) {
        try {
            return parse(new StringReader(text));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static CategoryMap parse(Reader reader) throws IOException {
        Builder b = new Builder();
        ListFiles.lines(reader, b);
        return b.build();
    }

    /** Loads a local category file (never downloads anything). */
    public static CategoryMap load(Path file) throws IOException {
        Builder b = new Builder();
        ListFiles.lines(file, b);
        return b.build();
    }

    public Optional<String> category(HostName host) {
        for (String s : host.suffixes()) {
            String c = categories.get(s);
            if (c != null) {
                return Optional.of(c);
            }
        }
        return Optional.empty();
    }

    public int size() {
        return categories.size();
    }

    public int rejectedLines() {
        return rejectedLines;
    }

    private static final class Builder implements ListFiles.LineSink {
        private final Map<String, String> map = new HashMap<>();
        private int rejected;

        @Override
        public void line(String raw) {
            int hash = raw.indexOf('#');
            String line = (hash >= 0 ? raw.substring(0, hash) : raw).strip();
            if (line.isEmpty()) {
                return;
            }
            String[] t = line.split("\\s+");
            if (t.length != 2) {
                rejected++;
                return;
            }
            Optional<HostName> host = HostName.parse(t[0]);
            String category = t[1].toLowerCase(Locale.ROOT);
            if (host.isEmpty() || !CATEGORY.matcher(category).matches()) {
                rejected++;
                return;
            }
            String previous = map.get(host.get().value());
            if (previous != null) {
                if (!previous.equals(category)) {
                    rejected++;
                }
                return;
            }
            if (map.size() >= MAX_ENTRIES) {
                throw new IllegalStateException("category file has more than " + MAX_ENTRIES + " entries");
            }
            map.put(host.get().value(), category);
        }

        @Override
        public void rejected() {
            rejected++;
        }

        CategoryMap build() {
            return new CategoryMap(map, rejected);
        }
    }

    @Override
    public String toString() {
        return "CategoryMap[" + size() + " entries, " + rejectedLines + " rejected lines]";
    }
}

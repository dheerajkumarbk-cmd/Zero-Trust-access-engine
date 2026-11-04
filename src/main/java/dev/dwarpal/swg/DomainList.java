package dev.dwarpal.swg;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * A blocklist of domains and IP addresses, loaded from a local file in either of the two formats free
 * public lists use:
 * <pre>
 *   # hosts format                 # domain-list format
 *   0.0.0.0 evil.example           evil.example
 *   127.0.0.1 ads.example          *.tracker.example
 *                                  ||malware.example^
 * </pre>
 * A listed domain also covers all its subdomains ({@code a.b.evil.example} matches {@code evil.example}).
 * Every entry passes through {@link HostName#parse}, so entries and requests are compared in the same
 * canonical form. Lines that are not understood are counted, not guessed at.
 *
 * <p>Immutable: an update loads a new list and replaces the old one as a whole.
 */
public final class DomainList {

    public static final int MAX_ENTRIES = 2_000_000;

    /** Names that hosts files list for the machine itself; they are not blocklist entries. */
    private static final Set<String> HOSTS_BOILERPLATE = Set.of("localhost", "localhost.localdomain", "local",
            "broadcasthost", "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes",
            "ip6-allrouters", "ip6-allhosts", "0.0.0.0");

    private final Set<String> names;
    private final Set<String> ips;
    private final int rejectedLines;

    private DomainList(Set<String> names, Set<String> ips, int rejectedLines) {
        this.names = Set.copyOf(names);
        this.ips = Set.copyOf(ips);
        this.rejectedLines = rejectedLines;
    }

    public static DomainList empty() {
        return new DomainList(Set.of(), Set.of(), 0);
    }

    /** A list from entries given in code (tests, small fixed lists). */
    public static DomainList of(String... entries) {
        return parse(String.join("\n", entries));
    }

    public static DomainList parse(String text) {
        try {
            return parse(new StringReader(text));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static DomainList parse(Reader reader) throws IOException {
        Builder b = new Builder();
        ListFiles.lines(reader, b);
        return b.build();
    }

    /** Loads a local list file (never downloads anything). */
    public static DomainList load(Path file) throws IOException {
        Builder b = new Builder();
        ListFiles.lines(file, b);
        return b.build();
    }

    /** The entry that covers {@code host}, if any: the host itself or one of its parent domains. */
    public Optional<String> match(HostName host) {
        if (host.ipLiteral()) {
            return ips.contains(host.value()) ? Optional.of(host.value()) : Optional.empty();
        }
        for (String s : host.suffixes()) {
            if (names.contains(s)) {
                return Optional.of(s);
            }
        }
        return Optional.empty();
    }

    public boolean matches(HostName host) {
        return match(host).isPresent();
    }

    public int size() {
        return names.size() + ips.size();
    }

    /** Lines that were neither comments nor understood entries (a sign of a wrong or damaged file). */
    public int rejectedLines() {
        return rejectedLines;
    }

    private static final class Builder implements ListFiles.LineSink {
        private final Set<String> names = new HashSet<>();
        private final Set<String> ips = new HashSet<>();
        private int rejected;

        @Override
        public void line(String raw) {
            String line = stripComment(raw).strip();
            if (line.isEmpty()) {
                return;
            }
            String[] tokens = line.split("\\s+");
            if (tokens.length == 1) {
                if (!add(domainToken(tokens[0]))) {
                    rejected++;
                }
                return;
            }
            // hosts format: an address, then one or more names
            String address = tokens[0].indexOf(':') >= 0 ? "[" + tokens[0] + "]" : tokens[0];
            if (HostName.parse(address).filter(HostName::ipLiteral).isEmpty()) {
                rejected++;
                return;
            }
            for (int i = 1; i < tokens.length; i++) {
                if (!HOSTS_BOILERPLATE.contains(tokens[i].toLowerCase(java.util.Locale.ROOT)) && !add(tokens[i])) {
                    rejected++;
                }
            }
        }

        @Override
        public void rejected() {
            rejected++;
        }

        private static String stripComment(String line) {
            String s = line;
            if (s.startsWith("#") || s.startsWith("!")) {
                return "";
            }
            int hash = s.indexOf('#');
            return hash >= 0 ? s.substring(0, hash) : s;
        }

        private static String domainToken(String t) {
            String s = t;
            if (s.startsWith("||") && s.endsWith("^")) {
                s = s.substring(2, s.length() - 1);
            }
            if (s.startsWith("*.")) {
                s = s.substring(2);
            }
            return s;
        }

        private boolean add(String token) {
            Optional<HostName> h = HostName.parse(token);
            if (h.isEmpty()) {
                return false;
            }
            if (names.size() + ips.size() >= MAX_ENTRIES) {
                throw new IllegalStateException("blocklist has more than " + MAX_ENTRIES + " entries");
            }
            (h.get().ipLiteral() ? ips : names).add(h.get().value());
            return true;
        }

        DomainList build() {
            return new DomainList(names, ips, rejected);
        }
    }

    @Override
    public String toString() {
        return "DomainList[" + size() + " entries, " + rejectedLines + " rejected lines]";
    }
}

package dev.dwarpal.console;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The public keys of the people's device passkeys. A public key is not a secret, but who may sign with it is what the
 * console trusts, so the file is owner-only and replaced whole (written beside it, then moved over it). One line per
 * passkey: {@code person|credential id|alg|public key (X.509, Base64)|signature counter|created}.
 */
final class PasskeyStore {

    /** One registered passkey. {@code alg} is the COSE number: -7 (ES256) or -257 (RS256). */
    record Credential(String person, String id, int alg, String publicKey, long signCount, Instant created) {
        String line() {
            return person + "|" + id + "|" + alg + "|" + publicKey + "|" + signCount + "|" + created;
        }
    }

    private final Path file;
    private final Map<String, Credential> byId = new LinkedHashMap<>();

    private PasskeyStore(Path file) {
        this.file = file;
    }

    static PasskeyStore inMemory() {
        return new PasskeyStore(null);
    }

    static PasskeyStore open(Path file) throws IOException {
        PasskeyStore s = new PasskeyStore(file);
        if (Files.isRegularFile(file)) {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] p = line.split("[|]", -1);
                if (p.length != 6) {
                    throw new IOException("the passkey file is damaged (a line has " + p.length + " parts)");
                }
                s.byId.put(p[1], new Credential(p[0], p[1], Integer.parseInt(p[2]), p[3], Long.parseLong(p[4]), Instant.parse(p[5])));
            }
        }
        return s;
    }

    synchronized List<Credential> of(String person) {
        List<Credential> out = new ArrayList<>();
        for (Credential c : byId.values()) {
            if (c.person().equals(person)) {
                out.add(c);
            }
        }
        return out;
    }

    synchronized Optional<Credential> find(String person, String id) {
        Credential c = byId.get(id);
        return c != null && c.person().equals(person) ? Optional.of(c) : Optional.empty();
    }

    /** True when somebody already holds a passkey with this id. */
    synchronized boolean taken(String id) {
        return byId.containsKey(id);
    }

    /** The person's passkey becomes this one; any earlier one of theirs stops working. */
    synchronized void replace(Credential c) throws IOException {
        Map<String, Credential> before = new LinkedHashMap<>(byId);
        byId.values().removeIf(x -> x.person().equals(c.person()));
        byId.put(c.id(), c);
        try {
            save();
        } catch (IOException e) {
            byId.clear();
            byId.putAll(before);
            throw e;
        }
    }

    synchronized void counter(Credential c, long signCount) throws IOException {
        Credential old = byId.get(c.id());
        if (old == null) {
            return;
        }
        byId.put(c.id(), new Credential(old.person(), old.id(), old.alg(), old.publicKey(), signCount, old.created()));
        save();
    }

    private void save() throws IOException {
        if (file == null) {
            return;
        }
        Path dir = file.toAbsolutePath().getParent();
        if (dir == null) {
            throw new IOException("the passkey file has no folder");
        }
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, "passkeys", ".tmp");
        try {
            OwnerOnly.restrict(tmp);
            List<String> lines = new ArrayList<>();
            lines.add("# person|credential id|alg|public key|signature counter|created. Public keys only; nothing here is secret.");
            byId.values().forEach(c -> lines.add(c.line()));
            Files.write(tmp, lines, StandardCharsets.UTF_8);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            OwnerOnly.restrict(file);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}

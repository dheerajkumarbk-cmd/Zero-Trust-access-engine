package dev.dwarpal.console;

import dev.dwarpal.domain.Sanitize;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Short notices for people ("an emergency password was activated on your account"). A notice says what happened and to
 * whom, never a secret, and stays until the person has read it. Kept in an owner-only file so a restart does not lose
 * them; the newest 500 are kept.
 */
public final class NoticeBoard {

    /** One notice for one person. */
    public record Notice(String id, String to, Instant at, boolean read, String text) {
    }

    private static final int KEEP = 500;
    private static final int MAX_TEXT = 300;

    private final Path file;
    private final Clock clock;
    private final Object lock = new Object();
    private final List<Notice> all = new ArrayList<>();
    private final AtomicLong counter = new AtomicLong();

    private NoticeBoard(Path file, Clock clock) {
        this.file = file;
        this.clock = clock;
    }

    /** Notices that live only as long as this run (the tests, and a lab with no folder). */
    public static NoticeBoard inMemory(Clock clock) {
        return new NoticeBoard(null, clock);
    }

    public static NoticeBoard open(Path file, Clock clock) throws IOException {
        NoticeBoard b = new NoticeBoard(file, clock);
        synchronized (b.lock) {
            if (Files.isRegularFile(file)) {
                for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                    if (line.isBlank() || line.startsWith("#")) {
                        continue;
                    }
                    String[] p = line.split("[|]", 5);
                    if (p.length != 5) {
                        throw new IOException("the notices file is damaged");
                    }
                    b.all.add(new Notice(p[0], p[1], Instant.parse(p[2]), "1".equals(p[3]), p[4]));
                    b.counter.set(Math.max(b.counter.get(), Long.parseLong(p[0].substring(2))));
                }
            }
        }
        return b;
    }

    /** Leaves a notice for the person; false if it could not be kept (the caller carries on: a notice is not a gate). */
    public boolean post(String to, String text) {
        synchronized (lock) {
            String clean = Sanitize.text(text == null ? "" : text, MAX_TEXT).replace('|', '/');
            all.add(new Notice("n-" + counter.incrementAndGet(), to, clock.instant(), false, clean));
            while (all.size() > KEEP) {
                all.removeFirst();
            }
            return save();
        }
    }

    /** The person's notices, newest first. */
    public List<Notice> of(String person, int max) {
        synchronized (lock) {
            List<Notice> out = new ArrayList<>();
            for (int i = all.size() - 1; i >= 0 && out.size() < max; i--) {
                if (all.get(i).to().equals(person)) {
                    out.add(all.get(i));
                }
            }
            return out;
        }
    }

    public int unread(String person) {
        synchronized (lock) {
            int n = 0;
            for (Notice x : all) {
                if (x.to().equals(person) && !x.read()) {
                    n++;
                }
            }
            return n;
        }
    }

    /** Marks one notice (or, with a null id, every notice) of this person as read. Other people's notices are never touched. */
    public void markRead(String person, String id) {
        synchronized (lock) {
            for (int i = 0; i < all.size(); i++) {
                Notice x = all.get(i);
                if (x.to().equals(person) && !x.read() && (id == null || id.equals(x.id()))) {
                    all.set(i, new Notice(x.id(), x.to(), x.at(), true, x.text()));
                }
            }
            save();
        }
    }

    private boolean save() {
        if (file == null) {
            return true;
        }
        try {
            Path dir = file.toAbsolutePath().getParent();
            if (dir == null) {
                return false;
            }
            Files.createDirectories(dir);
            Path tmp = Files.createTempFile(dir, "notices", ".tmp");
            try {
                OwnerOnly.restrict(tmp);
                List<String> lines = new ArrayList<>();
                lines.add("# id|person|time|read|text. Notices say what happened, never a secret.");
                for (Notice x : all) {
                    lines.add(x.id() + "|" + x.to() + "|" + x.at() + "|" + (x.read() ? "1" : "0") + "|" + x.text());
                }
                Files.write(tmp, lines, StandardCharsets.UTF_8);
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
                OwnerOnly.restrict(file);
            } finally {
                Files.deleteIfExists(tmp);
            }
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}

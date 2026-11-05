package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleAuth.Enrolment;
import dev.dwarpal.console.ConsoleAuth.Person;
import dev.dwarpal.console.ConsoleModule.Role;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * The people of the lab console: the three analysts of the SOC (ana, ben, cleo), an administrator (dana) and an
 * ordinary user (uma). Passwords and security-key PINs are random, made once and kept in {@code <lab>/console/people.txt}
 * (owner-only), because a lab that changes every password at each start is a lab nobody logs in to. They are printed by
 * the launcher for the owner and are never in the repository.
 */
public final class DemoPeople {

    private static final String ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    private DemoPeople() {
    }

    /** The five demo people, with fresh random secrets. */
    public static List<Enrolment> fresh() {
        List<Enrolment> out = new ArrayList<>();
        out.add(enrol("ana", "Ana (analyst)", Set.of(Role.ANALYST)));
        out.add(enrol("ben", "Ben (analyst)", Set.of(Role.ANALYST)));
        out.add(enrol("cleo", "Cleo (SOC lead)", Set.of(Role.LEAD, Role.ANALYST)));
        out.add(enrol("dana", "Dana (administrator)", Set.of(Role.ADMIN)));
        out.add(enrol("uma", "Uma (user)", Set.of(Role.USER)));
        return out;
    }

    private static Enrolment enrol(String id, String display, Set<Role> roles) {
        return new Enrolment(new Person(id, display, roles), random(16), random(8));
    }

    private static String random(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }

    /** Reads {@code <lab>/console/people.txt}, making it (owner-only) on the first start. */
    public static List<Enrolment> loadOrCreate(Path labDir) throws IOException {
        Path dir = labDir.resolve("console");
        Files.createDirectories(dir);
        OwnerOnly.restrict(dir);
        Path file = dir.resolve("people.txt");
        if (!Files.isRegularFile(file)) {
            StringBuilder sb = new StringBuilder("# id|display name|roles|password|security-key PIN  (lab secrets, owner only)\n");
            for (Enrolment e : fresh()) {
                sb.append(e.person().id()).append('|').append(e.person().display()).append('|')
                        .append(String.join(",", e.person().roles().stream().map(Enum::name).sorted().toList())).append('|')
                        .append(e.password()).append('|').append(e.pin()).append('\n');
            }
            Files.writeString(file, sb.toString(), StandardCharsets.UTF_8);
            OwnerOnly.restrict(file);
        }
        List<Enrolment> out = new ArrayList<>();
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] f = line.split("\\|", -1);
            if (f.length != 5) {
                throw new IllegalArgumentException("people.txt: a line has the wrong number of fields");
            }
            Set<Role> roles = EnumSet.noneOf(Role.class);
            for (String r : f[2].split(",")) {
                roles.add(Role.valueOf(r.strip()));
            }
            out.add(new Enrolment(new Person(f[0], f[1], roles), f[3], f[4]));
        }
        return List.copyOf(out);
    }
}

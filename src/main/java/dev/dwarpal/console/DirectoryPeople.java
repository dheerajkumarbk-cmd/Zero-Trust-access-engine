package dev.dwarpal.console;

import dev.dwarpal.console.ConsoleAuth.Enrolment;
import dev.dwarpal.console.ConsoleAuth.Person;
import dev.dwarpal.console.ConsoleModule.Role;
import dev.dwarpal.directory.Directory;
import dev.dwarpal.directory.DirectoryPerson;

import java.time.Clock;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Joins the people file and the directory database at start-up. The people file holds only what the directory cannot:
 * each person's first password and security-key PIN. The directory is the authority on who exists, what they are
 * called, which console roles they hold and whether they may sign in at all. A person the directory does not know yet
 * is moved in (once); after that the directory wins, so a role changed or a person disabled there is what the console
 * enrols.
 */
final class DirectoryPeople {

    /** Department and job of the demo people; anyone else the file knows gets the plain defaults. */
    private static final Map<String, String[]> JOBS = Map.of(
            "ana", new String[]{"SOC", "Security analyst"},
            "ben", new String[]{"SOC", "Security analyst"},
            "cleo", new String[]{"SOC", "SOC lead"},
            "dana", new String[]{"IT Security", "Administrator"},
            "uma", new String[]{"Finance", "Finance officer"},
            "hana", new String[]{"Human Resources", "HR officer"});

    /** The people to enrol, and how many were moved into the directory by this start. */
    record Result(List<Enrolment> people, int movedIn, int skipped, int issued) {
    }

    private DirectoryPeople() {
    }

    static Result sync(Directory directory, List<Enrolment> fromFile, Clock clock) {
        return sync(directory, fromFile, clock, p -> null);
    }

    /**
     * @param issuer gives first secrets to an active person with a console role who has none yet (a joiner), or null
     *               to leave that person out until somebody does
     */
    static Result sync(Directory directory, List<Enrolment> fromFile, Clock clock,
                       java.util.function.Function<Person, Enrolment> issuer) {
        int moved = 0;
        int issued = 0;
        for (Enrolment e : fromFile) {
            if (directory.addIfAbsent(seed(e.person(), clock))) {
                moved++;
            }
        }
        Map<String, Enrolment> secrets = new java.util.HashMap<>();
        for (Enrolment e : fromFile) {
            secrets.put(e.person().id(), e);
        }
        List<Enrolment> out = new ArrayList<>();
        int skipped = 0;
        for (DirectoryPerson p : directory.people()) {
            Enrolment known = secrets.get(p.id());
            // a person who left, or who holds no console role yet, cannot sign in
            if (p.status() != DirectoryPerson.Status.ACTIVE || p.consoleRoles().isEmpty()) {
                skipped++;
                continue;
            }
            Set<Role> roles = EnumSet.noneOf(Role.class);
            p.consoleRoles().forEach(r -> roles.add(Role.valueOf(r)));
            Person person = new Person(p.id(), p.displayName(), roles);
            if (known == null) {
                known = issuer.apply(person);
                if (known == null) {
                    skipped++;
                    continue;
                }
                issued++;
            }
            out.add(new Enrolment(person, known.password(), known.pin()));
        }
        return new Result(List.copyOf(out), moved, skipped, issued);
    }

    private static DirectoryPerson seed(Person p, Clock clock) {
        String[] job = Optional.ofNullable(JOBS.get(p.id())).orElse(new String[]{"Unassigned", "Employee"});
        Set<String> roles = new TreeSet<>();
        p.roles().forEach(r -> roles.add(r.name()));
        return new DirectoryPerson(p.id(), p.display(), job[0], job[1], DirectoryPerson.Status.ACTIVE,
                DirectoryPerson.Source.SEED, clock.instant(), roles);
    }
}

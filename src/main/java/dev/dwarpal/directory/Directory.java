package dev.dwarpal.directory;

import java.util.List;
import java.util.Optional;

/**
 * The directory of people (the "who" of the IAM process): the one door to it. The running lab holds a
 * {@link PostgresDirectory}; tests that do not need a database can hold a small in-memory one. Nothing outside the
 * {@code dev.dwarpal.directory} package touches SQL.
 */
public interface Directory {

    /** What the Directory page shows about the database itself: no address, no user, no password. */
    record Health(String server, int schemaVersion) {
    }

    /** Everyone, by id. */
    List<DirectoryPerson> people();

    /** One person, or nothing: an id that is malformed or unknown gives the same answer and never reaches the database. */
    Optional<DirectoryPerson> find(String id);

    /**
     * Adds the person (and their roles, together or not at all) unless that id exists already.
     *
     * @return true if the person was added
     */
    boolean addIfAbsent(DirectoryPerson person);

    /** The database's own name and version and the version of its tables. */
    Health health();
}

package dev.dwarpal.directory;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;

/** A directory held in memory, for tests that are about something else than PostgreSQL. */
public final class MemoryDirectory implements Directory {

    private final TreeMap<String, DirectoryPerson> people = new TreeMap<>();

    @Override
    public synchronized List<DirectoryPerson> people() {
        return new ArrayList<>(people.values());
    }

    @Override
    public synchronized Optional<DirectoryPerson> find(String id) {
        return Optional.ofNullable(people.get(id));
    }

    @Override
    public synchronized boolean addIfAbsent(DirectoryPerson person) {
        return people.putIfAbsent(person.id(), person) == null;
    }

    @Override
    public Health health() {
        return new Health("PostgreSQL (memory stand-in)", Migrator.expectedVersion());
    }

    /** Replaces a person outright, as a later stage will when roles change. */
    public synchronized void put(DirectoryPerson person) {
        people.put(person.id(), person);
    }
}

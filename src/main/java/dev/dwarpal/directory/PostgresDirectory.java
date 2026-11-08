package dev.dwarpal.directory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The directory in PostgreSQL. Standard SQL only, and every statement below is a constant with {@code ?} for each
 * value: nothing a person typed is ever joined into SQL text. The running lab signs in as the low-privilege app user,
 * which can read and write these rows and nothing else.
 */
public final class PostgresDirectory implements Directory {

    private static final String PERSON_COLUMNS =
            "SELECT person_id, display_name, department, business_role, status, source, created_at FROM directory_person";
    private static final String LIST_PEOPLE = PERSON_COLUMNS + " ORDER BY person_id";
    private static final String FIND_PERSON = PERSON_COLUMNS + " WHERE person_id = ?";
    private static final String LIST_ROLES = "SELECT person_id, console_role FROM directory_person_role ORDER BY person_id, console_role";
    private static final String FIND_ROLES = "SELECT console_role FROM directory_person_role WHERE person_id = ? ORDER BY console_role";
    private static final String INSERT_PERSON = "INSERT INTO directory_person (person_id, display_name, department, business_role,"
            + " status, source, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    private static final String INSERT_ROLE = "INSERT INTO directory_person_role (person_id, console_role) VALUES (?, ?)";
    private static final String EXISTS_PERSON = "SELECT 1 FROM directory_person WHERE person_id = ?";
    private static final String SCHEMA_VERSION = "SELECT MAX(version) FROM schema_version";

    private final Database db;

    public PostgresDirectory(Database db) {
        this.db = Objects.requireNonNull(db, "db");
    }

    @Override
    public List<DirectoryPerson> people() {
        return db.read(c -> {
            Map<String, Set<String>> roles = new HashMap<>();
            try (PreparedStatement s = c.prepareStatement(LIST_ROLES); ResultSet r = s.executeQuery()) {
                while (r.next()) {
                    roles.computeIfAbsent(r.getString(1), k -> new HashSet<>()).add(r.getString(2));
                }
            }
            List<DirectoryPerson> out = new ArrayList<>();
            try (PreparedStatement s = c.prepareStatement(LIST_PEOPLE); ResultSet r = s.executeQuery()) {
                while (r.next()) {
                    out.add(person(r, roles.getOrDefault(r.getString(1), Set.of())));
                }
            }
            return List.copyOf(out);
        });
    }

    @Override
    public Optional<DirectoryPerson> find(String id) {
        return DirectoryPerson.validId(id) ? findExact(id) : Optional.empty();
    }

    /** The lookup itself, with no pre-check: used by tests to show the query is safe even if the pre-check were missing. */
    Optional<DirectoryPerson> findExact(String id) {
        return db.read(c -> {
            Set<String> roles = new HashSet<>();
            try (PreparedStatement s = c.prepareStatement(FIND_ROLES)) {
                s.setString(1, id);
                try (ResultSet r = s.executeQuery()) {
                    while (r.next()) {
                        roles.add(r.getString(1));
                    }
                }
            }
            try (PreparedStatement s = c.prepareStatement(FIND_PERSON)) {
                s.setString(1, id);
                try (ResultSet r = s.executeQuery()) {
                    return r.next() ? Optional.of(person(r, roles)) : Optional.<DirectoryPerson>empty();
                }
            }
        });
    }

    @Override
    public boolean addIfAbsent(DirectoryPerson p) {
        Objects.requireNonNull(p, "person");
        return db.write(c -> {
            if (exists(c, p.id())) {
                return false;
            }
            OffsetDateTime at = p.createdAt().atOffset(ZoneOffset.UTC);
            try (PreparedStatement s = c.prepareStatement(INSERT_PERSON)) {
                s.setString(1, p.id());
                s.setString(2, p.displayName());
                s.setString(3, p.department());
                s.setString(4, p.businessRole());
                s.setString(5, p.status().name());
                s.setString(6, p.source().name());
                s.setObject(7, at);
                s.setObject(8, at);
                s.executeUpdate();
            } catch (SQLException e) {
                if (Database.isDuplicate(e)) {
                    return false;
                }
                throw e;
            }
            try (PreparedStatement s = c.prepareStatement(INSERT_ROLE)) {
                for (String role : p.consoleRoles()) {
                    s.setString(1, p.id());
                    s.setString(2, role);
                    s.addBatch();
                }
                s.executeBatch();
            }
            return true;
        });
    }

    @Override
    public Health health() {
        return db.read(c -> {
            String server = c.getMetaData().getDatabaseProductName() + " " + c.getMetaData().getDatabaseProductVersion();
            int version;
            try (PreparedStatement s = c.prepareStatement(SCHEMA_VERSION); ResultSet r = s.executeQuery()) {
                version = r.next() ? r.getInt(1) : 0;
            }
            return new Health(server, version);
        });
    }

    private static boolean exists(Connection c, String id) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(EXISTS_PERSON)) {
            s.setString(1, id);
            try (ResultSet r = s.executeQuery()) {
                return r.next();
            }
        }
    }

    private static DirectoryPerson person(ResultSet r, Set<String> roles) throws SQLException {
        return new DirectoryPerson(r.getString(1), r.getString(2), r.getString(3), r.getString(4),
                DirectoryPerson.Status.valueOf(r.getString(5)), DirectoryPerson.Source.valueOf(r.getString(6)),
                r.getObject(7, OffsetDateTime.class).toInstant(), roles);
    }
}

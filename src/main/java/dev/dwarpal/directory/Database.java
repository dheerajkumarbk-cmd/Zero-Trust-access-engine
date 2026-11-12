package dev.dwarpal.directory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Objects;
import java.util.Properties;

/**
 * The one place that opens connections to PostgreSQL. A short-lived connection per piece of work: the lab asks a few
 * questions a minute, and a connection that is closed when the work ends cannot leak a half-finished transaction.
 * Every statement run through it must be a {@link java.sql.PreparedStatement} (the source scan in
 * {@code DirectorySourceTest} enforces it), so a value typed by a person is only ever a parameter, never SQL text.
 */
public final class Database {

    /** A piece of work on one connection. */
    @FunctionalInterface
    public interface Work<T> {
        T run(Connection connection) throws SQLException;
    }

    private static final int CONNECT_SECONDS = 5;
    private static final int SOCKET_SECONDS = 20;

    private final DbSettings.Login login;

    public Database(DbSettings.Login login) {
        this.login = Objects.requireNonNull(login, "login");
    }

    /** Opens a connection that the caller must close. */
    public Connection open() throws SQLException {
        Properties p = new Properties();
        p.setProperty("user", login.user());
        p.setProperty("password", login.password());
        p.setProperty("ApplicationName", "dwarpal");
        p.setProperty("connectTimeout", Integer.toString(CONNECT_SECONDS));
        p.setProperty("socketTimeout", Integer.toString(SOCKET_SECONDS));
        return DriverManager.getConnection(login.url(), p);
    }

    /** Work that only reads. The connection is read-only, so a mistake cannot write. */
    public <T> T read(Work<T> work) {
        try (Connection c = open()) {
            c.setReadOnly(true);
            return work.run(c);
        } catch (SQLException e) {
            throw failure(e);
        }
    }

    /** Work that writes: everything in it happens together or not at all. */
    public <T> T write(Work<T> work) {
        try (Connection c = open()) {
            c.setAutoCommit(false);
            try {
                T result = work.run(c);
                c.commit();
                return result;
            } catch (SQLException | RuntimeException e) {
                c.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw failure(e);
        }
    }

    /** True when the database said "that row already exists" (SQLSTATE 23505). */
    static boolean isDuplicate(SQLException e) {
        return "23505".equals(e.getSQLState());
    }

    private static DirectoryException failure(SQLException e) {
        return new DirectoryException("the directory database refused or could not do that (SQLSTATE " + e.getSQLState() + ")", e);
    }
}

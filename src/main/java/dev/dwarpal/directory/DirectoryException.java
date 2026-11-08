package dev.dwarpal.directory;

/**
 * Anything that goes wrong between the lab and its directory database. The message is safe to show or log: it never
 * holds a password, a query or a value a person typed (the cause, kept for the developer, may hold the database's own
 * wording).
 */
public final class DirectoryException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public DirectoryException(String message) {
        super(message);
    }

    public DirectoryException(String message, Throwable cause) {
        super(message, cause);
    }
}

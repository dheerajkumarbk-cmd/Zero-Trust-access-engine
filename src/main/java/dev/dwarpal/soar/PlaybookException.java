package dev.dwarpal.soar;

/**
 * A playbook file that cannot be read at all (not safe YAML, wrong shape, too large). Messages name the place in
 * the file, never its content, so a secret pasted into a file does not end up in a log.
 */
public final class PlaybookException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public PlaybookException(String message) {
        super(message);
    }
}

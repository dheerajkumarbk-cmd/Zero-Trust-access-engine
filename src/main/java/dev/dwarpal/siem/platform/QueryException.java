package dev.dwarpal.siem.platform;

import java.io.Serial;

/**
 * A query or rule expression that cannot be parsed or is over a limit. The message names the position and
 * the problem; it never echoes more than a short, sanitised piece of the input.
 */
public final class QueryException extends IllegalArgumentException {

    @Serial
    private static final long serialVersionUID = 1L;

    public QueryException(String message) {
        super(message);
    }
}

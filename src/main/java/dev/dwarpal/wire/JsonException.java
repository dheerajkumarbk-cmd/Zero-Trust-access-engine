package dev.dwarpal.wire;

import dev.dwarpal.domain.Sanitize;

/**
 * Any JSON that is malformed, too large, or does not match the expected shape. The message names the
 * problem and position only; it never echoes the input, so it is safe to log.
 */
public final class JsonException extends RuntimeException {

    private static final long serialVersionUID = 1L;
    private static final int MAX_MESSAGE_LENGTH = 200;

    public JsonException(String message) {
        super(Sanitize.text(message, MAX_MESSAGE_LENGTH));
    }
}

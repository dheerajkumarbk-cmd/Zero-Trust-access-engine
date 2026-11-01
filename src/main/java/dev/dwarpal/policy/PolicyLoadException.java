package dev.dwarpal.policy;

import dev.dwarpal.domain.Sanitize;

/**
 * A policy file was rejected. The message names the offending path, e.g. {@code policies[2].when}.
 * Messages can quote parts of the (untrusted) file, such as an unknown key, so they are
 * sanitised here once, for every caller.
 */
public class PolicyLoadException extends RuntimeException {

    private static final long serialVersionUID = 1L;
    private static final int MAX_MESSAGE_LENGTH = 2048;

    public PolicyLoadException(String message) {
        super(Sanitize.text(message, MAX_MESSAGE_LENGTH));
    }

    public PolicyLoadException(String message, Throwable cause) {
        super(Sanitize.text(message, MAX_MESSAGE_LENGTH), cause);
    }
}

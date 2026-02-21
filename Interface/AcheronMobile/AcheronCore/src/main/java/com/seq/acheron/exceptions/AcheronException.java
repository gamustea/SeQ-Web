package com.seq.acheron.exceptions;

/**
 * Base class for all unchecked exceptions thrown by the Acheron vault system.
 * <p>
 * Extend this class to create domain-specific exceptions that signal
 * errors within the Acheron vault lifecycle (e.g., authentication
 * failures, encryption errors, or persistence issues).
 * <p>
 * Being a {@link RuntimeException}, callers are not required to declare
 * or catch {@code AcheronException} explicitly, though they should handle
 * it at appropriate boundaries (e.g., the UI layer or a service entry point).
 *
 * @see WrongPasswordException
 */
public class AcheronException extends RuntimeException {

    /**
     * Creates a new {@code AcheronException} with the given detail message.
     *
     * @param message a human-readable description of the error
     */
    public AcheronException(String message) {
        super(message);
    }

    /**
     * Creates a new {@code AcheronException} with the given detail message
     * and the underlying cause.
     * <p>
     * Use this constructor when wrapping a lower-level exception so that
     * the original stack trace is preserved and accessible via
     * {@link #getCause()}.
     *
     * @param message a human-readable description of the error
     * @param cause   the exception that triggered this one; may be {@code null}
     */
    public AcheronException(String message, Throwable cause) {
        super(message, cause);
    }
}

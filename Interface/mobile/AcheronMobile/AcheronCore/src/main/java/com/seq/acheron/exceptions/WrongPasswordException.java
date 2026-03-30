package com.seq.acheron.exceptions;

/**
 * Thrown when the master password supplied to unlock a vault is incorrect.
 * <p>
 * This exception is raised by {@link com.seq.acheron.vault.VaultFactory#fromJSON}
 * in two situations:
 * <ul>
 *   <li>The AES-GCM authentication tag check fails during vault key unwrapping
 *       (the encrypted vault key cannot be decrypted with the given password).</li>
 *   <li>The {@code checker} value stored in the vault JSON does not match the
 *       SHA-256 hash of the username derived from the supplied password.</li>
 * </ul>
 * <p>
 * Callers should catch this exception at the UI or service boundary and prompt
 * the user to re-enter their master password. The original low-level cause
 * (if any) is preserved via {@link #getCause()} for diagnostic purposes.
 *
 * @see com.seq.acheron.vault.VaultFactory
 * @see AcheronException
 */
public class WrongPasswordException extends AcheronException {

    /**
     * Creates a new {@code WrongPasswordException} with the given detail message.
     *
     * @param message a human-readable description of why the password was rejected
     */
    public WrongPasswordException(String message) {
        super(message);
    }

    /**
     * Creates a new {@code WrongPasswordException} with the given detail message
     * and the underlying cause.
     * <p>
     * Use this constructor when the exception is triggered by a lower-level
     * cryptographic failure (e.g., {@link javax.crypto.AEADBadTagException})
     * so that the original stack trace is not lost.
     *
     * @param message a human-readable description of the error
     * @param cause   the cryptographic or I/O exception that triggered this one
     */
    public WrongPasswordException(String message, Throwable cause) {
        super(message, cause);
    }
}

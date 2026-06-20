package com.seq.acheron.vault.secrets.symmetric;

import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Creates a {@link VaultEncryptingStrategy} for a new vault.
 * <p>
 * Tries Argon2 first; if the native library is unavailable
 * (e.g. on Android/arm64 or a platform without bundled natives),
 * falls back silently to PBKDF2.  The chosen KDF is recorded in
 * {@code toJson()} so that reopening the vault always uses the
 * same algorithm.
 */
public final class VaultEncryptingStrategyFactory {

    private static final Logger LOG =
            Logger.getLogger(VaultEncryptingStrategyFactory.class.getName());

    private VaultEncryptingStrategyFactory() {}

    /**
     * Creates a strategy for a brand-new vault (generates a random vault key).
     *
     * @param masterPassword the user's master password
     * @param saltBase64     Base64-encoded salt
     * @return a ready-to-use {@link VaultEncryptingStrategy}
     * @throws GeneralSecurityException if key generation fails
     */
    public static VaultEncryptingStrategy create(
            String masterPassword,
            String saltBase64
    ) throws GeneralSecurityException {
        try {
            return new Argon2VaultEncryptingStrategy(masterPassword, saltBase64, true);
        } catch (UnsatisfiedLinkError | ExceptionInInitializerError | RuntimeException e) {
            LOG.log(Level.INFO,
                    "Argon2 native library unavailable, falling back to PBKDF2", e);
            return new PBKDF2VaultEncryptingStrategy(masterPassword, saltBase64, true);
        }
    }
}

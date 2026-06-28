package com.seq.acheron.vault.secrets.symmetric;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Single source of truth for selecting and instantiating the concrete
 * {@link VaultEncryptingStrategy} (Argon2 or PBKDF2) for both vault lifecycle
 * stages:
 * <ul>
 *     <li>{@link #create(String, String)} — brand-new vault, generates a random vault key.</li>
 *     <li>{@link #reopen(String, String, String, int, int, int)} — existing vault,
 *     re-derives the key from a persisted KDF identifier; the caller still has to
 *     unwrap the vault key via {@link VaultEncryptingStrategy#importVaultKey(String)}.</li>
 * </ul>
 */
public final class VaultEncryptingStrategyFactory {

    private static final Logger LOG =
            Logger.getLogger(VaultEncryptingStrategyFactory.class.getName());

    private VaultEncryptingStrategyFactory() {}

    /**
     * Creates a strategy for a brand-new vault (generates a random vault key).
     * <p>
     * Tries Argon2 first; if the native library is unavailable
     * (e.g. on Android/arm64 or a platform without bundled natives),
     * falls back silently to PBKDF2.  The chosen KDF is recorded in
     * {@code toJson()} so that reopening the vault always uses the
     * same algorithm.
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

    /**
     * Re-derives a strategy for reopening an existing vault, using the KDF
     * identifier and parameters previously persisted by
     * {@link VaultEncryptingStrategy#toJson()}.
     * <p>
     * Unlike {@link #create(String, String)}, this never falls back between
     * algorithms: the vault was already created with {@code kdfId}, so that is
     * the only algorithm that can possibly unwrap its vault key. The returned
     * strategy has no vault key yet; the caller must subsequently call
     * {@link VaultEncryptingStrategy#importVaultKey(String)}.
     *
     * @param kdfId          the persisted KDF identifier ({@code "Argon2"} or {@code "PBKDF2"})
     * @param masterPassword candidate master password supplied by the caller
     * @param saltBase64     Base64-encoded salt used for the original KDF run
     * @param iterations     KDF iteration count ({@code 0} uses the algorithm's default)
     * @param memoryKiB      Argon2 memory cost in KiB (ignored for PBKDF2)
     * @param parallelism    Argon2 parallelism degree (ignored for PBKDF2)
     * @return a strategy configured with the candidate master password; vault key unset
     * @throws GeneralSecurityException if key derivation fails
     */
    public static VaultEncryptingStrategy reopen(
            String kdfId,
            String masterPassword,
            String saltBase64,
            int iterations,
            int memoryKiB,
            int parallelism
    ) throws GeneralSecurityException {
        if ("PBKDF2".equalsIgnoreCase(kdfId)) {
            return new PBKDF2VaultEncryptingStrategy(masterPassword, saltBase64, (SecretKey) null,
                    iterations, 256);
        }
        return new Argon2VaultEncryptingStrategy(masterPassword, saltBase64, (SecretKey) null,
                iterations, memoryKiB, parallelism);
    }
}

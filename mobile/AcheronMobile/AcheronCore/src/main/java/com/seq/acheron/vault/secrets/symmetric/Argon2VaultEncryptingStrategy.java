package com.seq.acheron.vault.secrets.symmetric;

import de.mkammerer.argon2.Argon2Advanced;
import de.mkammerer.argon2.Argon2Factory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 * AES-based encryption strategy using Argon2 to derive a key
 * from the user's master password.
 * <p>
 * This strategy:
 * <ul>
 *     <li>Derives {@link #derivedKey} from a master password + salt using Argon2.</li>
 *     <li>Generates or accepts a random {@link #vaultKey} used with AES-GCM.</li>
 *     <li>Allows exporting and importing the {@link #vaultKey} wrapped
 *     (encrypted) with {@link #derivedKey} via the base class.</li>
 * </ul>
 */
public final class Argon2VaultEncryptingStrategy extends VaultEncryptingStrategy {

    private static final int DEFAULT_ITERATIONS   = 3;
    private static final int DEFAULT_MEMORY_KIB   = 65536;
    private static final int DEFAULT_PARALLELISM  = 1;

    private final int iterations;
    private final int memoryKiB;
    private final int parallelism;

    /**
     * Creates a new strategy instance that:
     * <ul>
     *     <li>Derives {@link #derivedKey} from the given master password and salt
     *     using Argon2.</li>
     *     <li>Generates a new random {@link #vaultKey} internally if {@code generateVaultKey} is
     *     set to true; otherwise, it will remain null</li>
     * </ul>
     *
     * @param masterPassword    the user's master password
     * @param saltBase64        Base64-encoded salt used for Argon2
     * @param generateVaultKey  Whether the constructor builds a random {@link #vaultKey} or not
     * @throws GeneralSecurityException if key generation fails
     */
    public Argon2VaultEncryptingStrategy(
            String masterPassword,
            String saltBase64,
            boolean generateVaultKey
    ) throws GeneralSecurityException {
        this(masterPassword, saltBase64, generateVaultKey, DEFAULT_ITERATIONS, DEFAULT_MEMORY_KIB, DEFAULT_PARALLELISM);
    }

    public Argon2VaultEncryptingStrategy(
            String masterPassword,
            String saltBase64,
            boolean generateVaultKey,
            int iterations,
            int memoryKiB,
            int parallelism
    ) throws GeneralSecurityException {
        super(
            masterPassword,
            "AES/GCM/NoPadding",
            saltBase64,
            generateVaultKey
        );
        this.iterations = iterations > 0 ? iterations : DEFAULT_ITERATIONS;
        this.memoryKiB = memoryKiB > 0 ? memoryKiB : DEFAULT_MEMORY_KIB;
        this.parallelism = parallelism > 0 ? parallelism : DEFAULT_PARALLELISM;
        this.derivedKey = deriveKey(masterPassword, saltBase64);
    }

    /**
     * Creates a new strategy instance using an existing {@link #vaultKey}.
     * <p>
     * This constructor is typically used when reopening an existing vault:
     * the vault key is first unwrapped using {@link #derivedKey}, and then
     * passed here to be reused.
     *
     * @param masterPassword the user's master password
     * @param saltBase64     Base64-encoded salt used for Argon2
     * @param vaultKey       an existing vault key to reuse
     */
    public Argon2VaultEncryptingStrategy(
            String masterPassword,
            String saltBase64,
            SecretKey vaultKey
    ) throws GeneralSecurityException {
        this(masterPassword, saltBase64, vaultKey, DEFAULT_ITERATIONS, DEFAULT_MEMORY_KIB, DEFAULT_PARALLELISM);
    }

    public Argon2VaultEncryptingStrategy(
            String masterPassword,
            String saltBase64,
            SecretKey vaultKey,
            int iterations,
            int memoryKiB,
            int parallelism
    ) throws GeneralSecurityException {
        super(
                masterPassword,
                "AES/GCM/NoPadding",
                saltBase64,
                vaultKey
        );
        this.iterations = iterations > 0 ? iterations : DEFAULT_ITERATIONS;
        this.memoryKiB = memoryKiB > 0 ? memoryKiB : DEFAULT_MEMORY_KIB;
        this.parallelism = parallelism > 0 ? parallelism : DEFAULT_PARALLELISM;
        this.derivedKey = deriveKey(masterPassword, saltBase64);
    }

    public SecretKey deriveKey(
            String masterPassword,
            String saltBase64
    ) throws GeneralSecurityException {
        Argon2Advanced argon2 = Argon2Factory.createAdvanced();
        char[] passwordChars = masterPassword.toCharArray();

        try {
            byte[] saltBytes = Base64.getDecoder().decode(saltBase64);
            byte[] keyBytes = argon2.rawHash(
                    iterations,
                    memoryKiB,
                    parallelism,
                    passwordChars,
                    saltBytes
            );
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            argon2.wipeArray(passwordChars);
        }
    }

    /**
     * Serialises the cryptographic configuration of this strategy to JSON.
     * <p>
     * This does NOT include any secret material (no master password, no
     * derivedKey, no raw vaultKey), only public parameters required to
     * reconstruct the KDF and cipher configuration.
     * Example output:
     * {
     *   "algorithm": "AES/GCM/NoPadding",
     *   "kdf": "Argon2",
     *   "kdfIterations": 3,
     *   "kdfMemoryKiB": 65536,
     *   "kdfParallelism": 1,
     *   "salt": "base64..."
     * }
     */
    public String toJson() {
        return "{" +
                    "\"transformation\": \"" + transformation + "\", " +
                    "\"kdf\": \"Argon2\", " +
                    "\"kdfIterations\": " + iterations + ", " +
                    "\"kdfMemoryKiB\": " + memoryKiB + ", " +
                    "\"kdfParallelism\": " + parallelism + ", " +
                    "\"salt\": \"" + saltBase64 + "\"" +
                "}";
    }

}

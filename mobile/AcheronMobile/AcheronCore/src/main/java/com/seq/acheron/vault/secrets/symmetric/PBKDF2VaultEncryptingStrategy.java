package com.seq.acheron.vault.secrets.symmetric;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * AES-based vault encryption strategy using PBKDF2 to derive a key
 * from the user's master password.
 * <p>
 * This strategy:
 * <ul>
 * <li>Derives {@link #derivedKey} from a master password and salt
 * using PBKDF2WithHmacSHA256.</li>
 * <li>Uses an existing {@link #vaultKey} (provided to the constructor)
 * for AES-GCM encryption/decryption of vault data.</li>
 * <li>Relies on {@link VaultEncryptingStrategy} to wrap and unwrap
 * the vault key using the derived key.</li>
 * </ul>
 */
public final class PBKDF2VaultEncryptingStrategy extends VaultEncryptingStrategy {

    /**
     * PBKDF2 iteration count. This should be tuned according to security
     * requirements and performance characteristics of the target platform.
     */
    private static final int ITERATIONS = 600_000;

    /**
     * Desired length of the derived key in bits.
     */
    private static final int KEY_LENGTH_BITS = 256;

    /**
     * Creates a new PBKDF2-based strategy instance.
     * <p>
     * Derives {@link #derivedKey} from the master password and salt using
     * {@code PBKDF2WithHmacSHA256} with {@value #ITERATIONS} iterations and a
     * {@value #KEY_LENGTH_BITS}-bit output key.
     * If {@code generateVaultKey} is {@code true}, a new random 256-bit AES
     * {@link #vaultKey} is generated automatically; otherwise {@link #vaultKey}
     * remains {@code null} until {@link VaultEncryptingStrategy#importVaultKey(String)}
     * is called.
     *
     * @param masterPassword  the user's master password; wiped from memory after use
     * @param saltBase64      Base64-encoded salt used for PBKDF2
     * @param generateVaultKey {@code true} to generate a fresh random vault key;
     *                        {@code false} to defer key assignment
     * @throws GeneralSecurityException if key derivation or key generation fails
     */
    public PBKDF2VaultEncryptingStrategy(String masterPassword, String saltBase64, boolean generateVaultKey)
            throws GeneralSecurityException {
        super(masterPassword, "AES/GCM/NoPadding", saltBase64, generateVaultKey);
    }

    /**
     * Creates a new PBKDF2-based strategy instance using an existing vault key.
     * <p>
     * This constructor is typically used when reopening an existing vault:
     * the vault key has already been unwrapped (for example by calling
     * {@link VaultEncryptingStrategy#importVaultKey(String)}) and is passed
     * in here to be reused.
     * <p>
     * The constructor derives {@link #derivedKey} from the master password
     * and salt using PBKDF2WithHmacSHA256.
     *
     * @param masterPassword the user's master password
     * @param saltBase64     Base64-encoded salt used for PBKDF2
     * @param vaultKey       an existing vault key to reuse for AES-GCM
     * @throws GeneralSecurityException if key derivation fails
     */
    public PBKDF2VaultEncryptingStrategy(
            String masterPassword,
            String saltBase64,
            SecretKey vaultKey
    ) throws GeneralSecurityException {
        super(masterPassword, "AES/GCM/NoPadding", saltBase64, vaultKey);
    }

    protected SecretKey deriveKey(
            String masterPassword,
            String saltBase64
    ) throws GeneralSecurityException {
        char[] passwordChars = masterPassword.toCharArray();
        try {
            byte[] saltBytes = Base64.getDecoder().decode(saltBase64);
            KeySpec spec = new PBEKeySpec(passwordChars, saltBytes, ITERATIONS, KEY_LENGTH_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey tmp = factory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), "AES");
        } finally {
            Arrays.fill(passwordChars, '\0');
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
     *   "transformation": "AES/GCM/NoPadding",
     *   "kdf": "PBKDF2",
     *   "kdfIterations": 600000,
     *   "kdfKeyLength": 256,
     *   "salt": "base64..."
     * }
     *
     * @return a JSON string with non-secret cryptographic parameters
     */
    public String toJson() {
        return "{"
                + "\"transformation\": \"" + transformation + "\","
                + "\"kdf\": \"PBKDF2\","
                + "\"kdfIterations\": " + ITERATIONS + ","
                + "\"kdfKeyLength\": " + KEY_LENGTH_BITS + ","
                + "\"salt\": \"" + saltBase64 + "\""
                + "}";
    }
}

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

    private static final int DEFAULT_ITERATIONS = 600_000;
    private static final int DEFAULT_KEY_LENGTH_BITS = 256;

    private final int iterations;
    private final int keyLengthBits;

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
        this(masterPassword, saltBase64, generateVaultKey, DEFAULT_ITERATIONS, DEFAULT_KEY_LENGTH_BITS);
    }

    public PBKDF2VaultEncryptingStrategy(
            String masterPassword,
            String saltBase64,
            boolean generateVaultKey,
            int iterations,
            int keyLengthBits
    ) throws GeneralSecurityException {
        super(masterPassword, "AES/GCM/NoPadding", saltBase64, generateVaultKey);
        this.iterations = iterations > 0 ? iterations : DEFAULT_ITERATIONS;
        this.keyLengthBits = keyLengthBits > 0 ? keyLengthBits : DEFAULT_KEY_LENGTH_BITS;
        this.derivedKey = deriveKey(masterPassword, saltBase64);
    }

    /**
     * Creates a new PBKDF2-based strategy instance using an existing vault key.
     */
    public PBKDF2VaultEncryptingStrategy(
            String masterPassword,
            String saltBase64,
            SecretKey vaultKey
    ) throws GeneralSecurityException {
        this(masterPassword, saltBase64, vaultKey, DEFAULT_ITERATIONS, DEFAULT_KEY_LENGTH_BITS);
    }

    public PBKDF2VaultEncryptingStrategy(
            String masterPassword,
            String saltBase64,
            SecretKey vaultKey,
            int iterations,
            int keyLengthBits
    ) throws GeneralSecurityException {
        super(masterPassword, "AES/GCM/NoPadding", saltBase64, vaultKey);
        this.iterations = iterations > 0 ? iterations : DEFAULT_ITERATIONS;
        this.keyLengthBits = keyLengthBits > 0 ? keyLengthBits : DEFAULT_KEY_LENGTH_BITS;
        this.derivedKey = deriveKey(masterPassword, saltBase64);
    }

    protected SecretKey deriveKey(
            String masterPassword,
            String saltBase64
    ) throws GeneralSecurityException {
        char[] passwordChars = masterPassword.toCharArray();
        try {
            byte[] saltBytes = Base64.getDecoder().decode(saltBase64);
            KeySpec spec = new PBEKeySpec(passwordChars, saltBytes, iterations, keyLengthBits);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey tmp = factory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), "AES");
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    public String toJson() {
        return "{"
                + "\"transformation\": \"" + transformation + "\","
                + "\"kdf\": \"PBKDF2\","
                + "\"kdfIterations\": " + iterations + ","
                + "\"kdfKeyLength\": " + keyLengthBits + ","
                + "\"salt\": \"" + saltBase64 + "\""
                + "}";
    }
}

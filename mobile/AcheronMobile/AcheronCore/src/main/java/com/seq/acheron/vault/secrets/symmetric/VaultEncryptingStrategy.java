package com.seq.acheron.vault.secrets.symmetric;

import com.seq.acheron.vault.User;
import lombok.Getter;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static com.seq.acheron.util.CryptoUtils.constantTimeEquals;

/**
 * Abstract base class for symmetric encryption strategies used by the vault.
 * <p>
 * This class models the common pattern used in password managers:
 * <ul>
 *     <li>A {@link #derivedKey} obtained from the user's master password
 *     via a KDF (e.g., Argon2, PBKDF2).</li>
 *     <li>A randomly generated {@link #vaultKey} which is used to encrypt
 *     and decrypt the actual vault data (typically with AES-GCM).</li>
 * </ul>
 * Concrete subclasses are responsible for initializing {@link #derivedKey}
 * in their constructors.
 */
@Getter
public abstract class VaultEncryptingStrategy {

    /**
     * Key derived from the user's master password via a KDF.
     * <p>
     * This key is typically used to encrypt and decrypt the
     * {@link #vaultKey}, not the vault contents directly.
     */
    protected SecretKey derivedKey;

    /**
     * Symmetric key used to encrypt and decrypt vault data.
     * <p>
     * This key may be generated randomly in the constructor or assigned
     * later by calling {@link #importVaultKey(String)}.
     */
    protected SecretKey vaultKey = null;

    /**
     * JCE transformation string, e.g. {@code "AES/GCM/NoPadding"}.
     */
    protected final String transformation;

    protected String saltBase64;

    /**
     * Creates a new encrypting strategy and optionally generates a random
     * {@link #vaultKey}.  Subclasses MUST set {@link #derivedKey} after
     * their own fields are initialised; this constructor intentionally
     * does NOT call {@link #deriveKey}.
     *
     * @param transformation  the cipher transformation, e.g. {@code "AES/GCM/NoPadding"}
     * @param generateVaultKey if {@code true}, a new random {@link #vaultKey}
     *                         will be generated; if {@code false}, the
     *                         {@code vaultKey} remains {@code null} until
     *                         {@link #importVaultKey(String)} is called
     * @throws GeneralSecurityException if key generation fails
     */
    protected VaultEncryptingStrategy(
            String masterPassword,
            String transformation,
            String saltBase64,
            boolean generateVaultKey
    ) throws GeneralSecurityException {
        this.saltBase64                     = saltBase64;
        this.transformation                 = transformation;
        if (generateVaultKey) this.vaultKey = generateKey();
    }

    /**
     * Creates a new encrypting strategy using an existing {@link #vaultKey}.
     * <p>
     * Subclasses MUST set {@link #derivedKey} after their own fields are
     * initialised.
     *
     * @param transformation the cipher transformation
     * @param vaultKey       an existing vault key to reuse
     */
    protected VaultEncryptingStrategy(
            String masterPassword,
            String transformation,
            String saltBase64,
            SecretKey vaultKey
    ) throws GeneralSecurityException {
        this.saltBase64     = saltBase64;
        this.transformation = transformation;
        this.vaultKey       = vaultKey;
    }



    /**
     * Exports the current {@link #vaultKey} in encrypted form using
     * the {@link #derivedKey}.
     * <p>
     * The raw vault key bytes are first encoded as Base64, and then
     * encrypted with AES-GCM using the {@code derivedKey}. The return
     * value is a Base64 string containing {@code IV || ciphertext}.
     *
     * @return Base64-encoded, encrypted representation of the vault key
     * @throws GeneralSecurityException if encryption fails or {@code derivedKey}
     *                                  is not initialized
     */
    public String exportVaultKey() throws GeneralSecurityException {
        byte[] rawVaultKey = vaultKey.getEncoded();
        String vaultKeyBase64 = java.util.Base64.getEncoder().encodeToString(rawVaultKey);
        return encryptWithKey(vaultKeyBase64, derivedKey);
    }

    /**
     * Imports (unwraps) a vault key previously exported by
     * {@link #exportVaultKey()} using the current {@link #derivedKey}.
     * <p>
     * This method both reconstructs the key and assigns it to
     * {@link #vaultKey}, and also returns it so callers can reuse
     * the instance or pass the key elsewhere.
     *
     * @param encryptedVaultKeyBase64 Base64-encoded encrypted vault key as
     *                                produced by {@link #exportVaultKey()}
     * @return a {@link SecretKey} instance representing the original vault key
     * @throws GeneralSecurityException if decryption fails or the input
     *                                  is malformed
     */
    public SecretKey importVaultKey(String encryptedVaultKeyBase64)
            throws GeneralSecurityException
    {

        String vaultKeyBase64 = decryptWithKey(encryptedVaultKeyBase64, derivedKey);
        byte[] rawVaultKey = java.util.Base64.getDecoder().decode(vaultKeyBase64);
        this.vaultKey = new SecretKeySpec(rawVaultKey, "AES");
        return vaultKey;
    }

    /**
     * Encrypts the given plain-text using the current {@link #vaultKey}.
     * <p>
     * This is the primary method used to encrypt vault data.
     *
     * @param plainText the plain-text to encrypt
     * @return Base64-encoded {@code IV || ciphertext}
     * @throws GeneralSecurityException if encryption fails
     */
    public String encrypt(String plainText) throws GeneralSecurityException {
        return encryptWithKey(plainText, vaultKey);
    }

    /**
     * Decrypts a Base64-encoded {@code IV || ciphertext} string using
     * the current {@link #vaultKey}.
     * <p>
     * This is the primary method used to decrypt vault data.
     *
     * @param ivAndCiphertextBase64 Base64-encoded {@code IV || ciphertext}
     * @return the decrypted plain-text string
     * @throws GeneralSecurityException if decryption fails
     */
    public String decrypt(String ivAndCiphertextBase64) throws GeneralSecurityException {
        return decryptWithKey(ivAndCiphertextBase64, vaultKey);
    }

    public String encryptWithDerivedKey(String plainText) throws GeneralSecurityException {
        return encryptWithKey(plainText, derivedKey);
    }

    public String decryptWithDerivedKey(String text) throws GeneralSecurityException {
        return decryptWithKey(text, derivedKey);
    }

    /**
     * Validates that the master password currently configured in the provided
     * {@link VaultEncryptingStrategy} matches the one used to produce the
     * given {@code checker} value.
     * <p>
     * The checker is decrypted, the SHA-256 of the current {@link User}'s
     * username is recomputed, and both values are compared using a
     * constant-time comparison to reduce timing side-channels.
     *
     * @param encryptedChecker  encrypted verifier stored alongside the vault
     * @param validator         based used to get the encrypted checker; system will
     *                          compare the decrypted checker with the hash of the validator
     * @return {@code true} if the master password is correct, {@code false} otherwise
     */
    public boolean isValidChecker(String encryptedChecker, String validator) throws GeneralSecurityException {
        String decryptedChecker = decryptWithDerivedKey(encryptedChecker);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(
                validator.getBytes(StandardCharsets.UTF_8)
        );
        StringBuilder hex = new StringBuilder();
        for (byte b : hashBytes) {
            hex.append(String.format("%02x", b));
        }
        String hashedValidator = hex.toString();

        return constantTimeEquals(hashedValidator, decryptedChecker);
    }

    public String getChecker(String validator) throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(validator.getBytes(StandardCharsets.UTF_8));

        StringBuilder hex = new StringBuilder();
        for (byte b : hashBytes) {
            hex.append(String.format("%02x", b));
        }
        return encryptWithDerivedKey(hex.toString());
    }

    /**
     * Re-derives the {@link #derivedKey} from a new master password and salt,
     * <b>preserving the current {@link #vaultKey}</b>.
     * <p>
     * Because the vault data is encrypted with the {@code vaultKey} (not the
     * derived key), rotating the master password only requires re-deriving the
     * key-encryption key and re-wrapping the unchanged {@code vaultKey}; the
     * stored ciphertext of every item stays byte-identical. After calling this,
     * {@link #exportVaultKey()} and {@link #getChecker(String)} will produce
     * material bound to the new password, and {@link #toJson()} will report the
     * new salt.
     *
     * @param newMasterPassword the new master password
     * @param newSaltBase64     a freshly generated Base64-encoded salt
     * @throws GeneralSecurityException if key derivation fails
     */
    public void changePassword(String newMasterPassword, String newSaltBase64)
            throws GeneralSecurityException {
        SecretKey newDerivedKey = deriveKey(newMasterPassword, newSaltBase64);
        this.saltBase64 = newSaltBase64;
        this.derivedKey = newDerivedKey;
    }

    /**
     * Checks, in constant time, whether {@code candidatePassword} derives the
     * same key as the one currently held in {@link #derivedKey} (using the
     * current {@link #saltBase64}).
     * <p>
     * This is used to verify the current master password before allowing a
     * password change on an already-unlocked vault, where {@link #derivedKey}
     * is by definition the key of the correct password.
     *
     * @param candidatePassword the master password to verify
     * @return {@code true} if the candidate derives the current key
     * @throws GeneralSecurityException if key derivation fails
     */
    public boolean matchesPassword(String candidatePassword) throws GeneralSecurityException {
        if (derivedKey == null) {
            return false;
        }
        SecretKey candidate = deriveKey(candidatePassword, saltBase64);
        return MessageDigest.isEqual(candidate.getEncoded(), derivedKey.getEncoded());
    }

    /**
     * Generates a new random 256-bit AES key that can be used as a
     * {@link #vaultKey}.
     *
     * @return a new {@link SecretKey} instance
     * @throws GeneralSecurityException if secure random generation fails
     */
    private static SecretKey generateKey() throws GeneralSecurityException {
        byte[] keyBytes = new byte[32]; // 256 bits
        SecureRandom.getInstanceStrong().nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Encrypts a plain-text string using the given key with AES-GCM and
     * returns the result as Base64 {@code IV || ciphertext}.
     *
     * @param plainText the plain-text to encrypt
     * @param key       the key to use (can be {@link #vaultKey} or {@link #derivedKey})
     * @return Base64-encoded {@code IV || ciphertext}
     * @throws GeneralSecurityException if encryption fails
     */
    private String encryptWithKey(String plainText, SecretKey key) throws GeneralSecurityException {
        byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance(transformation);

        byte[] iv = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(iv);

        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] cipherBytes = cipher.doFinal(plainTextBytes);

        ByteBuffer buffer = ByteBuffer.allocate(iv.length + cipherBytes.length);
        buffer.put(iv);
        buffer.put(cipherBytes);

        return java.util.Base64.getEncoder().encodeToString(buffer.array());
    }

    /**
     * Decrypts a Base64-encoded {@code IV || ciphertext} string using
     * the specified key.
     *
     * @param ivAndCiphertextBase64 Base64-encoded {@code IV || ciphertext}
     * @param key                   the key to use (can be {@link #vaultKey} or {@link #derivedKey})
     * @return the decrypted plain-text string
     * @throws GeneralSecurityException if decryption fails or the input
     *                                  is malformed
     */
    private String decryptWithKey(String ivAndCiphertextBase64, SecretKey key)
            throws GeneralSecurityException {

        byte[] ivAndCiphertext = java.util.Base64.getDecoder().decode(ivAndCiphertextBase64);
        ByteBuffer buffer = ByteBuffer.wrap(ivAndCiphertext);

        byte[] iv = new byte[12];
        buffer.get(iv);

        byte[] cipherBytes = new byte[buffer.remaining()];
        buffer.get(cipherBytes);

        Cipher cipher = Cipher.getInstance(transformation);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        byte[] plainBytes = cipher.doFinal(cipherBytes);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    public abstract String toJson();

    protected abstract SecretKey deriveKey(
            String masterPassword,
            String saltBase64
    ) throws GeneralSecurityException;
}

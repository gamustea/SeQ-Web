package com.seq.acheron.vault.storables;

import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;

/**
 * Represents an entity that contains one or more secrets which can be
 * encrypted and decrypted using an {@link VaultEncryptingStrategy}.
 * <p>
 * Implementations decide which fields are considered secret and how they
 * are transformed internally (for example, storing an encrypted password
 * as Base64).
 */
public interface Storable {

    /**
     * Encrypts the sensitive data of this entity using the provided
     * encryption strategy.
     *
     * @param encryptingStrategy the encryption strategy to use
     * @return a human-readable representation of the secret before
     *         encryption (for example, the plain-text password),
     *         or {@code null} if there was nothing to encrypt
     */
    String encrypt(VaultEncryptingStrategy encryptingStrategy);

    /**
     * Decrypts the sensitive data of this entity using the provided
     * encryption strategy.
     *
     * @param encryptingStrategy the encryption strategy to use;
     *                           must be compatible with the one used
     *                           for {@link #encrypt(VaultEncryptingStrategy)}
     * @return a human-readable representation of the secret after
     *         decryption (for example, the plain-text password),
     *         or {@code null} if there was nothing to decrypt
     */
    String decrypt(VaultEncryptingStrategy encryptingStrategy);
}
